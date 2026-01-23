#!/bin/bash
set -e

# Configuration
CARDANO_CLI="cardano-cli"
NETWORK="--mainnet"
POLICY_DIR="tmp/version-nft-policy"

# Token details
POLICY_ID=$(cat "$POLICY_DIR/policyID" | tr -d '\n')
ASSET_NAME_HEX="000de140763130"  # 000de140 (CIP-67 NFT label) + 763130 ("v10" as hex bytes)
TOKEN_AMOUNT="1"
DESTINATION_ADDR="addr1q9rxvzdtgqpa9freesxr60pycnjhd42svuxyzunxqe3g3vafswgqe992qm02xq7jcuxvj4wq2nvclckrglfwxxxjhn2sx9g840"

# Working directory for transaction files
WORK_DIR="tmp/cardano-mint-work"
mkdir -p "$WORK_DIR"

echo "========================================="
echo "Cardano Token Minting Script"
echo "========================================="
echo "Policy ID: $POLICY_ID"
echo "Asset Name (hex): $ASSET_NAME_HEX"
echo "Asset Name (decoded): v10"
echo "Amount: $TOKEN_AMOUNT"
echo "Destination: $DESTINATION_ADDR"
echo "========================================="
echo ""

# Step 1: Extract payment address from Eternl wallet
# For this script, we need the user to provide their payment address manually
# as extracting keys from Eternl export requires deriving from the mnemonic
echo "Step 1: Wallet Setup"
echo "Please provide your Cardano payment address from the Eternl wallet:"
read -p "Payment Address: " PAYMENT_ADDR

if [ -z "$PAYMENT_ADDR" ]; then
    echo "Error: Payment address is required"
    exit 1
fi

echo "Payment Address: $PAYMENT_ADDR"
echo ""

## Step 2: Query UTXOs
#echo "Step 2: Querying UTXOs for address: $PAYMENT_ADDR"
#"$CARDANO_CLI" query utxo \
#    --address "$PAYMENT_ADDR" \
#    $NETWORK \
#    --out-file "$WORK_DIR/utxos.json"
#
#echo "UTXOs saved to $WORK_DIR/utxos.json"
#cat "$WORK_DIR/utxos.json"
#echo ""

# Parse UTXOs to find a suitable input
# This is a simplified version - in production you'd want better UTXO selection
UTXO_TXHASH=$(jq -r 'keys[2] | split("#")[0]' "$WORK_DIR/utxos.json")
UTXO_TXIX=$(jq -r 'keys[2] | split("#")[1]' "$WORK_DIR/utxos.json")
UTXO_BALANCE=$(jq -r 'to_entries[2].value.value.lovelace' "$WORK_DIR/utxos.json")

if [ -z "$UTXO_TXHASH" ] || [ "$UTXO_TXHASH" = "null" ]; then
    echo "Error: No UTXOs found at address $PAYMENT_ADDR"
    exit 1
fi

echo "Selected UTXO:"
echo "  TxHash: $UTXO_TXHASH"
echo "  TxIx: $UTXO_TXIX"
echo "  Balance: $UTXO_BALANCE lovelace"

# Extract any existing tokens in the UTXO to preserve them in change output
EXISTING_TOKENS=$(jq -r --arg key "$(echo ${UTXO_TXHASH}#${UTXO_TXIX})" '.[$key].value | to_entries | map(select(.key != "lovelace") | .key as $policy | .value | to_entries[] | "\(.value) \($policy).\(.key)") | join("+")' "$WORK_DIR/utxos.json")

if [ -n "$EXISTING_TOKENS" ]; then
    echo "  Existing tokens: $EXISTING_TOKENS"
fi
echo ""

# Step 3: Build the transaction
echo "Step 3: Building transaction..."

# Query protocol parameters
"$CARDANO_CLI" query protocol-parameters \
    $NETWORK \
    --out-file "$WORK_DIR/protocol.json"

# Calculate minimum ADA to send with the token (approximately 2 ADA)
TOKEN_OUTPUT_ADA="2000000"

# Build the raw transaction with existing tokens in change output
CHANGE_OUTPUT="${PAYMENT_ADDR}+0"
if [ -n "$EXISTING_TOKENS" ]; then
    CHANGE_OUTPUT="${CHANGE_OUTPUT}+${EXISTING_TOKENS}"
fi

"$CARDANO_CLI" conway transaction build-raw \
    --tx-in "${UTXO_TXHASH}#${UTXO_TXIX}" \
    --tx-out "${DESTINATION_ADDR}+${TOKEN_OUTPUT_ADA}+${TOKEN_AMOUNT} ${POLICY_ID}.${ASSET_NAME_HEX}" \
    --tx-out "$CHANGE_OUTPUT" \
    --mint "${TOKEN_AMOUNT} ${POLICY_ID}.${ASSET_NAME_HEX}" \
    --minting-script-file "$POLICY_DIR/policy.script" \
    --fee 0 \
    --out-file "$WORK_DIR/tx.draft"

echo "Draft transaction created"
echo ""

# Step 4: Calculate fees
echo "Step 4: Calculating transaction fee..."
FEE_CALCULATED=$("$CARDANO_CLI" conway transaction calculate-min-fee \
    --tx-body-file "$WORK_DIR/tx.draft" \
    --tx-in-count 1 \
    --tx-out-count 2 \
    --witness-count 2 \
    $NETWORK \
    --protocol-params-file "$WORK_DIR/protocol.json" | cut -d' ' -f1)

# Add a buffer to ensure fee is sufficient (10% extra)
FEE=$((FEE_CALCULATED + FEE_CALCULATED / 10))

echo "Calculated minimum fee: $FEE_CALCULATED lovelace"
echo "Fee with 10% buffer: $FEE lovelace"

# Calculate change
CHANGE=$((UTXO_BALANCE - TOKEN_OUTPUT_ADA - FEE))

if [ $CHANGE -lt 1000000 ]; then
    echo "Error: Insufficient funds. Need at least $((TOKEN_OUTPUT_ADA + FEE + 1000000)) lovelace"
    echo "Available: $UTXO_BALANCE lovelace"
    exit 1
fi

echo "Change to return: $CHANGE lovelace"
echo ""

# Rebuild transaction with correct fee and change
echo "Step 5: Building final transaction..."

# Rebuild change output with correct ADA amount
CHANGE_OUTPUT="${PAYMENT_ADDR}+${CHANGE}"
if [ -n "$EXISTING_TOKENS" ]; then
    CHANGE_OUTPUT="${CHANGE_OUTPUT}+${EXISTING_TOKENS}"
fi

"$CARDANO_CLI" conway transaction build-raw \
    --tx-in "${UTXO_TXHASH}#${UTXO_TXIX}" \
    --tx-out "${DESTINATION_ADDR}+${TOKEN_OUTPUT_ADA}+${TOKEN_AMOUNT} ${POLICY_ID}.${ASSET_NAME_HEX}" \
    --tx-out "$CHANGE_OUTPUT" \
    --mint "${TOKEN_AMOUNT} ${POLICY_ID}.${ASSET_NAME_HEX}" \
    --minting-script-file "$POLICY_DIR/policy.script" \
    --fee $FEE \
    --out-file "$WORK_DIR/tx.raw"

echo "Final transaction built"
echo ""

# Step 6: Sign the transaction
echo "Step 6: Signing transaction..."
echo "This transaction requires two signatures:"
echo "  1. Policy signing key (from $POLICY_DIR/policy.skey)"
echo "  2. Payment signing key (you need to provide this)"
echo ""
echo "Please provide the path to your payment signing key:"
read -p "Payment signing key path: " PAYMENT_SKEY

"$CARDANO_CLI" conway transaction sign \
    --tx-body-file "$WORK_DIR/tx.raw" \
    --signing-key-file "$POLICY_DIR/policy.skey" \
    --signing-key-file "$PAYMENT_SKEY" \
    $NETWORK \
    --out-file "$WORK_DIR/tx.signed"

echo "Transaction signed"
echo ""

# Step 7: Submit the transaction
echo "Step 7: Ready to submit transaction to mainnet"
echo "========================================="
echo "Transaction Summary:"
echo "  Minting: $TOKEN_AMOUNT token(s) of ${POLICY_ID}.${ASSET_NAME_HEX}"
echo "  Destination: $DESTINATION_ADDR"
echo "  Token Output: $TOKEN_OUTPUT_ADA lovelace"
echo "  Fee: $FEE lovelace"
echo "  Change: $CHANGE lovelace"
echo "========================================="
echo ""
read -p "Submit transaction to MAINNET? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Transaction cancelled. Signed transaction saved at: $WORK_DIR/tx.signed"
    echo "You can submit it later with:"
    echo "  $CARDANO_CLI transaction submit --tx-file $WORK_DIR/tx.signed $NETWORK"
    exit 0
fi

"$CARDANO_CLI" conway transaction submit \
    --tx-file "$WORK_DIR/tx.signed" \
    $NETWORK

echo ""
echo "========================================="
echo "SUCCESS! Transaction submitted to mainnet"
echo "========================================="
echo ""
echo "Token: ${POLICY_ID}.${ASSET_NAME_HEX}"
echo "Transaction files saved in: $WORK_DIR/"
echo ""
echo "You can track the transaction on:"
echo "  https://cardanoscan.io/transaction/$(cat $WORK_DIR/tx.signed | jq -r '.cborHex' | xxd -r -p | "$CARDANO_CLI" conway transaction txid --tx-file /dev/stdin)"
