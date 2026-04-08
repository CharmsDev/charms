#!/bin/bash
set -e

# Usage: ./scripts/mint-cardano-token.sh <asset-name> <funding-utxo> <ref-script-utxo>
# Example: ./scripts/mint-cardano-token.sh v13 "5a8c...#1" "e6ef...#0"

# Configuration
POLICY_DIR="tmp/version-nft-policy"
WALLET_DIR="tmp/charms-inc-wallet"
WORK_DIR="tmp/cardano-mint-work"

# Arguments
ASSET_NAME_STRING="${1:?Usage: $0 <asset-name> <funding-utxo> <ref-script-utxo>}"
PAYMENT_UTXO="${2:?Usage: $0 <asset-name> <funding-utxo> <ref-script-utxo>}"
REF_SCRIPT_UTXO="${3:?Usage: $0 <asset-name> <funding-utxo> <ref-script-utxo>}"

# Token details
POLICY_ID=$(cat "$POLICY_DIR/policyID" | tr -d '\n')

# CIP-67 NFT label prefix (000de140)
NFT_LABEL_HEX="000de140"

# Convert asset name string to hex
ASSET_NAME_STRING_HEX=$(echo -n "$ASSET_NAME_STRING" | xxd -p -c 256)

# Combine NFT label + string hex to form complete asset name
ASSET_NAME_HEX="${NFT_LABEL_HEX}${ASSET_NAME_STRING_HEX}"

DESTINATION_ADDR=$(cat "$WALLET_DIR/payment.addr" | tr -d '\n')
TOKEN_OUTPUT_ADA="5000000"

mkdir -p "$WORK_DIR"

echo "========================================="
echo "Cardano Token Minting Script"
echo "========================================="
echo "Policy ID: $POLICY_ID"
echo "NFT Label (hex): $NFT_LABEL_HEX (CIP-67 label 222)"
echo "Asset Name String: $ASSET_NAME_STRING"
echo "Asset Name String (hex): $ASSET_NAME_STRING_HEX"
echo "Full Asset Name (hex): $ASSET_NAME_HEX"
echo "Destination: $DESTINATION_ADDR"
echo "Funding UTXO: $PAYMENT_UTXO"
echo "Reference Script UTXO: $REF_SCRIPT_UTXO"
echo "========================================="
echo ""

# Step 1: Query funding UTXO
echo "Step 1: Querying funding UTXO..."
cardano-cli query utxo \
    --tx-in "$PAYMENT_UTXO" \
    --out-file "$WORK_DIR/utxos.json"

UTXO_BALANCE=$(jq -r 'to_entries[0].value.value.lovelace' "$WORK_DIR/utxos.json")

if [ -z "$UTXO_BALANCE" ] || [ "$UTXO_BALANCE" = "null" ]; then
    echo "Error: No UTXO found for $PAYMENT_UTXO"
    exit 1
fi

# Check for existing tokens in the UTXO
EXISTING_TOKENS=$(jq -r 'to_entries[0].value.value | to_entries | map(select(.key != "lovelace")) | length' "$WORK_DIR/utxos.json")
if [ "$EXISTING_TOKENS" -gt 0 ]; then
    echo "Error: Funding UTXO contains tokens, use a pure ADA UTXO"
    exit 1
fi

echo "  Balance: $UTXO_BALANCE lovelace"
echo ""

# Step 2: Extract reference script from source UTXO
echo "Step 2: Extracting reference script from $REF_SCRIPT_UTXO..."
cardano-cli query utxo \
    --tx-in "$REF_SCRIPT_UTXO" \
    --out-file "$WORK_DIR/ref-script-utxo.json"

jq -r ".[\"$REF_SCRIPT_UTXO\"].referenceScript.script" "$WORK_DIR/ref-script-utxo.json" > "$WORK_DIR/reference-script.json"

if [ "$(cat "$WORK_DIR/reference-script.json")" = "null" ]; then
    echo "Error: No reference script found in $REF_SCRIPT_UTXO"
    exit 1
fi

echo "  Reference script extracted"
echo ""

# Step 3: Query protocol parameters
echo "Step 3: Querying protocol parameters..."
cardano-cli query protocol-parameters \
    --out-file "$WORK_DIR/protocol.json"

# Step 4: Build draft transaction (fee = 0) to calculate fees
echo "Step 4: Building draft transaction..."
cardano-cli conway transaction build-raw \
    --tx-in "$PAYMENT_UTXO" \
    --tx-out "${DESTINATION_ADDR}+${TOKEN_OUTPUT_ADA}+1 ${POLICY_ID}.${ASSET_NAME_HEX}" \
    --tx-out-reference-script-file "$WORK_DIR/reference-script.json" \
    --tx-out "${DESTINATION_ADDR}+0" \
    --mint "1 ${POLICY_ID}.${ASSET_NAME_HEX}" \
    --minting-script-file "$POLICY_DIR/policy.script" \
    --fee 0 \
    --out-file "$WORK_DIR/tx.draft"

# Step 5: Calculate fees
echo "Step 5: Calculating transaction fee..."
FEE_CALCULATED=$(cardano-cli conway transaction calculate-min-fee \
    --tx-body-file "$WORK_DIR/tx.draft" \
    --tx-in-count 1 \
    --tx-out-count 2 \
    --witness-count 2 \
    --protocol-params-file "$WORK_DIR/protocol.json" | cut -d' ' -f1)

# Add 10% buffer
FEE=$((FEE_CALCULATED + FEE_CALCULATED / 10))

CHANGE=$((UTXO_BALANCE - TOKEN_OUTPUT_ADA - FEE))

if [ $CHANGE -lt 1000000 ]; then
    echo "Error: Insufficient funds. Need at least $((TOKEN_OUTPUT_ADA + FEE + 1000000)) lovelace, have $UTXO_BALANCE"
    exit 1
fi

echo "  Calculated fee: $FEE_CALCULATED lovelace (with 10% buffer: $FEE)"
echo "  Change: $CHANGE lovelace"
echo ""

# Step 6: Build final transaction
echo "Step 6: Building final transaction..."
cardano-cli conway transaction build-raw \
    --tx-in "$PAYMENT_UTXO" \
    --tx-out "${DESTINATION_ADDR}+${TOKEN_OUTPUT_ADA}+1 ${POLICY_ID}.${ASSET_NAME_HEX}" \
    --tx-out-reference-script-file "$WORK_DIR/reference-script.json" \
    --tx-out "${DESTINATION_ADDR}+${CHANGE}" \
    --mint "1 ${POLICY_ID}.${ASSET_NAME_HEX}" \
    --minting-script-file "$POLICY_DIR/policy.script" \
    --fee $FEE \
    --out-file "$WORK_DIR/tx.raw"

# Step 7: Sign transaction
echo "Step 7: Signing transaction..."
cardano-cli conway transaction sign \
    --tx-body-file "$WORK_DIR/tx.raw" \
    --signing-key-file "$POLICY_DIR/policy.skey" \
    --signing-key-file "$WALLET_DIR/payment.skey" \
    --out-file "$WORK_DIR/tx.signed"

echo ""
echo "========================================="
echo "Transaction Summary:"
echo "  Minting: 1 ${POLICY_ID}.${ASSET_NAME_HEX}"
echo "  Destination: $DESTINATION_ADDR"
echo "  Token Output: $TOKEN_OUTPUT_ADA lovelace + NFT + reference script"
echo "  Fee: $FEE lovelace"
echo "  Change: $CHANGE lovelace"
echo "========================================="
echo ""
read -p "Submit transaction to MAINNET? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Transaction cancelled. Signed transaction saved at: $WORK_DIR/tx.signed"
    echo "You can submit it later with:"
    echo "  cardano-cli conway transaction submit --tx-file $WORK_DIR/tx.signed"
    exit 0
fi

# Step 8: Submit
cardano-cli conway transaction submit \
    --tx-file "$WORK_DIR/tx.signed"

echo ""
echo "========================================="
echo "SUCCESS! Transaction submitted to mainnet"
echo "========================================="
echo "Token: ${POLICY_ID}.${ASSET_NAME_HEX}"
echo "Transaction files saved in: $WORK_DIR/"
