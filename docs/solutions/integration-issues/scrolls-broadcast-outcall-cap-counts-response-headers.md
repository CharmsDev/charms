---
title: Scrolls broadcast outcall cap counts response headers
date: 2026-11-04
category: integration-issues
module: scrolls litecoin and bitcoin broadcast outcalls
problem_type: integration_issue
component: scrolls_canister
symptoms:
  - "`sign_and_submit` returned `litecoinspace HTTP outcall failed: Http body exceeds size limit of 1024 bytes`"
  - The transaction was broadcast and mined anyway (Litecoin testnet unwrap 92bdf0aa…3b47, block 5016534)
root_cause: config_error
resolution_type: code_fix
severity: high
tags:
  - scrolls
  - icp
  - https-outcalls
  - max-response-bytes
  - broadcast
  - litecoin
  - bitcoin
---

# Scrolls broadcast outcall cap counts response headers

## Problem

`scrolls_litecoin` broadcasts a signed transaction with a POST to litecoinspace. On the first real unwrap, the POST reached litecoinspace and the transaction was mined, but the outcall itself failed and `sign_and_submit` returned an error. A caller that trusts the error would think the withdrawal failed and might retry or give up on a transaction that is already on chain.

## Root cause

`MAX_BROADCAST_RESPONSE_BYTES` was 1024, sized for the 64-character txid body. The IC counts the response **header names and values plus the body** against `max_response_bytes`, and it checks the raw response before the transform runs, so stripping headers in `transform_http` does not help. litecoinspace sits behind Cloudflare: a `POST /testnet/api/tx` returns about 680 B of headers (`nel`, a long `report-to` URL, `cf-ray`, `x-powered-by`, `x-litecoin-version`, ...) before the body. The `report-to` value varies per response, so the total sometimes fits and sometimes does not. mempool.space currently sends about 240 B of headers, which is why `scrolls_bitcoin` had not failed yet with the same 1024 cap.

The error text says "body" but the budget it reports is headers plus body.

## Solution

Both canisters now use `MAX_BROADCAST_RESPONSE_BYTES = 16 * 1024` (`scrolls/src/scrolls_litecoin/src/lib.rs`, `scrolls/src/scrolls_bitcoin/src/lib.rs`). Under the per-byte outcall price (about 800 cycles per byte per subnet node), the extra 15 KiB costs roughly 0.2B cycles on a 13-node subnet and under 0.5B on a 34-node subnet. That is small next to the base outcall fee and the threshold signature in the same call. The success path is unchanged: HTTP 200 with the expected txid, or the litecoind/bitcoind `-27` "already in chain" error normalized to 200 by the transform.

## Prevention

Size every outcall cap for headers + body as the remote server actually sends them, with margin. Measure with `curl -s -D - -o body -X POST ...` against the real endpoint and count the header bytes too. For a side-effecting POST, an outcall error does not mean the side effect did not happen. Callers should check the chain before they retry.
