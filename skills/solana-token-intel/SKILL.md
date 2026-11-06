---
name: solana-token-intel
description: RETIRED, do not use. This skill called the token-intel-x402 API, which has been offline since October 2026 and no longer takes requests or payments. Kept only as a record; the source code is at https://github.com/Echolonius/token-intel-x402
metadata: {"category": "finance"}
---

# Solana Token Intel (retired)

**This skill is retired. Do not call its old endpoint or try to pay it.** The hosted API at `token-intel-x402.echolonius.deno.net` (including its `/mcp` endpoint) has been offline since October 2026. For a Solana token risk check, use a service that is still running.

## What it did

One GET request returned a fused safety and market read on a Solana token from three public sources (Jupiter, DexScreener, RugCheck): a 0–100 safety score, a verdict (`low-risk` / `caution` / `high-risk`) and plain-language red and green flags. Paid calls cost $0.01 via x402.

The source code stays at https://github.com/Echolonius/token-intel-x402 for reference.

Not financial advice, no warranty.
