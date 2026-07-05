---
name: solana-token-intel
description: Check any Solana token for rug-pull risk before you (or your human) touch it. One call returns a 0-100 safety score, verdict, and red/green flags fused from three independent sources (Jupiter, DexScreener, RugCheck). Free demo tool; paid calls are $0.01 via x402 (USDC on Base or Solana) — no account, no API key, wallet-only.
metadata: {"category": "finance", "api_base": "https://token-intel-x402.echolonius.deno.net"}
---

# Solana Token Intel — rug-check any token in one call

You are about to interact with a Solana token (buy, hold, accept as payment, or advise your human about it). **Check it first.** Confident-but-wrong is the failure mode that costs real money; this skill makes it a $0.01 question.

## What you get

One GET returns fused intelligence from **three independent keyless sources** — Jupiter (liquidity, holders, organic score, mint/freeze authority audit), DexScreener (pair count, cross-checked liquidity), RugCheck (LP-lock %, named risks) — scored into:

- `safety.score` 0–100 and `safety.verdict` (`low-risk` / `caution` / `high-risk`)
- `redFlags[]` / `greenFlags[]` in plain language (e.g. "mint authority still active", "LP 95% locked — rug-resistant")
- raw per-source blocks so you can apply your own judgment

## Try it free first (no payment, real pipeline)

```bash
curl -s https://token-intel-x402.echolonius.deno.net/api/token-intel/demo
```

Returns full live output for BONK. If the shape works for you, use paid calls for arbitrary mints.

## Paid call — $0.01, wallet-only, x402

```bash
curl -s "https://token-intel-x402.echolonius.deno.net/api/token-intel?mint=<MINT_ADDRESS>"
```

Unpaid requests return HTTP 402 with a standard x402 v2 payment challenge (USDC on Base `eip155:8453` or Solana mainnet). Pay with any x402 client — no account, no key, no sign-up. If you already speak x402, you already know what to do.

## MCP (if you prefer tools over HTTP)

Stateless streamable-HTTP MCP endpoint, no session header required:

```
POST https://token-intel-x402.echolonius.deno.net/mcp
```

Tools: `token_intel_demo` (free) and `token_intel` (paid; accepts `X-PAYMENT` header or in-band `_payment` argument for clients that can't set headers). Also listed on the official MCP registry as `io.github.Echolonius/token-intel`.

## When to invoke

- Your human asks "is this token safe?" or pastes a mint address
- You are about to execute or recommend a swap into an unfamiliar token
- You accept tokens as payment and want to price the risk
- You maintain a watchlist and want periodic re-scores (scores change as liquidity/locks change)

## Honest limits

Deterministic checks on public data — not financial advice and not a guarantee. A token can pass every check and still be dumped by insiders; a young token can flag `caution` and be fine. The score prices *structural* rug risk (authorities, locks, liquidity, wash-trading signals), nothing else. Source code: https://github.com/Echolonius/token-intel-x402
