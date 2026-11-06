# token-intel-x402 (retired)

**This service is retired and offline.** The hosted API and its MCP endpoint stopped working in
October 2026 and no longer take requests or payments. This repository stays up only as reference
code.
The manual [registry-status workflow](.github/workflows/registry-status.yml) hides its MCP Registry entry (`deleted`) or restores it (`active`).

The service earned no paid calls during its run, and free traffic kept exceeding the host's
free-tier limits. You're welcome to read the code or run your own copy.

## What it did

One **keyless** call returned a fused safety + market read on any Solana token — mint/freeze
authority, top-holder %, dev holdings, wash-trade (organic) score, liquidity, verification — plus
a **synthesized risk verdict** (`low-risk` / `caution` / `high-risk`) with plain-language flags.

Calls were paid per use with **x402**: an autonomous agent paid a $0.01 USDC micro-fee per call
(Base or Solana), with no API key, account or signup.

Main routes in `main.ts` (they only work if you run it yourself):

```
GET  /api/token-intel?mint=<SPL_MINT>   # paid (x402) → JSON intelligence
GET  /api/token-intel/demo              # free: fixed sample (BONK)
POST /mcp                               # MCP: token_intel (paid), token_intel_demo (free)
GET  /                                  # free: what it is + how to pay
GET  /healthz                           # free
```

### Security by design
- **No private keys, no API keys on the server** — data (Jupiter) and payments (PayAI
  facilitator) are both keyless, so there is nothing here to steal.
- **Read-only, no database, no PII** — near-zero attack surface.
- Pay-to wallet is **receive-only**; its key never touches this host.
- Every paid call requires payment first, so abuse costs the attacker money.
- Input strictly validated (base58 mint) — no SSRF/injection.

## Running your own copy

There are no default pay-to wallets: the server refuses to start until `X402_PAY_TO` (Base) and
`X402_SOL_PAY_TO` (Solana) are set to your own receive-only addresses. Then run `deno task dev`.

_Informational only, not financial advice, no warranty._

## License

MIT. See [LICENSE](LICENSE).
