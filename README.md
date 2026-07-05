# token-intel-x402 — agent-native Solana token intelligence

One **keyless** call returns a fused safety + market read on any Solana token — mint/freeze
authority, top-holder %, dev holdings, wash-trade (organic) score, liquidity, verification — plus
a **synthesized risk verdict** (`low-risk` / `caution` / `high-risk`) with plain-language flags.

Gated by **x402**: an autonomous agent pays a $0.01 USDC micro-fee per call (Base or Solana) — **no API key, no
account, no signup**. That is the differentiator: every rival (RugCheck, Birdeye, SolSniffer,
GoPlus) needs a key and a signup; this is built for machine-to-machine payment.

```
GET /api/token-intel?mint=<SPL_MINT>   # PAID (x402) → JSON intelligence
GET /                                  # free: what it is + how to pay
GET /healthz                           # free
```

### Security by design
- **No private keys, no API keys on the server** — data (Jupiter) and payments (PayAI
  facilitator) are both keyless, so there is nothing here to steal.
- **Read-only, no database, no PII** — near-zero attack surface.
- Pay-to wallet is **receive-only**; its key never touches this host.
- Every paid call requires payment first, so abuse costs the attacker money.
- Input strictly validated (base58 mint) — no SSRF/injection.

_Informational only, not financial advice, no warranty._
