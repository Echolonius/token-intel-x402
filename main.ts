/**
 * Solana Token Intelligence — agent-native x402 API. Runs on Deno Deploy (always-on edge,
 * alive when no home machine is on). One keyless call returns a fused safety/quality read on
 * any Solana token, gated behind an x402 micropayment in USDC on Base.
 *
 * SECURITY POSTURE (by design, not afterthought):
 *   - holds NO private keys and NO API keys — Jupiter (data) and the PayAI facilitator (payment
 *     verify/settle) are both keyless, so there is nothing on this host to steal.
 *   - read-only: only reads public chain/market data and returns JSON. No database, no user
 *     accounts, no PII, no writes — a near-zero attack surface.
 *   - the payTo wallet is RECEIVE-ONLY; its key never leaves the operator's offline machine.
 *   - every paid call requires payment first, so spam/DDoS costs the attacker money.
 *   - input is strictly validated (base58 mint only) so it can never be used for SSRF/injection.
 */

const PAY_TO = Deno.env.get("X402_PAY_TO") ?? "0xd194AB36E66BccDD80f19b56757CFe52EdEd49af";
const NETWORK = Deno.env.get("X402_NETWORK") ?? "eip155:8453"; // Base mainnet
const ASSET = Deno.env.get("X402_ASSET") ?? "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"; // USDC
const AMOUNT = Deno.env.get("X402_AMOUNT") ?? "20000"; // 0.02 USDC
const FACILITATOR = Deno.env.get("X402_FACILITATOR") ?? "https://facilitator.payai.network";
const INDEX_HASH = Deno.env.get("X402INDEX_HASH") ?? "dbe4d192e3b36a2a8494005f9f9396ccad725d267f61c7a4a4d00c97d6ed6442";
const PRICE_USD = 0.02;

const DISCLAIMER =
  "Informational only, not financial advice, no warranty. Scores are heuristic; verify before transacting.";

// ---------- product: fused token intelligence (keyless Jupiter v2) ----------

const isMint = (s: string) => /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s);

// Optional second source (keyless). MUST never break the route: any failure → null → Jupiter-only.
// deno-lint-ignore no-explicit-any
async function dexScreener(mint: string): Promise<any | null> {
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 5000);
    const r = await fetch(`https://api.dexscreener.com/latest/dex/tokens/${mint}`, { signal: ctl.signal, headers: { Accept: "application/json" } });
    clearTimeout(t);
    if (!r.ok) return null;
    const d = await r.json();
    const pairs = Array.isArray(d?.pairs) ? d.pairs.filter((p: any) => p?.chainId === "solana") : [];
    if (!pairs.length) return null;
    const liq = pairs.reduce((s: number, p: any) => s + (Number(p?.liquidity?.usd) || 0), 0);
    const vol = pairs.reduce((s: number, p: any) => s + (Number(p?.volume?.h24) || 0), 0);
    return { pairCount: pairs.length, liquidityUsd: Math.round(liq), volume24hUsd: Math.round(vol) };
  } catch { return null; }
}

// deno-lint-ignore no-explicit-any
async function tokenIntel(mint: string): Promise<any> {
  if (!isMint(mint)) throw new Error("invalid mint address");
  const dexP = dexScreener(mint); // fire in parallel; optional
  const r = await fetch(`https://lite-api.jup.ag/tokens/v2/search?query=${mint}`, {
    headers: { Accept: "application/json" },
  });
  if (!r.ok) throw new Error(`jupiter ${r.status}`);
  const arr = await r.json();
  const t = Array.isArray(arr) ? arr.find((x) => x.id === mint) ?? arr[0] : null;
  if (!t || t.id !== mint) throw new Error("token not found on Jupiter (unlisted / not an SPL mint / no market)");

  const a = t.audit ?? {};
  const mintDisabled = a.mintAuthorityDisabled === true;
  const freezeDisabled = a.freezeAuthorityDisabled === true;
  const topPct = typeof a.topHoldersPercentage === "number" ? a.topHoldersPercentage : null;
  const devPct = typeof a.devBalancePercentage === "number" ? a.devBalancePercentage : null;
  const organic = typeof t.organicScore === "number" ? t.organicScore : null;
  const liq = t.liquidity ?? null;
  const ageDays = t.createdAt ? Math.floor((Date.now() - Date.parse(t.createdAt)) / 86400000) : null;

  let score = 0;
  const red: string[] = [], green: string[] = [];
  if (mintDisabled) { score += 24; green.push("mint authority renounced (supply is fixed)"); }
  else red.push("MINT AUTHORITY ACTIVE — team can print unlimited new supply");
  if (freezeDisabled) { score += 18; green.push("freeze authority renounced (tokens can’t be frozen)"); }
  else red.push("FREEZE AUTHORITY ACTIVE — team can freeze your wallet");
  if (topPct != null) {
    if (topPct < 20) { score += 20; green.push(`top holders only ${topPct.toFixed(1)}%`); }
    else if (topPct < 35) score += 12;
    else if (topPct < 50) { score += 4; red.push(`concentrated — top holders ${topPct.toFixed(1)}%`); }
    else red.push(`HIGHLY CONCENTRATED — top holders ${topPct.toFixed(1)}% (dump risk)`);
  }
  if (devPct != null) {
    if (devPct < 1) score += 8;
    else if (devPct < 5) { score += 3; red.push(`dev holds ${devPct.toFixed(2)}%`); }
    else red.push(`DEV HOLDS ${devPct.toFixed(1)}% — insider dump risk`);
  }
  if (liq != null) {
    if (liq >= 100000) { score += 14; green.push(`deep liquidity $${Math.round(liq).toLocaleString()}`); }
    else if (liq >= 25000) score += 9;
    else if (liq >= 5000) { score += 3; red.push(`thin liquidity $${Math.round(liq).toLocaleString()}`); }
    else red.push(`VERY THIN LIQUIDITY $${Math.round(liq).toLocaleString()} — hard/impossible to exit`);
  } else red.push("no priced liquidity found");
  if (organic != null) {
    if (organic >= 70) { score += 12; green.push(`organic score ${organic.toFixed(0)}/100 (real volume, not wash-traded)`); }
    else if (organic >= 40) score += 6;
    else red.push(`LOW ORGANIC SCORE ${organic.toFixed(0)}/100 — volume looks bot/wash-traded`);
  }
  if (t.isVerified) { score += 4; green.push("Jupiter-verified token"); }
  if (ageDays != null && ageDays < 2) red.push(`brand new — ${ageDays}d old (highest rug window)`);

  // Cross-check against DexScreener (second independent source) — additive and optional.
  const dex = await dexP;
  if (dex) {
    if (dex.pairCount >= 3) { score += 3; green.push(`liquidity spread across ${dex.pairCount} DEX pairs`); }
    if (liq != null && dex.liquidityUsd > 0) {
      const ratio = Math.max(liq, dex.liquidityUsd) / Math.max(1, Math.min(liq, dex.liquidityUsd));
      if (ratio > 5) red.push(`sources disagree on liquidity 5x+ (Jupiter $${Math.round(liq).toLocaleString()} vs DexScreener $${dex.liquidityUsd.toLocaleString()}) — treat with caution`);
      else green.push("liquidity confirmed by two independent sources");
    }
  }
  score = Math.max(0, Math.min(100, score));
  const verdict = score >= 75 ? "low-risk" : score >= 45 ? "caution" : "high-risk";

  return {
    mint,
    identity: { name: t.name, symbol: t.symbol, isVerified: !!t.isVerified, tags: t.tags ?? [], holderCount: t.holderCount ?? null, ageDays },
    market: { priceUsd: t.usdPrice ?? null, liquidityUsd: liq, mcap: t.mcap ?? null, fdv: t.fdv ?? null, change24h: t.stats24h?.priceChange ?? null },
    audit: { mintAuthorityDisabled: mintDisabled, freezeAuthorityDisabled: freezeDisabled, topHoldersPercentage: topPct, devBalancePercentage: devPct, organicScore: organic, organicScoreLabel: t.organicScoreLabel ?? null },
    dexScreener: dex,
    safety: { score, verdict, redFlags: red, greenFlags: green },
    disclaimer: DISCLAIMER,
    _generatedAt: new Date().toISOString(),
  };
}

// ---------- x402 (hand-rolled v2, keyless facilitator) ----------

const b64e = (o: unknown) => btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(o))));
const b64d = (s: string) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0))));
const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type,PAYMENT-SIGNATURE,X-PAYMENT", "Access-Control-Expose-Headers": "PAYMENT-REQUIRED,PAYMENT-RESPONSE" };
const json = (o: unknown, status = 200, h: Record<string, string> = {}) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json", ...CORS, ...h } });

const requirements = () => ({ scheme: "exact", network: NETWORK, amount: AMOUNT, asset: ASSET, payTo: PAY_TO, maxTimeoutSeconds: 300, extra: { name: "USD Coin", version: "2" } });
const DESC = "Solana token intelligence: fused safety + market read (authorities, holder concentration, dev holdings, organic-score, liquidity) with a synthesized risk verdict.";
const INPUT_SCHEMA = {
  type: "object",
  required: ["mint"],
  properties: { mint: { type: "string", pattern: "^[1-9A-HJ-NP-Za-km-z]{32,44}$", description: "SPL mint address (base58)" } },
};
const OUTPUT_EXAMPLE = {
  mint: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
  identity: { name: "Bonk", symbol: "Bonk", isVerified: true, tags: ["community"], holderCount: 995000, ageDays: 1290 },
  market: { priceUsd: 0.0000079, liquidityUsd: 6100000, mcap: 620000000, fdv: 700000000, change24h: -1.2 },
  audit: { mintAuthorityDisabled: true, freezeAuthorityDisabled: true, topHoldersPercentage: 12.1, devBalancePercentage: 0, organicScore: 91, organicScoreLabel: "high" },
  dexScreener: { pairCount: 30, liquidityUsd: 1174297, volume24hUsd: 1492394 },
  safety: { score: 95, verdict: "low-risk", redFlags: [], greenFlags: ["mint authority renounced (supply is fixed)", "liquidity confirmed by two independent sources"] },
};
function require402(url: string, error = "Payment required") {
  // Full x402 v2 document in BOTH body and header: some clients/validators (e.g. x402scan's
  // probe) parse the JSON body, others read the PAYMENT-REQUIRED header. The bazaar extension
  // carries invocation schemas so agents/marketplaces know what to send and expect back.
  const doc = {
    x402Version: 2,
    error,
    resource: { url, description: DESC, mimeType: "application/json" },
    accepts: [requirements()],
    extensions: {
      bazaar: {
        schema: {
          properties: {
            input: { properties: { queryParams: INPUT_SCHEMA } },
            output: { properties: { example: OUTPUT_EXAMPLE } },
          },
        },
      },
    },
  };
  return json(doc, 402, { "PAYMENT-REQUIRED": b64e(doc) });
}
// deno-lint-ignore no-explicit-any
async function facilitator(path: string, paymentPayload: any) {
  const r = await fetch(`${FACILITATOR}/${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ x402Version: 2, paymentPayload, paymentRequirements: requirements() }) });
  let data = null; try { data = await r.json(); } catch { /* */ }
  return { ok: r.ok, status: r.status, data };
}

Deno.serve(async (req) => {
  const url = new URL(req.url);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  if (url.pathname === "/healthz") return json({ ok: true });
  if (url.pathname === "/favicon.svg" || url.pathname === "/favicon.ico") {
    return new Response(
      `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#14213d"/><text x="16" y="23" font-size="18" text-anchor="middle" fill="#7df9aa" font-family="monospace">Ti</text></svg>`,
      { headers: { "Content-Type": "image/svg+xml", "Cache-Control": "public, max-age=86400", ...CORS } },
    );
  }
  if (url.pathname === "/.well-known/402index-verify.txt") return new Response(INDEX_HASH, { headers: { "Content-Type": "text/plain", ...CORS } });

  // Discovery documents (x402scan + any crawler): OpenAPI-first, .well-known fan-out as fallback.
  if (url.pathname === "/.well-known/x402") {
    return json({ version: 1, resources: [`${url.origin}/api/token-intel`] });
  }
  if (url.pathname === "/openapi.json") {
    return json({
      openapi: "3.0.3",
      info: {
        title: "Solana Token Intelligence",
        version: "1.0.0",
        description: DESC,
        contact: { name: "Echolonius", url: "https://github.com/Echolonius/token-intel-x402" },
        "x-guidance": "Pay-per-call, no account, no API key. GET /api/token-intel?mint=<base58 SPL mint> with an x402 v2 payment (USDC on Base, $0.02). Unpaid calls return 402 with full requirements in body and PAYMENT-REQUIRED header. Free: GET / (index), GET /healthz, and GET /api/token-intel/demo (fixed BONK sample of the full two-source output).",
      },
      servers: [{ url: url.origin }],
      "x-discovery": { contact: { url: "https://github.com/Echolonius/token-intel-x402" } },
      paths: {
        "/api/token-intel": {
          get: {
            summary: "Fused safety + market read on any Solana token",
            description: DESC,
            "x-payment-info": { protocols: ["x402"], pricingMode: "fixed", price: PRICE_USD.toFixed(2), currency: "USD" },
            parameters: [{ name: "mint", in: "query", required: true, schema: { type: "string", pattern: "^[1-9A-HJ-NP-Za-km-z]{32,44}$" }, description: "SPL mint address (base58)" }],
            responses: {
              "200": { description: "Token intelligence report (identity, market, audit, safety verdict)" },
              "400": { description: "Invalid mint" },
              "402": { description: "Payment required — x402 v2 requirements in PAYMENT-REQUIRED header" },
            },
          },
        },
      },
    });
  }

  if (url.pathname === "/" ) {
    return json({
      service: "solana-token-intelligence",
      version: "1.0.0",
      what: "One keyless call → fused safety + market read on any Solana token, with a synthesized risk verdict. Built for autonomous agents: pay per call in USDC, no API key, no account.",
      payment: { protocol: "x402", x402Version: 2, priceUsd: PRICE_USD, network: NETWORK, asset: ASSET, payTo: PAY_TO, facilitator: FACILITATOR },
      usage: 'GET /api/token-intel?mint=<SPL_MINT>  (PAID) · GET /api/token-intel/demo (free BONK sample) · GET /healthz (free)',
      example: { mint: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263" },
      disclaimer: DISCLAIMER,
    });
  }

  // Free fixed-sample demo (BONK only, cached 10 min): buyers see real output before paying,
  // and it exercises the full intel pipeline in production without touching the paid gate.
  if (url.pathname === "/api/token-intel/demo") {
    const DEMO_MINT = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"; // BONK
    const now = Date.now();
    // deno-lint-ignore no-explicit-any
    const g = globalThis as any;
    if (!g.__demoCache || now - g.__demoCache.at > 600_000) {
      try { g.__demoCache = { at: now, data: await tokenIntel(DEMO_MINT) }; }
      catch (e) { return json({ error: (e as Error).message }, 502); }
    }
    return json({ ...g.__demoCache.data, _demo: "free fixed-sample (BONK). Any other mint: GET /api/token-intel?mint=<mint> with x402 payment ($0.02 USDC on Base)." });
  }

  if (url.pathname === "/api/token-intel") {
    const mint = url.searchParams.get("mint") ?? "";
    const resource = `${url.origin}/api/token-intel`;
    // Payment challenge FIRST (even on a bare probe with no params) — unpaid callers and
    // discovery crawlers must always see the 402 requirements, never a 400.
    const header = req.headers.get("PAYMENT-SIGNATURE") ?? req.headers.get("X-PAYMENT");
    if (!header) return require402(resource);
    if (!isMint(mint)) return json({ error: 'pass ?mint=<base58 SPL mint>' }, 400);
    // deno-lint-ignore no-explicit-any
    let payload: any; try { payload = b64d(header); } catch { return require402(resource, "Malformed payment header"); }
    const v = await facilitator("verify", payload);
    if (!v.ok || !v.data?.isValid) return require402(resource, `Payment verification failed: ${v.data?.invalidReason ?? v.status}`);
    let result; try { result = await tokenIntel(mint); } catch (e) { return json({ error: (e as Error).message }, 502); }
    const s = await facilitator("settle", payload);
    if (!s.ok || !s.data?.success) return require402(resource, `Settlement failed: ${s.data?.errorReason ?? s.status}`);
    return json(result, 200, { "PAYMENT-RESPONSE": b64e(s.data) });
  }

  return json({ error: "not found" }, 404);
});
