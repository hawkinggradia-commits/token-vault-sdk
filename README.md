# TokenVault SDK (`token-vault-sdk`)

> **Zero-Latency In-Process Hybrid AI Gateway, Local RAM Prompt Cache & FinOps Circuit Breaker**  
> Official Website: [https://www.tockenvault.com](https://www.tockenvault.com) | Live Platform: [https://www.tokenvault.com](https://www.tokenvault.com)  
> Built by [Phrona](https://www.phrona.com)

---

## Overview

**TokenVault** replaces slow, high-latency cloud gateway proxies (such as Portkey, Cloudflare AI Gateway, or Helicone) with a zero-external-dependency, in-memory local interceptor.

Rather than routing your private API keys and customer prompts through third-party remote servers—adding 80ms–150ms of network latency and compliance risk—**TokenVault executes directly inside your application's host process** in **< 0.02ms**.

### Key Architectural Invariants

- **0.1ms Hybrid Local-First Gateway:** Eliminates remote cloud proxy hops.
- **Hard 512 KB RAM Ceiling:** In-memory `KVFlow` cost-density ring buffer never exceeds 512 KB of process memory.
- **100% Fail-Open Reliability:** Wraps all proxy logic in fail-safe blocks. If anything fails, it falls back to native unintercepted provider calls immediately without dropping requests.
- **Zero External Dependencies:** Built purely on native runtimes (`httpx` / `urllib` in Python; `globalThis.fetch` in Node.js, Next.js, and V8 Edge).
- **Multi-Provider Direct Fallback:** Immediate on-host failover across **OpenAI**, **Anthropic**, and **Google Gemini** upon HTTP 429 rate limits, 5xx outages, or timeouts.
- **Runaway Agent 3-Strike Loop Breaker:** Detects recursive agent hallucinations or repetitive loop queries and halts them on-host before racking up thousands in unmonitored API bills.
- **Reversible In-RAM PII Vault:** Scrubs credit cards (Luhn-verified), API credentials, JWTs, Indian PAN/Aadhaar, and HIPAA data in local memory before payloads leave your server, rehydrating response streams transparently.
- **100% Lossless Shadow Mode by Default:** Operates non-destructively without altering prompt context or dropping tools.

---

## Included Runtime SDKs

This repository distributes the two single-file standalone SDK conduits:

| File | Runtime | Target Ecosystems | Memory Footprint |
| :--- | :--- | :--- | :--- |
| **`token-vault.js`** | Node.js 18+, Bun, Deno, Cloudflare Workers, Next.js | `fetch`, `openai`, `@anthropic-ai/sdk`, `langchain` | Hard capped at `512 KB` |
| **`token_vault.py`** | Python 3.9+ | `httpx`, `openai`, `anthropic`, `google-genai`, `langchain`, `crewai` | Hard capped at `512 KB` |

---

## Quick Start: JavaScript / TypeScript / Node.js

Drop `token-vault.js` into your project and initialize it once at your application's entry point:

```javascript
// index.js / server.ts / app/layout.tsx
import "./token-vault.js";

// Now every standard fetch, OpenAI, and Anthropic call automatically
// enjoys 0.02ms deduplication, multi-provider failover, and local caching.
const response = await fetch("https://api.openai.com/v1/chat/completions", {
  method: "POST",
  headers: {
    "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Hello world" }],
  }),
});
```

---

## Quick Start: Python

Import and activate `token_vault` at the beginning of your script, agent, or FastAPI server:

```python
# main.py
import token_vault

# Activate the in-process interceptor
token_vault.init()

# Use OpenAI, Anthropic, or httpx exactly as normal:
from openai import OpenAI
client = OpenAI()

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Analyze quarterly token usage"}]
)
print(response.choices[0].message.content)
```

---

## Comparison: TokenVault vs. Traditional Cloud Gateways

| Feature | TokenVault SDK | Remote Cloud Gateways (Portkey / Cloudflare) | Basic Local Cache |
| :--- | :--- | :--- | :--- |
| **Gateway Latency** | **< 0.02ms** (in-process RAM) | 80ms – 150ms remote hop | 10ms – 30ms (Redis) |
| **Data Privacy** | **100% On-Host** (never leaves process) | Prompts traverse 3rd-party servers | On-host or internal network |
| **Provider Fallback** | **Instant Local Normalization** | Cloud proxy retry | None (custom code required) |
| **Agent Loop Breaker**| **3-Strike Circuit Breaker** | None or delayed cloud quota | None |
| **Pricing** | **Flat Monthly** (Zero per-request fee) | Metered per-token markup | Infrastructure maintenance |
| **Dependencies** | **0 External Dependencies** | Heavy SDKs / Remote routing | Redis daemon / connection pool |

---

## Workplace & FinOps Dashboard

Connect your SDK telemetry with the interactive TokenVault Workplace to monitor real-time token savings, gross spend, and recoverable leakage:

- **Official Web Portal:** [https://www.tockenvault.com](https://www.tockenvault.com)
- **First Month 100% Free:** Full access upon sign-in (no credit card or pre-subscription required).

---

## Topics

`#openai` `#anthropic` `#llm-gateway` `#prompt-caching` `#finops`

---

## License & Support

Maintained by **Phrona** ([https://www.phrona.com](https://www.phrona.com)).  
For questions, commercial team licenses, or enterprise support, visit [https://www.tockenvault.com](https://www.tockenvault.com).
