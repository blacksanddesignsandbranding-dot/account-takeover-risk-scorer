# Account Takeover (ATO) Risk Scorer for Node.js

The zero-dependency middleware for **Express, Next.js, and Fastify**.

Stop sending sensitive login telemetry to expensive, high-latency third-party
fraud APIs. Implement a local, tunable rules engine to catch account
takeover, SIM-swapping, and brute-force patterns natively within your own
infrastructure.

## Why use this?

- **Zero latency**: no external API calls — all processing happens locally in your Node.js process.
- **You keep the data**: no telemetry ever leaves your servers, which simplifies GDPR/CCPA data-residency and vendor-risk questions (this library is a data-minimization tool, not a substitute for your own compliance review).
- **Transparent and tunable**: no black-box scoring — every rule and weight is visible and adjustable to your traffic patterns.
- **Fail-open architecture**: if the middleware hits an internal error, requests proceed rather than locking users out.

## Quick start

**1. Install**

```bash
npm install github:blacksanddesignsandbranding-dot/account-takeover-risk-scorer
```

This installs directly from the GitHub repo — no separate npm registry
publish required. Because `package.json`'s `name` field is
`devguard-labs-risk-scorer`, all the `require`/`import` examples below
work exactly as shown regardless of install source.

*(A registry install via `npm install devguard-labs-risk-scorer` may be
added later — check the repo's README for the current recommended install
command.)*

**2. Integrate (Express example)**

```javascript
const express = require('express');
const { riskScorer } = require('devguard-labs-risk-scorer');
const app = express();

app.use(riskScorer({
  threshold: 75, // risk score that triggers onRiskDetected
  onRiskDetected: (req, score) => console.warn(`Risk detected: ${score}`)
}));

app.post('/login', (req, res) => {
  // your existing auth logic — req.riskScore and req.riskAssessment
  // are available here
});
```

That's it — no database setup required to get started. `riskScorer()` uses
an in-memory store by default to track known devices and recent activity
per user.

### Zero-config for Fastify and Next.js

```js
// Fastify
const { riskScorerPlugin } = require('devguard-labs-risk-scorer/fastifyZeroConfig');
fastify.register(riskScorerPlugin, { threshold: 75, onRiskDetected });
```

```js
// Next.js — middleware.js at your project root
import { createRiskScorerMiddleware } from 'devguard-labs-risk-scorer/nextZeroConfig';
export const middleware = createRiskScorerMiddleware({ threshold: 75, onRiskDetected });
export const config = { matcher: ['/login', '/api/login'] };
```

### What zero-config mode actually scores

**Express and Fastify** (`riskScorer()`, `riskScorerPlugin`): evaluate
three of the six available signals automatically —

- **New/unrecognized device**
- **Session velocity spikes**
- **Brute-force-then-success** pattern (tracked across requests, via a
  response-finished hook)

**Next.js Middleware** (`createRiskScorerMiddleware`): scores
**new_device** and **session_velocity** automatically. It does **not**
score brute-force-then-success out of the box — Next.js Middleware runs
*before* your route handler and can't see the eventual response status.
Call `middleware.recordAttempt(userId, success)` from inside your route
handler once you know the outcome to enable that signal — see the
[Integration guide](../../wiki/Integration-guide) for the full pattern.

None of the zero-config entry points score impossible travel, SIM-swap
recovery timing, or high-value-action-after-reset — those require knowing
what the request actually *is* (a withdrawal, a password reset, a
location), which a blanket middleware doesn't have. For that full signal
set, wrap your sensitive routes individually — see below.

### Storage caveats — read this before deploying

- **Express / Fastify**: the default `InMemoryStore` does not share state
  across multiple app instances. For production deployments running more
  than one process, pass your own `store` (Redis/DB-backed, same interface
  as `lib/store.js`) via `riskScorer({ store })` / `riskScorerPlugin`'s
  options.
- **Next.js Middleware**: runs on the Edge runtime, where instances are
  often isolated and short-lived — the default in-memory store is
  unreliable in most real deployments beyond local development. Use an
  edge-compatible external store (Upstash Redis, Vercel KV, etc.)
  implementing the same interface for anything beyond local testing.

## Full signal set (route-level integration)

For the complete six-signal engine — including impossible travel and
SIM-swap-specific detection — wrap individual sensitive routes directly
using the lower-level exports. This requires you to supply user history
from your own database, but gives full control over what's scored.

Included out of the box: **Express**, **Fastify**, and **Next.js** (both
App Router and Pages Router). The core scorer has zero framework
dependencies, so writing an adapter for anything else (Koa, NestJS, Hono...)
is a short wrapper — use any of these as a template.

### Express

```js
const { atoRiskMiddleware } = require('devguard-labs-risk-scorer/expressMiddleware');

app.post(
  "/withdraw",
  atoRiskMiddleware({
    getEvent: (req) => ({
      type: "withdrawal",
      status: "success",
      deviceFingerprint: req.headers["x-device-id"],
      location: req.geo,
    }),
    getUserHistory: (req) => loadUserHistoryFromDB(req.user.id),
    onHighRisk: (req, res, result) =>
      res.status(403).json({ error: "step_up_required", reasons: result.reasons }),
  }),
  withdrawHandler
);
```

### Fastify

```js
const { atoRiskPreHandler } = require('devguard-labs-risk-scorer/fastifyAdapter');

fastify.post("/withdraw", {
  preHandler: atoRiskPreHandler({
    getEvent: (req) => ({ type: "withdrawal", status: "success", deviceFingerprint: req.headers["x-device-id"] }),
    getUserHistory: (req) => loadUserHistoryFromDB(req.user.id),
    onHighRisk: (req, reply, result) =>
      reply.code(403).send({ error: "step_up_required", reasons: result.reasons }),
  }),
}, withdrawHandler);
```

### Next.js — App Router

```js
import { evaluateAtoRisk } from 'devguard-labs-risk-scorer/nextAdapter';

export async function POST(req) {
  const result = await evaluateAtoRisk({
    event: { type: "withdrawal", status: "success", deviceFingerprint: req.headers.get("x-device-id") },
    userHistory: await loadUserHistoryFromDB(req),
  });

  if (result.level === "high") {
    return Response.json({ error: "step_up_required", reasons: result.reasons }, { status: 403 });
  }
  return Response.json({ ok: true, risk: result });
}
```

### Next.js — Pages Router

```js
import { withAtoRisk } from 'devguard-labs-risk-scorer/nextAdapter';

async function handler(req, res) {
  res.status(200).json({ ok: true, risk: req.atoRisk });
}

export default withAtoRisk(handler, {
  getEvent: (req) => ({ type: "withdrawal", status: "success", deviceFingerprint: req.headers["x-device-id"] }),
  getUserHistory: (req) => loadUserHistoryFromDB(req.userId),
  onHighRisk: (req, res, result) => res.status(403).json({ error: "step_up_required", reasons: result.reasons }),
});
```

See the [Integration guide](../../wiki/Integration-guide) on the wiki for full setup notes and troubleshooting.

## All six signals (reference)

- **New/unrecognized device** logging in
- **Impossible travel** (large geo jump in a short time window)
- **Brute-force-then-success** 2FA pattern
- **Recovery flow shortly after a phone number change** (classic SIM-swap signal)
- **High-value action right after a password reset** (the strongest single ATO signal)
- **Session velocity spikes**

## Core API (advanced / custom integrations)

```js
const { scoreSessionRisk } = require('devguard-labs-risk-scorer');

const result = scoreSessionRisk(event, userHistory);
// => { score: 95, level: "high", reasons: ["new_device", "impossible_travel", ...] }
```

Run the bundled example directly:

```bash
node example.js
```

## Design notes

- **Fails open by default.** If the scorer throws, the request proceeds and
  logs the error rather than locking out legitimate users. Flip this in
  the relevant adapter if your risk tolerance needs fail-closed instead.
- **You own the data.** `userHistory` is a plain object — pull it from
  Postgres, Redis, DynamoDB, whatever you already use. No vendor lock-in.
- **Weights and thresholds are fully configurable** — pass `options.weights`
  / `options.thresholds` to `scoreSessionRisk` (or the equivalent config
  on `riskScorer()` / `riskScorerPlugin` / `createRiskScorerMiddleware`) to
  tune to your risk appetite.
- **Framework-agnostic core.** `riskScorer.js` has zero dependencies on
  any framework — write your own adapter for Koa, Hono, etc. in a few lines
  using `expressMiddleware.js` as a template.

## When to use this

- You need to secure login/registration flows without adding network latency.
- You require full ownership of security data for compliance.
- You want to catch common anomalies like impossible travel or high-frequency
  login attempts without the cost of an enterprise fraud-detection suite.

## What this is NOT

This is a rules-based first line of defense, not a replacement for your
bank/processor's existing fraud systems (e.g. card-network fraud scoring).
It's meant to catch account-takeover patterns specifically, using signals
available at the application layer — not a full enterprise fraud platform.

## Roadmap

- [x] Zero-config entry points for Express, Fastify, and Next.js Middleware
- [ ] IP reputation list support (static file injection)
- [ ] Customizable JSON rule definitions
- [ ] Support for additional framework adapters (Koa, NestJS)

## License

Buyer receives a license to use and modify this code within their own
product(s). Resale or redistribution of the source as a competing template
is not permitted. (Adjust this line to match your actual listing terms.)

---
*If you find this middleware useful for your stack, consider giving this repo a ⭐ to help other developers find it.*




