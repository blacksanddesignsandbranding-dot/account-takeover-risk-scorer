# ATO Risk Scorer

Drop-in account-takeover / SIM-swap risk-scoring middleware for Node.js apps. No ML pipeline, no external fraud API — just tunable, transparent rules you can drop into an existing login flow in under an hour.

---

## 🛡️ Production-Ready Bundle
This repository contains the documentation and implementation architecture guidelines. The optimized, production-grade, and fully self-hosted middleware bundle can be downloaded instantly here:

👉 **[Get the Production Bundle on Gumroad](https://1cf25c166759491.gumroad.com/l/jxfklq)**

---

## What it catches

- **New/unrecognized device** logging in
- **Impossible travel** (large geo jump in a short time window)
- **Brute-force-then-success** 2FA pattern
- **Recovery flow shortly after a phone number change** (classic SIM-swap signal)
- **High-value action right after a password reset** (the strongest single ATO signal)
- **Session velocity spikes**

## Quick start

```bash
npm install
node example.js
```

```js
const { scoreSessionRisk } = require("./riskScorer");[cite: 2]

const result = scoreSessionRisk(event, userHistory);[cite: 2]
// => { score: 95, level: "high", reasons: ["new_device", "impossible_travel", ...] }[cite: 2]
