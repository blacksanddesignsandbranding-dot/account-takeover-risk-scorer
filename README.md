
---

# Account Takeover (ATO) Risk Scorer for Node.js

**The lightweight, zero-dependency middleware for Express, Next.js, and Fastify.**

Stop sending sensitive login telemetry to expensive, high-latency third-party fraud APIs. Implement a local, tunable rules engine to catch ATO, SIM-swapping, and brute-force patterns within your own infrastructure.

## Why use this?

* **Zero-Latency:** No external API calls. Everything runs locally in your Node.js process.
* **100% Data Privacy:** No telemetry data ever leaves your servers. Fully GDPR/CCPA compliant by design.
* **Tunable Rules Engine:** Move away from "black-box" security. Our transparent rules allow you to adjust risk thresholds to your specific traffic patterns.
* **Fail-Open Architecture:** Your auth flow is mission-critical. If the middleware encounters an error, it fails open, ensuring your users are never locked out due to vendor downtime.

## Quick Start

Install the package directly into your project:

```bash
npm install devguard-labs-risk-scorer

```

Integrate into your Express login flow in minutes:

```javascript
const express = require('express');
const { riskScorer } = require('devguard-labs-risk-scorer');
const app = express();

app.use(riskScorer({
  threshold: 75, // Risk score trigger
  onRiskDetected: (req, score) => console.warn(`Risk detected: ${score}`)
}));

app.post('/login', (req, res) => {
  // Your existing auth logic here
});

```

## When to use this

This middleware is designed for developers who:

* Need to secure login/registration flows without adding network latency.
* Require full ownership of security data for compliance reasons.
* Want to catch common anomalies like "impossible travel" or high-frequency login attempts without the cost of enterprise fraud-detection suites.

## Roadmap

* [ ] IP reputation list support (static file injection).
* [ ] Customizable JSON rule definitions.
* [ ] Support for additional framework adaptors (Koa, NestJS).

---

*If you find this middleware useful for your stack, consider giving this repo a ⭐ to help other developers find it.*

---

