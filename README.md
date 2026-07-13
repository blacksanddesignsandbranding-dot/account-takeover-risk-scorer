

# Account Takeover (ATO) Risk Scorer for Node.js

The lightweight, zero-dependency middleware for **Express, Next.js, and Fastify**.

Stop sending sensitive login telemetry to expensive, high-latency third-party fraud APIs. Implement a local, tunable rules engine to catch ATO, SIM-swapping, and brute-force patterns natively within your own infrastructure.

## Why use this?

*   **Zero-Latency**: No external API calls. All processing happens locally in your Node.js process.
*   **100% Data Privacy**: No telemetry data ever leaves your servers. Fully GDPR/CCPA compliant by design.
*   **Transparent & Tunable**: Move away from "black-box" security. Our transparent rules allow you to adjust risk thresholds to your specific traffic patterns.
*   **Fail-Open Architecture**: Your auth flow is mission-critical. If the middleware encounters an error, it fails open, ensuring your users are never locked out due to vendor downtime.

## Quick Start

**1. Install**
```bash
npm install devguard-labs-risk-scorer

```

**2. Integrate (Express Example)**

```javascript
const express = require('express');
const { riskScorer } = require('devguard-labs-risk-scorer');

const app = express();

app.use(riskScorer({
  threshold: 75, // Risk score trigger
  onRiskDetected: (req, score) => console.warn(`Risk detected: ${score}`)
}));

app.post('/login', (req, res) => {
  // Your existing auth logic
});

```

## When to use this

* You need to secure login/registration flows without adding network latency.
* You require full ownership of security data for compliance.
* You want to catch common anomalies like "impossible travel" or high-frequency login attempts without the cost of enterprise fraud-detection suites.

## Roadmap

* [ ] IP reputation list support (static file injection).
* [ ] Customizable JSON rule definitions.
* [ ] Support for additional framework adaptors (Koa, NestJS).

---

*If you find this middleware useful for your stack, consider giving this repo a ⭐ to help other developers find it.*




