# Account Takeover (ATO) Risk Scorer for Node.js / Express

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Dependency Count](https://img.shields.io/badge/dependencies-zero-success.svg)](package.json)
[![Platform](https://img.shields.io/badge/node-%3E%3D%2016.0.0-informational.svg)](https://nodejs.org)

Drop-in account-takeover / SIM-swap risk-scoring middleware for Node.js apps. No ML pipeline, no external fraud API — just tunable, transparent rules you can drop into an existing login flow in under an hour.

---

## 📦 Production-Ready Bundle

This repository contains the documentation and implementation architecture guidelines. The optimized, production-grade, and fully self-hosted middleware bundle can be downloaded instantly:

👉 👉 **[Download the Production Middleware Bundle](https://1cf25c166759491.gumroad.com/l/jxfklq)**
---

## 🚀 Quick Start & Implementation

### 1. Basic Usage (Express)
```javascript
const express = require('express');
const { atoRiskScorer } = require('account-takeover-risk-scorer');

const app = express();
app.use(express.json());

// Apply globally or to sensitive authentication routes
app.post('/api/login', atoRiskScorer({
  failOpen: true,
  onHighRisk: (req, res, score) => {
    // Seamlessly trigger MFA or step-up authentication
    return res.status(403).json({ error: "Step-up authentication required", riskScore: score });
  }
}), (req, res) => {
  res.json({ success: true });
});
