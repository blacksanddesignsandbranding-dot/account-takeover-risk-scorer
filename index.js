/**
 * Zero-config entry point: `riskScorer()`.
 *
 * This is the `app.use(riskScorer({ threshold, onRiskDetected }))` API
 * shown in the README Quick Start. It is deliberately simpler than the
 * route-specific adapters (expressMiddleware.js, fastifyAdapter.js,
 * nextAdapter.js) — those give you full control over event type, location,
 * and history storage; this gives you a reasonable default so the package
 * works the moment you `app.use()` it, with no database wiring required.
 *
 * IMPORTANT — signal coverage in zero-config mode:
 * Three of the seven signals in riskScorer.js require information that is
 * not available from a generic, framework-level middleware (event type,
 * transaction amount, geolocation, phone-number-change timestamps). In
 * zero-config mode, riskScorer() actively scores:
 *   - new_device
 *   - session_velocity
 *   - brute_force_then_success (evaluated across requests, using status
 *     codes from previous responses)
 *   - ip_reputation (only if you pass an `ipReputationList` — see below;
 *     off by default, since there's no bundled blocklist)
 *
 * It does NOT score impossible_travel, recovery_after_number_change, or
 * high_value_action_after_reset out of the box, because those require
 * route-specific context (e.g. "this is a withdrawal for $X" or "this is
 * a password reset"). For that full signal set, wrap your sensitive routes
 * individually with expressMiddleware.js / fastifyAdapter.js / nextAdapter.js
 * — see the Integration guide.
 *
 * Zero-config mode also uses an in-memory store by default, which does not
 * share state across multiple processes/instances. Pass your own `store`
 * (Redis, DB-backed) implementing the same interface as lib/store.js for
 * production deployments running more than one instance.
 */

const { scoreSessionRisk } = require("./riskScorer");
const { InMemoryStore } = require("./lib/store");
const { fingerprintFromRequest } = require("./lib/fingerprint");

function defaultGetUserId(req) {
  return (
    req.body?.email ||
    req.body?.username ||
    req.ip ||
    req.headers?.["x-forwarded-for"] ||
    req.socket?.remoteAddress ||
    "anonymous"
  );
}

function defaultGetIp(req) {
  return req.ip || req.headers?.["x-forwarded-for"] || req.socket?.remoteAddress || null;
}

function riskScorer(config = {}) {
  const {
    threshold = 75,
    onRiskDetected = () => {},
    block = false,
    getUserId = defaultGetUserId,
    getDeviceFingerprint = fingerprintFromRequest,
    getIp = defaultGetIp,
    store = new InMemoryStore(),
    weights,
    thresholds,
    ipReputationList, // optional IpReputationList instance — see lib/ipReputation.js
  } = config;

  return async function (req, res, next) {
    let userId, fingerprint, result;

    try {
      userId = getUserId(req);
      fingerprint = getDeviceFingerprint(req);
      const history = await store.getHistory(userId);

      const event = {
        type: "login",
        deviceFingerprint: fingerprint,
        ip: getIp(req),
      };

      result = scoreSessionRisk(event, history, { weights, thresholds, ipReputationList });
      req.riskScore = result.score;
      req.riskAssessment = result;

      if (result.score >= threshold) {
        onRiskDetected(req, result.score, result);
        if (block) {
          return res.status(403).json({ error: "risk_threshold_exceeded", reasons: result.reasons });
        }
      }
    } catch (err) {
      // Fail open: a scorer bug should never block legitimate traffic.
      console.error("[riskScorer] scoring error, failing open:", err);
      req.riskScore = 0;
      req.riskAssessment = { score: 0, level: "low", reasons: ["scorer_error"] };
    }

    // Record outcome after the response completes, so brute-force and
    // device history are available for this user's NEXT request.
    if (res && typeof res.on === "function" && userId) {
      res.on("finish", async () => {
        try {
          const success = res.statusCode < 400;
          await store.recordAttempt(userId, success);
          await store.recordDevice(userId, fingerprint);
          await store.recordSession(userId);
        } catch (err) {
          console.error("[riskScorer] failed to record request outcome:", err);
        }
      });
    }

    next();
  };
}

module.exports = {
  riskScorer,
  scoreSessionRisk,
  InMemoryStore,
  fingerprintFromRequest,
};
