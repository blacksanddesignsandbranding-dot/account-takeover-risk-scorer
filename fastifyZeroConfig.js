/**
 * Zero-config Fastify plugin for the ATO risk scorer.
 *
 * Usage:
 *
 *   const { riskScorerPlugin } = require('devguard-labs-risk-scorer/fastifyZeroConfig');
 *
 *   fastify.register(riskScorerPlugin, {
 *     threshold: 75,
 *     onRiskDetected: (request, score, result) => request.log.warn({ score }, 'risk detected'),
 *   });
 *
 *   fastify.post('/login', async (request, reply) => {
 *     // request.riskScore and request.riskAssessment are available here
 *   });
 *
 * This mirrors index.js's riskScorer() for Express — same config shape,
 * same default in-memory store, same signal coverage caveats:
 *
 * Scores automatically: new_device, session_velocity, brute_force_then_success.
 * Does NOT score impossible_travel, recovery_after_number_change, or
 * high_value_action_after_reset — those need route-specific context. Use
 * fastifyAdapter.js on individual sensitive routes for full six-signal
 * coverage.
 */

const { scoreSessionRisk } = require("./riskScorer");
const { InMemoryStore } = require("./lib/store");
const { fingerprintFromRequest } = require("./lib/fingerprint");

function defaultGetUserId(request) {
  return (
    request.body?.email ||
    request.body?.username ||
    request.ip ||
    request.headers?.["x-forwarded-for"] ||
    "anonymous"
  );
}

function riskScorerPlugin(fastify, opts, done) {
  const {
    threshold = 75,
    onRiskDetected = () => {},
    block = false,
    getUserId = defaultGetUserId,
    getDeviceFingerprint = fingerprintFromRequest,
    store = new InMemoryStore(),
    weights,
    thresholds,
  } = opts || {};

  fastify.addHook("onRequest", async (request, reply) => {
    let userId, fingerprint, result;

    try {
      userId = getUserId(request);
      fingerprint = getDeviceFingerprint(request);
      const history = await store.getHistory(userId);
      const event = { type: "login", deviceFingerprint: fingerprint };

      result = scoreSessionRisk(event, history, { weights, thresholds });
      request.riskScore = result.score;
      request.riskAssessment = result;

      if (result.score >= threshold) {
        onRiskDetected(request, result.score, result);
        if (block) {
          reply.code(403).send({ error: "risk_threshold_exceeded", reasons: result.reasons });
          return;
        }
      }
    } catch (err) {
      request.log
        ? request.log.error(err, "[riskScorerPlugin] scoring error, failing open")
        : console.error("[riskScorerPlugin] scoring error, failing open:", err);
      request.riskScore = 0;
      request.riskAssessment = { score: 0, level: "low", reasons: ["scorer_error"] };
    }

    // Stash for the onResponse hook below, which records the outcome once
    // the status code is known.
    request._riskScorerUserId = userId;
    request._riskScorerFingerprint = fingerprint;
  });

  fastify.addHook("onResponse", async (request, reply) => {
    const userId = request._riskScorerUserId;
    if (!userId) return;

    try {
      const success = reply.statusCode < 400;
      await store.recordAttempt(userId, success);
      await store.recordDevice(userId, request._riskScorerFingerprint);
      await store.recordSession(userId);
    } catch (err) {
      console.error("[riskScorerPlugin] failed to record request outcome:", err);
    }
  });

  done();
}

module.exports = { riskScorerPlugin };
