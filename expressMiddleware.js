/**
 * Express adapter for the ATO risk scorer.
 *
 * Usage:
 *   const { atoRiskMiddleware } = require("./expressMiddleware");
 *
 *   app.post("/login", atoRiskMiddleware({
 *     getEvent: (req) => ({
 *       type: "login",
 *       status: "success", // set after you verify credentials, or run this post-auth
 *       deviceFingerprint: req.headers["x-device-id"],
 *       location: req.geo, // e.g. from a geo-IP lookup middleware you already run
 *     }),
 *     getUserHistory: async (req) => await loadUserHistoryFromDB(req.user.id),
 *     onHighRisk: async (req, res, result) => {
 *       // e.g. force step-up 2FA instead of blocking outright
 *       return res.status(403).json({ error: "step_up_required", reasons: result.reasons });
 *     },
 *   }), loginHandler);
 *
 * The middleware attaches `req.atoRisk = { score, level, reasons }` for any
 * downstream handler/logger to use, and only short-circuits the request when
 * you provide onHighRisk / onMediumRisk callbacks.
 */

const { scoreSessionRisk } = require("./riskScorer");

function atoRiskMiddleware({
  getEvent,
  getUserHistory,
  options = {},
  onHighRisk = null,
  onMediumRisk = null,
} = {}) {
  if (typeof getEvent !== "function" || typeof getUserHistory !== "function") {
    throw new Error("atoRiskMiddleware requires getEvent and getUserHistory functions");
  }

  return async function (req, res, next) {
    try {
      const event = await getEvent(req);
      const userHistory = await getUserHistory(req);

      const result = scoreSessionRisk(event, userHistory, options);
      req.atoRisk = result;

      if (result.level === "high" && onHighRisk) {
        return await onHighRisk(req, res, result);
      }
      if (result.level === "medium" && onMediumRisk) {
        return await onMediumRisk(req, res, result);
      }

      return next();
    } catch (err) {
      // Fail open by default so a scorer bug never locks legitimate users out.
      // Flip this to fail-closed if your risk tolerance requires it.
      console.error("[atoRiskMiddleware] scoring error, failing open:", err);
      req.atoRisk = { score: 0, level: "low", reasons: ["scorer_error"] };
      return next();
    }
  };
}

module.exports = { atoRiskMiddleware };
