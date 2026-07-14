/**
 * Fastify adapter for the ATO risk scorer.
 *
 * Usage (as a preHandler hook on a specific route):
 *
 *   const { atoRiskPreHandler } = require("./fastifyAdapter");
 *
 *   fastify.post("/withdraw", {
 *     preHandler: atoRiskPreHandler({
 *       getEvent: (req) => ({
 *         type: "withdrawal",
 *         status: "success",
 *         deviceFingerprint: req.headers["x-device-id"],
 *         location: req.geo,
 *       }),
 *       getUserHistory: async (req) => await loadUserHistoryFromDB(req.user.id),
 *       onHighRisk: async (req, reply, result) => {
 *         reply.code(403).send({ error: "step_up_required", reasons: result.reasons });
 *       },
 *     }),
 *   }, withdrawHandler);
 *
 * Result is attached to req.atoRisk for downstream handlers/logging.
 * Fails open by default (same rationale as the Express adapter).
 */

const { scoreSessionRisk } = require("./riskScorer");

function atoRiskPreHandler({
  getEvent,
  getUserHistory,
  options = {},
  onHighRisk = null,
  onMediumRisk = null,
} = {}) {
  if (typeof getEvent !== "function" || typeof getUserHistory !== "function") {
    throw new Error("atoRiskPreHandler requires getEvent and getUserHistory functions");
  }

  return async function (request, reply) {
    try {
      const event = await getEvent(request);
      const userHistory = await getUserHistory(request);

      const result = scoreSessionRisk(event, userHistory, options);
      request.atoRisk = result;

      if (result.level === "high" && onHighRisk) {
        return await onHighRisk(request, reply, result);
      }
      if (result.level === "medium" && onMediumRisk) {
        return await onMediumRisk(request, reply, result);
      }
      // returning nothing lets Fastify continue to the route handler
    } catch (err) {
      request.log?.error?.(err, "[atoRiskPreHandler] scoring error, failing open");
      request.atoRisk = { score: 0, level: "low", reasons: ["scorer_error"] };
    }
  };
}

/**
 * Optional: register as a Fastify plugin that decorates every request
 * with a `computeAtoRisk(event, userHistory)` helper instead of using
 * a preHandler on specific routes.
 */
function atoRiskPlugin(fastify, opts, done) {
  fastify.decorateRequest("computeAtoRisk", function (event, userHistory, overrideOptions) {
    return scoreSessionRisk(event, userHistory, overrideOptions || opts.options || {});
  });
  done();
}

module.exports = { atoRiskPreHandler, atoRiskPlugin };
