/**
 * Next.js adapter for the ATO risk scorer.
 * Covers two common setups: Pages Router API routes, and App Router
 * Route Handlers. Both wrap the same core scoreSessionRisk() function.
 *
 * ---------------------------------------------------------------
 * 1) Pages Router API route (pages/api/withdraw.js)
 * ---------------------------------------------------------------
 *
 *   import { withAtoRisk } from "../../../nextAdapter";
 *
 *   async function handler(req, res) {
 *     // req.atoRisk is available here
 *     res.status(200).json({ ok: true });
 *   }
 *
 *   export default withAtoRisk(handler, {
 *     getEvent: (req) => ({
 *       type: "withdrawal",
 *       status: "success",
 *       deviceFingerprint: req.headers["x-device-id"],
 *       location: req.body?.geo,
 *     }),
 *     getUserHistory: async (req) => await loadUserHistoryFromDB(req.userId),
 *     onHighRisk: (req, res, result) =>
 *       res.status(403).json({ error: "step_up_required", reasons: result.reasons }),
 *   });
 *
 * ---------------------------------------------------------------
 * 2) App Router Route Handler (app/api/withdraw/route.js)
 * ---------------------------------------------------------------
 *
 *   import { NextResponse } from "next/server";
 *   import { evaluateAtoRisk } from "../../../../nextAdapter";
 *
 *   export async function POST(req) {
 *     const result = await evaluateAtoRisk({
 *       event: {
 *         type: "withdrawal",
 *         status: "success",
 *         deviceFingerprint: req.headers.get("x-device-id"),
 *       },
 *       userHistory: await loadUserHistoryFromDB(req),
 *     });
 *
 *     if (result.level === "high") {
 *       return NextResponse.json({ error: "step_up_required", reasons: result.reasons }, { status: 403 });
 *     }
 *
 *     return NextResponse.json({ ok: true, risk: result });
 *   }
 */

const { scoreSessionRisk } = require("./riskScorer");

// ---- Pages Router: HOC-style wrapper ----
function withAtoRisk(handler, { getEvent, getUserHistory, options = {}, onHighRisk = null, onMediumRisk = null }) {
  return async function (req, res) {
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
      return handler(req, res);
    } catch (err) {
      console.error("[withAtoRisk] scoring error, failing open:", err);
      req.atoRisk = { score: 0, level: "low", reasons: ["scorer_error"] };
      return handler(req, res);
    }
  };
}

// ---- App Router: plain async helper, framework-agnostic by design ----
async function evaluateAtoRisk({ event, userHistory, options = {} }) {
  try {
    return scoreSessionRisk(event, userHistory, options);
  } catch (err) {
    console.error("[evaluateAtoRisk] scoring error, failing open:", err);
    return { score: 0, level: "low", reasons: ["scorer_error"] };
  }
}

module.exports = { withAtoRisk, evaluateAtoRisk };
