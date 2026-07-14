/**
 * Zero-config Next.js Middleware for the ATO risk scorer.
 *
 * Usage (middleware.js at your project root):
 *
 *   import { createRiskScorerMiddleware } from 'devguard-labs-risk-scorer/nextZeroConfig';
 *
 *   const scorer = createRiskScorerMiddleware({
 *     threshold: 75,
 *     onRiskDetected: (req, score, result) => console.warn('Risk detected:', score),
 *   });
 *
 *   export const middleware = scorer;
 *   export const config = { matcher: ['/login', '/api/login'] };
 *
 * IMPORTANT — honest limitations of this entry point, please read before use:
 *
 * 1. Next.js Middleware runs on the Edge runtime, which has no Node.js
 *    `crypto` module and no guaranteed shared memory across invocations
 *    (each request may be handled by a different, isolated instance). The
 *    default in-memory store WILL lose history between requests in most
 *    real deployments. For anything beyond local development, pass a
 *    `store` backed by an edge-compatible database (Upstash Redis, Vercel
 *    KV, etc.) implementing the same interface as lib/store.js.
 *
 * 2. Middleware runs BEFORE your route handler and does not know the
 *    eventual response status your login logic will produce. This means
 *    the automatic brute_force_then_success signal (which needs to know
 *    whether the previous attempt succeeded or failed) cannot be scored
 *    automatically here, unlike the Express/Fastify zero-config entry
 *    points. To use it, call `scorer.recordAttempt(userId, success)`
 *    yourself from inside your login route handler once you know the
 *    outcome — see example below.
 *
 * Given these two constraints, out of the box this entry point reliably
 * scores: new_device and session_velocity only, and only within a single
 * warm Edge instance unless you supply a real external store.
 *
 * Example of recording an outcome from your route handler:
 *
 *   import { scorer } from '../../middleware';
 *   export async function POST(req) {
 *     const ok = await verifyCredentials(req);
 *     await scorer.recordAttempt(getUserIdFromReq(req), ok);
 *     ...
 *   }
 */

const { scoreSessionRisk } = require("./riskScorer");
const { InMemoryStore } = require("./lib/store");

async function fingerprintFromRequestEdge(request) {
  const ua = request.headers.get("user-agent") || "";
  const lang = request.headers.get("accept-language") || "";
  const ip =
    request.headers.get("x-forwarded-for") ||
    request.ip ||
    "";

  const raw = `${ua}|${lang}|${ip}`;
  const encoded = new TextEncoder().encode(raw);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 16);
}

function defaultGetUserId(request) {
  return (
    request.headers.get("x-user-id") ||
    request.headers.get("x-forwarded-for") ||
    request.ip ||
    "anonymous"
  );
}

function createRiskScorerMiddleware(config = {}) {
  const {
    threshold = 75,
    onRiskDetected = () => {},
    block = false,
    getUserId = defaultGetUserId,
    getDeviceFingerprint = fingerprintFromRequestEdge,
    store = new InMemoryStore(),
    weights,
    thresholds,
    // Allows tests / non-Next edge runtimes (Cloudflare Workers, etc.) to
    // inject their own response builder instead of requiring next/server.
    NextResponse: InjectedNextResponse,
  } = config;

  async function middleware(request) {
    const NextResponse = InjectedNextResponse || require("next/server").NextResponse;

    let userId, fingerprint, result;

    try {
      userId = getUserId(request);
      fingerprint = await getDeviceFingerprint(request);
      const history = await store.getHistory(userId);
      const event = { type: "login", deviceFingerprint: fingerprint };

      result = scoreSessionRisk(event, history, { weights, thresholds });

      if (result.score >= threshold) {
        onRiskDetected(request, result.score, result);
        if (block) {
          return NextResponse.json(
            { error: "risk_threshold_exceeded", reasons: result.reasons },
            { status: 403 }
          );
        }
      }

      // Recorded immediately, not on a response-finished hook — see the
      // module doc comment on why brute-force scoring needs a manual
      // recordAttempt() call from your route handler in this entry point.
      await store.recordDevice(userId, fingerprint);
      await store.recordSession(userId);

      const response = NextResponse.next();
      response.headers.set("x-risk-score", String(result.score));
      response.headers.set("x-risk-level", result.level);
      return response;
    } catch (err) {
      console.error("[nextZeroConfig] scoring error, failing open:", err);
      return NextResponse.next();
    }
  }

  // Exposed so route handlers can report the true success/failure of a
  // login or sensitive action after the fact, enabling brute-force
  // detection despite middleware running before the handler.
  middleware.recordAttempt = (userId, success) => store.recordAttempt(userId, success);
  middleware.store = store;

  return middleware;
}

module.exports = { createRiskScorerMiddleware, fingerprintFromRequestEdge };
