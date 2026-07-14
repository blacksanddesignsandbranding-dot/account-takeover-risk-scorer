/**
 * Lightweight device fingerprint derived from request headers.
 * Not a substitute for a dedicated fingerprinting library (e.g. FingerprintJS)
 * on the client side — this is a server-side best-effort signal based on
 * what's available in a plain HTTP request, intended as a reasonable default
 * for the zero-config path. Swap in a stronger fingerprint via config.getDeviceFingerprint
 * if you already collect one client-side.
 */

const crypto = require("crypto");

function fingerprintFromRequest(req) {
  const ua = req.headers?.["user-agent"] || "";
  const acceptLang = req.headers?.["accept-language"] || "";
  const ip = req.ip || req.headers?.["x-forwarded-for"] || req.socket?.remoteAddress || "";

  const raw = `${ua}|${acceptLang}|${ip}`;
  return crypto.createHash("sha256").update(raw).digest("hex").slice(0, 16);
}

module.exports = { fingerprintFromRequest };
