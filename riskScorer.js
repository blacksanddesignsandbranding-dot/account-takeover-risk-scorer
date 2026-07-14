/**
 * Account Takeover (ATO) Risk Scorer
 * -----------------------------------
 * Framework-agnostic scoring engine. Feed it an `event` (the current
 * auth-related action) and `userHistory` (recent state you track per user),
 * and it returns a risk score + reasons. Wire the result into your own
 * auth middleware (see expressMiddleware.js for an example adapter).
 *
 * You own the data model: userHistory is just a plain object you maintain
 * in your DB/cache (Redis is a good fit for the time-based fields).
 */

const DEFAULT_WEIGHTS = {
  newDevice: 25,
  impossibleTravel: 30,
  bruteForceThenSuccess: 20,
  recoveryAfterNumberChange: 35,
  highValueActionAfterReset: 40,
  sessionVelocity: 15,
  ipReputation: 45,
};

const DEFAULT_THRESHOLDS = {
  medium: 30,
  high: 60,
};

/**
 * Haversine distance in km between two {lat, lng} points.
 */
function geoDistanceKm(a, b) {
  if (!a || !b) return 0;
  const toRad = (deg) => (deg * Math.PI) / 180;
  const R = 6371;
  const dLat = toRad(b.lat - a.lat);
  const dLng = toRad(b.lng - a.lng);
  const lat1 = toRad(a.lat);
  const lat2 = toRad(b.lat);

  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}

function minutesSince(timestamp) {
  if (!timestamp) return Infinity;
  return (Date.now() - new Date(timestamp).getTime()) / 60000;
}

/**
 * @param {Object} event
 *   event.type                 - "login" | "password_reset" | "withdrawal" | "payment" | "add_payee" | ...
 *   event.status                - "success" | "failed"
 *   event.deviceFingerprint     - string identifying the device/browser
 *   event.location              - { lat, lng }
 *   event.timestamp             - ISO string (defaults to now)
 *   event.ip                    - string IPv4 address, used with options.ipReputationList
 *   event.ipReputationListed    - boolean, precomputed IP-blocklist result (bypasses options.ipReputationList if set)
 *
 * @param {Object} userHistory
 *   userHistory.knownDevices          - array of previously seen device fingerprints
 *   userHistory.lastKnownLocation     - { lat, lng }
 *   userHistory.lastLoginTimestamp    - ISO string
 *   userHistory.failed2faAttempts     - number, recent consecutive failures
 *   userHistory.phoneNumberChangedAt  - ISO string | null
 *   userHistory.lastPasswordResetAt   - ISO string | null
 *   userHistory.sessionsLastHour      - number
 *
 * @param {Object} [options]
 *   options.weights            - override DEFAULT_WEIGHTS
 *   options.thresholds         - override DEFAULT_THRESHOLDS
 *   options.ipReputationList   - an IpReputationList instance (see lib/ipReputation.js),
 *                                checked against event.ip. No effect if event.ip is absent
 *                                or event.ipReputationListed is explicitly set.
 *
 * @returns {{score: number, level: "low"|"medium"|"high", reasons: string[]}}
 */
function scoreSessionRisk(event, userHistory = {}, options = {}) {
  const weights = { ...DEFAULT_WEIGHTS, ...(options.weights || {}) };
  const thresholds = { ...DEFAULT_THRESHOLDS, ...(options.thresholds || {}) };

  let risk = 0;
  const reasons = [];

  // 1. New / unrecognized device
  const knownDevices = userHistory.knownDevices || [];
  if (event.deviceFingerprint && !knownDevices.includes(event.deviceFingerprint)) {
    risk += weights.newDevice;
    reasons.push("new_device");
  }

  // 2. Impossible travel: big geo jump in a short time window
  if (event.location && userHistory.lastKnownLocation) {
    const distanceKm = geoDistanceKm(event.location, userHistory.lastKnownLocation);
    const minsSinceLastLogin = minutesSince(userHistory.lastLoginTimestamp);
    if (distanceKm > 500 && minsSinceLastLogin < 120) {
      risk += weights.impossibleTravel;
      reasons.push("impossible_travel");
    }
  }

  // 3. Brute-force pattern immediately followed by success
  if ((userHistory.failed2faAttempts || 0) >= 3 && event.status === "success") {
    risk += weights.bruteForceThenSuccess;
    reasons.push("brute_force_then_success");
  }

  // 4. Password/recovery flow shortly after a phone number change (SIM-swap signal)
  if (event.type === "password_reset" && userHistory.phoneNumberChangedAt) {
    if (minutesSince(userHistory.phoneNumberChangedAt) < 24 * 60) {
      risk += weights.recoveryAfterNumberChange;
      reasons.push("recovery_after_number_change");
    }
  }

  // 5. High-value action shortly after a password reset (key ATO signal)
  const highValueActions = ["withdrawal", "payment", "add_payee"];
  if (highValueActions.includes(event.type) && userHistory.lastPasswordResetAt) {
    if (minutesSince(userHistory.lastPasswordResetAt) < 15) {
      risk += weights.highValueActionAfterReset;
      reasons.push("high_value_action_after_reset");
    }
  }

  // 6. Session velocity spike
  if ((userHistory.sessionsLastHour || 0) > 5) {
    risk += weights.sessionVelocity;
    reasons.push("session_velocity");
  }

  // 7. IP reputation — local blocklist match (no external API call).
  // Either pass options.ipReputationList (an IpReputationList instance,
  // checked against event.ip), or precompute the check yourself and pass
  // event.ipReputationListed = true/false directly (useful if you already
  // do IP lookups elsewhere, e.g. against your own abuse-log table).
  const ipListed =
    typeof event.ipReputationListed === "boolean"
      ? event.ipReputationListed
      : options.ipReputationList && event.ip
      ? options.ipReputationList.isListed(event.ip)
      : false;

  if (ipListed) {
    risk += weights.ipReputation;
    reasons.push("ip_reputation");
  }

  const score = Math.min(risk, 100);
  const level = score < thresholds.medium ? "low" : score < thresholds.high ? "medium" : "high";

  return { score, level, reasons };
}

module.exports = { scoreSessionRisk, geoDistanceKm, DEFAULT_WEIGHTS, DEFAULT_THRESHOLDS };
