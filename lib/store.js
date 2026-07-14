/**
 * In-memory per-user history store. This is the default store used by the
 * zero-config riskScorer() export so `app.use(riskScorer())` works without
 * any setup. It is intentionally simple and NOT suitable for multi-process
 * or multi-instance deployments (each process has its own memory) or for
 * long-term persistence (data is lost on restart).
 *
 * For production use across multiple instances, implement the same
 * interface (getHistory / recordDevice / recordAttempt / recordSession)
 * backed by Redis or your database, and pass it in via `config.store`.
 */

class InMemoryStore {
  constructor({ maxEntries = 50000 } = {}) {
    this._users = new Map();
    this._maxEntries = maxEntries;
  }

  _get(userId) {
    if (!this._users.has(userId)) {
      if (this._users.size >= this._maxEntries) {
        // Evict the oldest entry to bound memory growth.
        const oldestKey = this._users.keys().next().value;
        this._users.delete(oldestKey);
      }
      this._users.set(userId, {
        knownDevices: [],
        failed2faAttempts: 0,
        sessionTimestamps: [],
        lastEventAt: null,
      });
    }
    return this._users.get(userId);
  }

  async getHistory(userId) {
    const record = this._get(userId);
    const oneHourAgo = Date.now() - 60 * 60 * 1000;
    const sessionsLastHour = record.sessionTimestamps.filter((t) => t > oneHourAgo).length;

    return {
      knownDevices: record.knownDevices,
      failed2faAttempts: record.failed2faAttempts,
      sessionsLastHour,
      lastEventTimestamp: record.lastEventAt,
    };
  }

  async recordDevice(userId, fingerprint) {
    const record = this._get(userId);
    if (fingerprint && !record.knownDevices.includes(fingerprint)) {
      record.knownDevices.push(fingerprint);
      if (record.knownDevices.length > 20) record.knownDevices.shift();
    }
  }

  async recordAttempt(userId, success) {
    const record = this._get(userId);
    record.failed2faAttempts = success ? 0 : record.failed2faAttempts + 1;
  }

  async recordSession(userId) {
    const record = this._get(userId);
    const now = Date.now();
    record.sessionTimestamps.push(now);
    record.sessionTimestamps = record.sessionTimestamps.filter((t) => t > now - 60 * 60 * 1000);
    record.lastEventAt = new Date(now).toISOString();
  }
}

module.exports = { InMemoryStore };
