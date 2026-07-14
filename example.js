/**
 * Minimal runnable example.
 * Run with: node example.js
 */

const { scoreSessionRisk } = require("./riskScorer");

// Simulate a user's stored history (you'd load this from your DB/Redis)
const userHistory = {
  knownDevices: ["device-abc-123"],
  lastKnownLocation: { lat: -26.2041, lng: 28.0473 }, // Johannesburg
  lastLoginTimestamp: new Date(Date.now() - 60 * 60 * 1000).toISOString(), // 1hr ago
  failed2faAttempts: 0,
  phoneNumberChangedAt: null,
  lastPasswordResetAt: new Date(Date.now() - 5 * 60 * 1000).toISOString(), // 5 min ago
  sessionsLastHour: 2,
};

// Simulate a suspicious event: withdrawal from a brand-new device, far away,
// right after a password reset.
const event = {
  type: "withdrawal",
  status: "success",
  deviceFingerprint: "device-new-999",
  location: { lat: 51.5074, lng: -0.1278 }, // London — far from JHB
};

const result = scoreSessionRisk(event, userHistory);

console.log("Risk result:", result);
// Expect: high score, reasons including new_device, impossible_travel,
// and high_value_action_after_reset
