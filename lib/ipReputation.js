/**
 * Local IP reputation list — matches the roadmap item "IP reputation list
 * support (static file injection)".
 *
 * This is deliberately NOT a live API lookup. The whole value proposition
 * of this package is zero external calls and zero added latency, so IP
 * reputation here means: you supply a list of known-bad IPs/CIDR ranges
 * (from a threat-intel feed you already trust, a Tor exit node list, your
 * own abuse logs, etc.), and this checks membership locally, synchronously,
 * with no network round-trip.
 *
 * Supports individual IPv4 addresses and IPv4 CIDR ranges (e.g. "1.2.3.0/24").
 * IPv6 is not supported in this version — see class doc below.
 */

class IpReputationList {
  /**
   * @param {string[]} entries - array of IPv4 addresses and/or CIDR ranges,
   *   e.g. ["203.0.113.7", "198.51.100.0/24"]
   */
  constructor(entries = []) {
    this.singleIps = new Set();
    this.cidrRanges = []; // [{ base: number, mask: number }]

    for (const entry of entries) {
      this.add(entry);
    }
  }

  add(entry) {
    const trimmed = String(entry).trim();
    if (!trimmed) return;

    if (trimmed.includes("/")) {
      const parsed = parseCidr(trimmed);
      if (parsed) this.cidrRanges.push(parsed);
    } else {
      this.singleIps.add(trimmed);
    }
  }

  /**
   * @param {string} ip - IPv4 address to check, e.g. from req.ip
   * @returns {boolean}
   */
  isListed(ip) {
    if (!ip) return false;
    // Strip IPv6-mapped IPv4 prefix some frameworks add, e.g. "::ffff:1.2.3.4"
    const normalized = ip.replace(/^::ffff:/i, "");

    if (this.singleIps.has(normalized)) return true;

    const ipInt = ipv4ToInt(normalized);
    if (ipInt === null) return false; // not IPv4 (e.g. real IPv6) — not supported

    for (const range of this.cidrRanges) {
      if ((ipInt & range.mask) === (range.base & range.mask)) return true;
    }

    return false;
  }

  /**
   * Load a list from a newline-delimited text file (one IP or CIDR per
   * line, "#" comments allowed). Node.js only (uses fs), not for browser/edge.
   */
  static fromFile(filePath) {
    const fs = require("fs");
    const content = fs.readFileSync(filePath, "utf8");
    const entries = content
      .split("\n")
      .map((line) => line.split("#")[0].trim())
      .filter(Boolean);
    return new IpReputationList(entries);
  }
}

function ipv4ToInt(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    result = (result << 8) | n;
  }
  return result >>> 0;
}

function parseCidr(cidr) {
  const [ip, prefixStr] = cidr.split("/");
  const prefix = Number(prefixStr);
  const base = ipv4ToInt(ip);
  if (base === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return null;
  }
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { base, mask };
}

module.exports = { IpReputationList, ipv4ToInt };
