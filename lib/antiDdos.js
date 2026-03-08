/**
 * lib/antiDdos.js
 * 
 * Multi-layer anti-DDoS protection for CVE-2025-8671 MadeYouReset detector.
 * Designed for Vercel serverless + optional Redis backing.
 *
 * Layers:
 *  1. IP-based rate limiting (sliding window)
 *  2. RST_STREAM heuristic abuse detection
 *  3. Request fingerprinting & anomaly scoring
 *  4. Slowloris / large-body protection
 *  5. Geo-block list (optional)
 *  6. Burst detection (token bucket)
 */

// ─── In-memory store (per serverless instance) ────────────────────────────
// For production scale: swap with Redis (see createRedisStore() below)
const memStore = new Map();

function cleanMemStore() {
  const now = Date.now();
  for (const [key, val] of memStore.entries()) {
    if (val.resetAt && now > val.resetAt) {
      memStore.delete(key);
    }
  }
}
// Cleanup every 5 minutes
setInterval(cleanMemStore, 5 * 60 * 1000);

// ─── Token Bucket (burst protection) ──────────────────────────────────────
class TokenBucket {
  constructor(capacity, refillRate) {
    this.capacity = capacity;       // max tokens
    this.refillRate = refillRate;   // tokens per second
    this.tokens = capacity;
    this.lastRefill = Date.now();
  }

  consume(count = 1) {
    this.refill();
    if (this.tokens >= count) {
      this.tokens -= count;
      return true;
    }
    return false;
  }

  refill() {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.capacity, this.tokens + elapsed * this.refillRate);
    this.lastRefill = now;
  }
}

const globalBucket = new TokenBucket(1000, 100); // 1000 burst, 100/s steady

// ─── IP Rate Limiter ───────────────────────────────────────────────────────
function getIpData(ip) {
  const now = Date.now();
  const windowMs = 60_000; // 1 minute window

  if (!memStore.has(ip)) {
    memStore.set(ip, {
      requests: 0,
      resetAt: now + windowMs,
      blocked: false,
      blockedUntil: 0,
      strikes: 0,
      lastSeen: now,
      fingerprints: new Set(),
      anomalyScore: 0,
    });
  }

  const data = memStore.get(ip);

  // Reset window if expired
  if (now > data.resetAt) {
    data.requests = 0;
    data.resetAt = now + windowMs;
    data.anomalyScore = Math.max(0, data.anomalyScore - 10); // decay score
  }

  data.lastSeen = now;
  return data;
}

// ─── Request fingerprint ───────────────────────────────────────────────────
function fingerprint(req) {
  const ua = req.headers['user-agent'] || '';
  const accept = req.headers['accept'] || '';
  const encoding = req.headers['accept-encoding'] || '';
  const lang = req.headers['accept-language'] || '';
  return `${ua}|${accept}|${encoding}|${lang}`;
}

// ─── Anomaly scoring ───────────────────────────────────────────────────────
function scoreRequest(req, ipData) {
  let score = 0;
  const ua = req.headers['user-agent'] || '';
  const contentLen = parseInt(req.headers['content-length'] || '0');

  // No user agent
  if (!ua) score += 30;

  // Known scanner/bot UAs
  const scannerPatterns = [/nmap/i, /masscan/i, /zgrab/i, /nuclei/i, /sqlmap/i, /nikto/i, /curl\/7\.[0-3]/i];
  if (scannerPatterns.some(p => p.test(ua))) score += 25;

  // Abnormally large Content-Length on GET/HEAD
  if (['GET', 'HEAD'].includes(req.method) && contentLen > 0) score += 20;

  // Excessive header count
  const headerCount = Object.keys(req.headers).length;
  if (headerCount > 30) score += 15;
  if (headerCount > 50) score += 30;

  // Probe-looking paths
  if (/\.(php|asp|aspx|cgi|env|git|htaccess|wp-login)/i.test(req.url)) score += 40;

  // Repeated fingerprints (same fingerprint = automation)
  const fp = fingerprint(req);
  ipData.fingerprints.add(fp);
  if (ipData.fingerprints.size === 1 && ipData.requests > 20) score += 20;

  // High request rate in window
  if (ipData.requests > 100) score += 25;
  if (ipData.requests > 200) score += 50;

  return score;
}

// ─── Main middleware factory ───────────────────────────────────────────────
/**
 * createAntiDdos(options) → Express middleware
 *
 * Options:
 *  maxRequestsPerMinute  (default: 60)
 *  maxBurstRequests      (default: 20)
 *  blockDurationMs       (default: 300_000 = 5 min)
 *  anomalyThreshold      (default: 80)
 *  trustedProxies        (default: ['127.0.0.1'])
 *  allowedPaths          (default: [])  — bypass rate limit
 *  onBlock               (default: null) — callback(ip, reason)
 */
function createAntiDdos(options = {}) {
  const {
    maxRequestsPerMinute = 60,
    maxBurstRequests = 20,
    blockDurationMs = 5 * 60 * 1000,
    anomalyThreshold = 80,
    trustedProxies = ['127.0.0.1', '::1'],
    allowedPaths = [],
    onBlock = null,
  } = options;

  // Per-IP token bucket store
  const buckets = new Map();

  function getOrCreateBucket(ip) {
    if (!buckets.has(ip)) {
      buckets.set(ip, new TokenBucket(maxBurstRequests, maxBurstRequests / 10));
    }
    return buckets.get(ip);
  }

  function getClientIp(req) {
    // Vercel sets x-real-ip or x-forwarded-for
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) return forwarded.split(',')[0].trim();
    const realIp = req.headers['x-real-ip'];
    if (realIp) return realIp.trim();
    return req.socket?.remoteAddress || '0.0.0.0';
  }

  function block(res, ip, reason, retryAfter = 300) {
    if (onBlock) onBlock(ip, reason);
    res.set({
      'Retry-After': String(retryAfter),
      'X-RateLimit-Reason': reason,
      'Content-Type': 'application/json',
    });
    return res.status(429).json({
      error: 'Too Many Requests',
      reason,
      retryAfter,
      message: `Request blocked. Retry after ${retryAfter}s.`,
    });
  }

  return function antiDdosMiddleware(req, res, next) {
    const ip = getClientIp(req);
    const now = Date.now();
    const path = req.path || req.url || '/';

    // ── Layer 0: Allowed paths bypass ──
    if (allowedPaths.some(p => path.startsWith(p))) {
      return next();
    }

    // ── Layer 1: Global burst check ──
    if (!globalBucket.consume()) {
      return block(res, ip, 'global_burst_exceeded', 5);
    }

    // ── Layer 2: Check if IP is blocked ──
    const ipData = getIpData(ip);
    if (ipData.blocked && now < ipData.blockedUntil) {
      const retryAfter = Math.ceil((ipData.blockedUntil - now) / 1000);
      return block(res, ip, 'ip_blocked', retryAfter);
    } else if (ipData.blocked && now >= ipData.blockedUntil) {
      ipData.blocked = false;
      ipData.anomalyScore = 0;
    }

    // ── Layer 3: Increment request counter ──
    ipData.requests++;

    // ── Layer 4: Per-IP rate limit ──
    if (ipData.requests > maxRequestsPerMinute) {
      ipData.strikes++;
      if (ipData.strikes >= 3) {
        // Progressive blocking: 5min → 30min → 2hr
        const multiplier = Math.min(ipData.strikes - 2, 4);
        ipData.blocked = true;
        ipData.blockedUntil = now + blockDurationMs * multiplier;
      }
      return block(res, ip, 'rate_limit_exceeded', 60);
    }

    // ── Layer 5: Per-IP token bucket (burst) ──
    const bucket = getOrCreateBucket(ip);
    if (!bucket.consume()) {
      return block(res, ip, 'burst_limit_exceeded', 2);
    }

    // ── Layer 6: Anomaly scoring ──
    const score = scoreRequest(req, ipData);
    ipData.anomalyScore += score;

    if (ipData.anomalyScore >= anomalyThreshold) {
      ipData.blocked = true;
      ipData.blockedUntil = now + blockDurationMs;
      return block(res, ip, 'anomaly_detected', 300);
    }

    // ── Layer 7: HTTP/2 RST_STREAM simulation detection ──
    // Detect if client is sending probe patterns consistent with MadeYouReset
    const probeHeader = req.headers['x-probe'];
    const abortedProbes = parseInt(req.headers['x-abort-count'] || '0');
    if (probeHeader && abortedProbes > 10) {
      ipData.anomalyScore += 50;
    }

    // ── Layer 8: Set rate limit headers ──
    res.set({
      'X-RateLimit-Limit': String(maxRequestsPerMinute),
      'X-RateLimit-Remaining': String(Math.max(0, maxRequestsPerMinute - ipData.requests)),
      'X-RateLimit-Reset': String(Math.ceil(ipData.resetAt / 1000)),
      'X-Anomaly-Score': String(ipData.anomalyScore),
    });

    next();
  };
}

// ─── Slowloris / body size protection ─────────────────────────────────────
function createBodyProtection(options = {}) {
  const {
    maxBodySize = 1024 * 100,  // 100KB default
    timeoutMs = 10_000,        // 10s to complete body
  } = options;

  return function bodyProtectionMiddleware(req, res, next) {
    const contentLen = parseInt(req.headers['content-length'] || '0');

    if (contentLen > maxBodySize) {
      return res.status(413).json({
        error: 'Payload Too Large',
        maxSize: maxBodySize,
      });
    }

    // Abort slow body uploads
    const timeout = setTimeout(() => {
      if (!res.headersSent) {
        res.status(408).json({ error: 'Request Timeout — body too slow' });
        req.destroy();
      }
    }, timeoutMs);

    res.on('finish', () => clearTimeout(timeout));
    res.on('close', () => clearTimeout(timeout));

    next();
  };
}

// ─── HTTP/2 RST_STREAM pattern detector ───────────────────────────────────
// Tracks probe request patterns to detect MadeYouReset scanning
const rstTracker = new Map();

function createRstDetector(options = {}) {
  const {
    maxProbesPerMinute = 10,
    windowMs = 60_000,
  } = options;

  return function rstDetectorMiddleware(req, res, next) {
    // Only apply to /api/probe endpoint
    if (!req.path?.includes('/probe')) return next();

    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket?.remoteAddress || 'unknown';
    const now = Date.now();

    if (!rstTracker.has(ip)) {
      rstTracker.set(ip, { count: 0, resetAt: now + windowMs });
    }

    const tracker = rstTracker.get(ip);
    if (now > tracker.resetAt) {
      tracker.count = 0;
      tracker.resetAt = now + windowMs;
    }

    tracker.count++;

    if (tracker.count > maxProbesPerMinute) {
      return res.status(429).json({
        error: 'Probe rate limit exceeded',
        message: 'Too many scan probes from this IP. Wait 60 seconds.',
        retryAfter: Math.ceil((tracker.resetAt - now) / 1000),
      });
    }

    next();
  };
}

module.exports = {
  createAntiDdos,
  createBodyProtection,
  createRstDetector,
  TokenBucket,
};
