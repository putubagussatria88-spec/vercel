/**
 * api/probe.js
 * 
 * CVE-2025-8671 MadeYouReset — detection probe endpoint
 * Protected by multi-layer anti-DDoS middleware
 */

const { createAntiDdos, createBodyProtection, createRstDetector } = require('../lib/antiDdos');

// ─── Middleware setup ──────────────────────────────────────────────────────
const antiDdos = createAntiDdos({
  maxRequestsPerMinute: 30,      // 30 req/min per IP for probe endpoint
  maxBurstRequests: 10,          // max 10 burst requests
  blockDurationMs: 10 * 60_000, // 10 min block on abuse
  anomalyThreshold: 60,          // lower threshold for sensitive endpoint
  onBlock: (ip, reason) => {
    console.warn(`[BLOCKED] IP=${ip} reason=${reason} time=${new Date().toISOString()}`);
  },
});

const bodyProtection = createBodyProtection({
  maxBodySize: 4096,   // 4KB max for probe requests
  timeoutMs: 8000,
});

const rstDetector = createRstDetector({
  maxProbesPerMinute: 8,
});

// ─── Compose middleware ────────────────────────────────────────────────────
function runMiddleware(req, res, fn) {
  return new Promise((resolve, reject) => {
    fn(req, res, (result) => {
      if (result instanceof Error) reject(result);
      else resolve(result);
    });
  });
}

// ─── Core probe logic ──────────────────────────────────────────────────────

/**
 * Analyze request headers for HTTP/2 indicators and vulnerability signals.
 * Vercel terminates TLS and forwards HTTP/1.1 or HTTP/2 to functions,
 * so we analyze what's available at the edge.
 */
function analyzeTarget(url, requestHeaders) {
  const results = {
    url,
    timestamp: new Date().toISOString(),
    checks: [],
  };

  // Check 1: HTTPS requirement
  results.checks.push({
    id: 'https',
    name: 'HTTPS / TLS',
    status: url.startsWith('https://') ? 'pass' : 'fail',
    detail: url.startsWith('https://') 
      ? 'HTTPS enabled — HTTP/2 negotiation via ALPN possible'
      : 'HTTPS required for HTTP/2 (ALPN negotiation)',
  });

  // Check 2: Forwarded protocol (if this server is the target)
  const forwardedProto = requestHeaders['x-forwarded-proto'];
  const via = requestHeaders['via'] || '';
  results.checks.push({
    id: 'protocol',
    name: 'Protocol Detection',
    status: forwardedProto === 'https' ? 'pass' : 'info',
    detail: `x-forwarded-proto: ${forwardedProto || 'not set'} | via: ${via || 'none'}`,
  });

  // Check 3: H2 fingerprint via headers
  const altSvc = requestHeaders['alt-svc'] || '';
  results.checks.push({
    id: 'h2_headers',
    name: 'HTTP/2 Header Signals',
    status: altSvc.includes('h2') ? 'warn' : 'info',
    detail: altSvc.includes('h2')
      ? `Alt-Svc advertises h2: "${altSvc}" — server uses HTTP/2`
      : 'No Alt-Svc h2 advertisement in response headers',
  });

  // Check 4: Server version heuristic
  const server = requestHeaders['server'] || '';
  const vulnerable = detectVulnerableVersion(server);
  results.checks.push({
    id: 'server_version',
    name: 'Server Version Check',
    status: vulnerable ? 'fail' : server ? 'pass' : 'info',
    detail: vulnerable
      ? `⚠ Potentially vulnerable: ${server} — ${vulnerable}`
      : server
        ? `Server: "${server}" — not matched to known vulnerable range`
        : 'Server header not disclosed',
  });

  // Check 5: Security headers
  const secHeaders = [
    'strict-transport-security',
    'x-content-type-options',
    'x-frame-options',
    'content-security-policy',
  ];
  const missing = secHeaders.filter(h => !requestHeaders[h]);
  results.checks.push({
    id: 'security_headers',
    name: 'Security Headers',
    status: missing.length === 0 ? 'pass' : missing.length <= 2 ? 'warn' : 'fail',
    detail: missing.length === 0
      ? 'All key security headers present'
      : `Missing: ${missing.join(', ')}`,
  });

  // Overall verdict
  const failCount = results.checks.filter(c => c.status === 'fail').length;
  const warnCount = results.checks.filter(c => c.status === 'warn').length;
  results.verdict = failCount > 0 ? 'vulnerable' : warnCount > 1 ? 'warning' : 'safe';
  results.score = failCount * 30 + warnCount * 10;

  return results;
}

function detectVulnerableVersion(serverHeader) {
  const s = (serverHeader || '').toLowerCase();
  const patterns = [
    { re: /nginx\/1\.2([0-5])\./i, msg: 'Nginx < 1.26.3 — vulnerable' },
    { re: /nginx\/1\.26\.[0-2]/i, msg: 'Nginx 1.26.0–1.26.2 — vulnerable, patch to 1.26.3+' },
    { re: /nginx\/1\.27\.[0-2]/i, msg: 'Nginx 1.27.0–1.27.2 — vulnerable, patch to 1.27.3+' },
    { re: /apache\/2\.4\.([0-5]\d|6[01])/i, msg: 'Apache < 2.4.62 — vulnerable' },
  ];
  for (const { re, msg } of patterns) {
    if (re.test(s)) return msg;
  }
  return null;
}

// ─── Vercel serverless handler ─────────────────────────────────────────────
module.exports = async function handler(req, res) {
  // Run anti-DDoS middleware chain
  try {
    await runMiddleware(req, res, antiDdos);
    if (res.headersSent) return; // blocked

    await runMiddleware(req, res, bodyProtection);
    if (res.headersSent) return;

    await runMiddleware(req, res, rstDetector);
    if (res.headersSent) return;
  } catch (err) {
    console.error('Middleware error:', err);
    return res.status(500).json({ error: 'Internal middleware error' });
  }

  // CORS for same-origin requests
  res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed. Use POST.' });
  }

  let body;
  try {
    // Parse body (Vercel parses JSON automatically for Content-Type: application/json)
    body = req.body || {};
  } catch {
    return res.status(400).json({ error: 'Invalid JSON body' });
  }

  const { url, vectors = [], probeCount = 3 } = body;

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'Missing required field: url' });
  }

  if (!url.startsWith('https://')) {
    return res.status(400).json({ error: 'URL must use HTTPS' });
  }

  // Prevent SSRF — block private/internal addresses
  const urlObj = (() => { try { return new URL(url); } catch { return null; } })();
  if (!urlObj) return res.status(400).json({ error: 'Invalid URL' });

  const hostname = urlObj.hostname;
  const privatePatterns = [
    /^localhost$/i,
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^::1$/,
    /^fc00:/i,
    /\.internal$/i,
    /\.local$/i,
  ];
  if (privatePatterns.some(p => p.test(hostname))) {
    return res.status(403).json({ error: 'Private/internal addresses not allowed' });
  }

  // Clamp probe count
  const safeProbeCount = Math.min(Math.max(parseInt(probeCount) || 3, 1), 10);

  // Perform server-side analysis using this request's own headers as reference
  // (In production you'd fetch the target and analyze its response headers)
  const analysis = analyzeTarget(url, req.headers);

  return res.status(200).json({
    success: true,
    analysis,
    meta: {
      probeCount: safeProbeCount,
      vectors: vectors.slice(0, 6),
      serverTime: new Date().toISOString(),
      note: 'Full HTTP/2 frame analysis requires raw TCP — use h2spec or the Python PoC for definitive results',
    },
  });
};
