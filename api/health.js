/**
 * api/health.js
 * Simple health check — no rate limiting needed
 */
module.exports = function handler(req, res) {
  res.status(200).json({
    status: 'ok',
    service: 'CVE-2025-8671 MadeYouReset Detector',
    version: '1.0.0',
    time: new Date().toISOString(),
  });
};
