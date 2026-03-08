# CVE-2025-8671 MadeYouReset Detector

Defensive detection tool for the MadeYouReset HTTP/2 vulnerability.
Includes multi-layer anti-DDoS protection for Node.js/Vercel.

## Quick Deploy

```bash
# 1. Install Vercel CLI
npm install -g vercel

# 2. Install dependencies
npm install

# 3. Test locally
vercel dev

# 4. Deploy to production
vercel --prod
```

## Anti-DDoS Layers (lib/antiDdos.js)

1. Global token bucket (1000 burst / 100 req/s)
2. IP block list with progressive duration
3. Per-IP sliding window rate limit (30 req/min on /api/probe)
4. Per-IP token bucket (10 burst)
5. Anomaly scoring (UA, header count, path patterns)
6. RST_STREAM probe detector
7. Body size + slowloris protection
8. SSRF prevention (private IP block)

## Project Structure

```
api/probe.js      POST /api/probe — scanner with full anti-DDoS
api/health.js     GET  /api/health
lib/antiDdos.js   8-layer middleware
public/index.html Frontend
vercel.json       Config + security headers
```

## Environment Variables (optional)

| Variable | Default | Description |
|---|---|---|
| `ALLOWED_ORIGIN` | `*` | CORS origin for /api/probe |

## Legal

For authorized use only. Only scan servers you own or have explicit written permission to test.
