require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const GSB_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
const VT_KEY = process.env.VIRUSTOTAL_API_KEY;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map((s) => s.trim().replace(/\/$/, '')).filter(Boolean);

if (!GSB_KEY || !VT_KEY) console.warn('Warning: API keys missing - scans will be limited.');
if (!ALLOWED_ORIGINS.length) console.warn('Warning: ALLOWED_ORIGINS is empty - browsers will be blocked by CORS.');

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

app.use(cors({
  origin(origin, cb) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(null, false);
  },
  methods: ['POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
  maxAge: 86400,
}));
app.use(express.json({ limit: '10kb' }));

const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many scans from this device. Please wait a few minutes and try again.' },
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const vtUrlId = (url) => Buffer.from(url).toString('base64url');

function isValidUrl(str) {
  try { const u = new URL(str); return u.protocol === 'http:' || u.protocol === 'https:'; }
  catch { return false; }
}

async function checkGoogleSafeBrowsing(url) {
  if (!GSB_KEY) return { checked: false, error: 'Not configured' };
  try {
    const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GSB_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'verilink', clientVersion: '2.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      }),
    });
    if (!res.ok) return { checked: false, error: `HTTP ${res.status}` };
    const matches = (await res.json()).matches || [];
    return { checked: true, flagged: matches.length > 0, threats: matches.map((m) => m.threatType) };
  } catch { return { checked: false, error: 'Request failed' }; }
}

async function checkVirusTotal(url) {
  if (!VT_KEY) return { checked: false, error: 'Not configured' };
  const headers = { 'x-apikey': VT_KEY };
  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${vtUrlId(url)}`, { headers });
    let stats;
    if (res.status === 404) {
      const sub = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ url }).toString(),
      });
      if (!sub.ok) return { checked: false, error: `HTTP ${sub.status}` };
      const id = (await sub.json()).data.id;
      for (let i = 0; i < 6; i++) {
        await sleep(2500);
        const a = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, { headers });
        if (!a.ok) continue;
        const ad = await a.json();
        if (ad.data.attributes.status === 'completed') { stats = ad.data.attributes.stats; break; }
      }
      if (!stats) return { checked: false, error: 'Analysis timed out' };
    } else if (res.ok) {
      stats = (await res.json()).data.attributes.last_analysis_stats;
    } else return { checked: false, error: `HTTP ${res.status}` };
    return {
      checked: true,
      malicious: stats.malicious || 0, suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0, undetected: stats.undetected || 0,
    };
  } catch { return { checked: false, error: 'Request failed' }; }
}

// A single engine out of ~90 flagging a URL is very often a false positive,
// so VirusTotal needs several engines to agree before we call a URL dangerous.
const VT_DANGER_THRESHOLD = 3;

function buildVerdict(gsb, vt) {
  if ((gsb.checked && gsb.flagged) || (vt.checked && vt.malicious >= VT_DANGER_THRESHOLD))
    return { level: 'danger', label: 'Dangerous — do not visit this site' };
  if (vt.checked && (vt.malicious > 0 || vt.suspicious > 0)) {
    const n = vt.malicious + vt.suspicious;
    return {
      level: 'warning',
      label: `Low-confidence warning — ${n} security ${n === 1 ? 'engine' : 'engines'} flagged this. Likely a false alarm, but proceed with caution.`,
    };
  }
  if (gsb.checked || vt.checked) return { level: 'safe', label: 'No threats detected' };
  return { level: 'unknown', label: 'Could not check this URL right now' };
}

app.get('/', (req, res) => res.json({ service: 'verilink-api', status: 'ok' }));
app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.post('/api/check', scanLimiter, async (req, res) => {
  const url = typeof req.body?.url === 'string' ? req.body.url.trim() : '';
  if (!url || url.length > 2048 || !isValidUrl(url))
    return res.status(400).json({ error: 'Please enter a valid URL starting with http:// or https://' });
  try {
    const [googleSafeBrowsing, virusTotal] = await Promise.all([checkGoogleSafeBrowsing(url), checkVirusTotal(url)]);
    res.json({ url, verdict: buildVerdict(googleSafeBrowsing, virusTotal), googleSafeBrowsing, virusTotal });
  } catch {
    res.status(500).json({ error: 'Something went wrong while scanning. Please try again.' });
  }
});

app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid request.' });
  res.status(500).json({ error: 'Something went wrong.' });
});

app.listen(PORT, () => console.log(`VeriLink API listening on ${PORT}`));
