require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const GSB_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
const VT_KEY = process.env.VIRUSTOTAL_API_KEY;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---- Helpers ----

// Base64url-encode a URL the way VirusTotal expects for its "url id"
function vtUrlId(url) {
  return Buffer.from(url)
    .toString('base64')
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function isValidUrl(str) {
  try {
    const u = new URL(str);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

// ---- Google Safe Browsing ----
async function checkGoogleSafeBrowsing(targetUrl) {
  if (!GSB_KEY) return { checked: false, reason: 'No API key configured' };

  const body = {
    client: { clientId: 'verilink', clientVersion: '1.0.0' },
    threatInfo: {
      threatTypes: [
        'MALWARE',
        'SOCIAL_ENGINEERING',
        'UNWANTED_SOFTWARE',
        'POTENTIALLY_HARMFUL_APPLICATION'
      ],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url: targetUrl }]
    }
  };

  const res = await fetch(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GSB_KEY}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }
  );

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Google Safe Browsing error (${res.status}): ${text}`);
  }

  const data = await res.json();
  const matches = data.matches || [];
  return {
    checked: true,
    flagged: matches.length > 0,
    threatTypes: matches.map(m => m.threatType)
  };
}

// ---- VirusTotal ----
async function checkVirusTotal(targetUrl) {
  if (!VT_KEY) return { checked: false, reason: 'No API key configured' };

  const id = vtUrlId(targetUrl);

  // Try to fetch an existing analysis first (fast path, no quota spent on submission)
  let res = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
    headers: { 'x-apikey': VT_KEY }
  });

  if (res.status === 404) {
    // Not scanned before — submit it
    const submitRes = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': VT_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `url=${encodeURIComponent(targetUrl)}`
    });

    if (!submitRes.ok) {
      const text = await submitRes.text();
      throw new Error(`VirusTotal submit error (${submitRes.status}): ${text}`);
    }

    const submitData = await submitRes.json();
    const analysisId = submitData.data.id;

    // Poll the analysis a few times — VT scans take a few seconds
    let stats = null;
    for (let i = 0; i < 6; i++) {
      await new Promise(r => setTimeout(r, 2500));
      const analysisRes = await fetch(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        { headers: { 'x-apikey': VT_KEY } }
      );
      if (!analysisRes.ok) continue;
      const analysisData = await analysisRes.json();
      if (analysisData.data.attributes.status === 'completed') {
        stats = analysisData.data.attributes.stats;
        break;
      }
    }

    return {
      checked: true,
      pending: stats === null,
      stats: stats || null
    };
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`VirusTotal error (${res.status}): ${text}`);
  }

  const data = await res.json();
  const stats = data.data.attributes.last_analysis_stats;
  return { checked: true, pending: false, stats };
}

// ---- Combined verdict ----
function buildVerdict(gsb, vt) {
  const gsbFlagged = gsb.checked && gsb.flagged;
  const vtMalicious = vt.checked && vt.stats ? vt.stats.malicious || 0 : 0;
  const vtSuspicious = vt.checked && vt.stats ? vt.stats.suspicious || 0 : 0;

  if (gsbFlagged || vtMalicious > 0) {
    return { level: 'danger', label: 'Threat detected' };
  }
  if (vtSuspicious > 0) {
    return { level: 'warning', label: 'Suspicious — proceed with caution' };
  }
  if ((gsb.checked || vt.checked) && !gsbFlagged && vtMalicious === 0) {
    return { level: 'safe', label: 'No threats found' };
  }
  return { level: 'unknown', label: 'Unable to verify' };
}

// ---- API route ----
app.post('/api/check', async (req, res) => {
  const { url } = req.body;

  if (!url || !isValidUrl(url)) {
    return res.status(400).json({ error: 'Please provide a valid http(s) URL.' });
  }

  try {
    const [gsb, vt] = await Promise.all([
      checkGoogleSafeBrowsing(url).catch(err => ({ checked: false, error: err.message })),
      checkVirusTotal(url).catch(err => ({ checked: false, error: err.message }))
    ]);

    const verdict = buildVerdict(gsb, vt);

    res.json({ url, verdict, googleSafeBrowsing: gsb, virusTotal: vt });
  } catch (err) {
    res.status(500).json({ error: 'Something went wrong while scanning that URL.' });
  }
});

app.listen(PORT, () => {
  console.log(`VeriLink running at http://localhost:${PORT}`);
  if (!GSB_KEY || !VT_KEY) {
    console.warn('Warning: missing API key(s) in .env — check .env.example');
  }
});
