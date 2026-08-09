const scanContainer = document.getElementById('scan-form');
const input = document.getElementById('url-input');
const btn = document.getElementById('scan-btn');
const results = document.getElementById('results');
const errorBox = document.getElementById('error-box');

const verdictCard = document.getElementById('verdict-card');
const verdictBadge = document.getElementById('verdict-badge');
const verdictLabel = document.getElementById('verdict-label');
const verdictUrl = document.getElementById('verdict-url');

const gsbStatus = document.getElementById('gsb-status');
const gsbBody = document.getElementById('gsb-body');
const vtStatus = document.getElementById('vt-status');
const vtBody = document.getElementById('vt-body');
const historySection = document.getElementById('history-section');
const historyList = document.getElementById('history-list');
const clearHistoryBtn = document.getElementById('clear-history-btn');
const historyToggleBtn = document.getElementById('history-toggle-btn');

const HISTORY_KEY = 'verilink-scan-history';
const BADGES = { danger: '⚠', warning: '!', safe: '✓', unknown: '?' };
let historyExpanded = false;

async function runScan() {
  const url = input.value.trim();
  if (!url) return;

  results.classList.add('hidden');
  errorBox.classList.add('hidden');
  btn.disabled = true;
  btn.textContent = 'Scanning…';

  try {
    const res = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Something went wrong.');
    }

    renderResults(data);
    addScanHistory({
      url: data.url,
      level: data.verdict.level,
      label: data.verdict.label,
      scannedAt: new Date().toISOString()
    });
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Scan URL';
  }
}

function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
  } catch {
    return [];
  }
}

function saveHistory(items) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(items));
}

function addScanHistory(entry) {
  const history = loadHistory();
  history.unshift(entry);
  saveHistory(history.slice(0, 10));
  renderHistory();
}

function renderHistory() {
  const history = loadHistory();

  if (!history.length) {
    historySection.classList.add('hidden');
    historyList.innerHTML = '';
    if (historyToggleBtn) historyToggleBtn.classList.add('hidden');
    return;
  }

  historySection.classList.remove('hidden');
  if (historyToggleBtn) {
    historyToggleBtn.classList.toggle('hidden', history.length <= 1);
    historyToggleBtn.textContent = historyExpanded ? 'Hide history' : `Show all scans (${history.length})`;
  }

  const itemsToRender = historyExpanded || history.length === 1 ? history : history.slice(0, 1);
  historyList.innerHTML = itemsToRender
    .map((item) => {
      const when = new Date(item.scannedAt).toLocaleString();
      return `
        <div class="history-item">
          <div class="history-details">
            <div class="history-url">${item.url}</div>
            <div class="history-meta">${item.label} · ${when}</div>
          </div>
          <span class="history-badge ${item.level}">${BADGES[item.level] || '?'}</span>
        </div>
      `;
    })
    .join('');
}

btn.addEventListener('click', runScan);
input.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    runScan();
  }
});

if (historyToggleBtn) {
  historyToggleBtn.addEventListener('click', () => {
    historyExpanded = !historyExpanded;
    renderHistory();
  });
}

clearHistoryBtn.addEventListener('click', () => {
  localStorage.removeItem(HISTORY_KEY);
  historyExpanded = false;
  renderHistory();
});

renderHistory();

function renderResults(data) {
  const { url, verdict, googleSafeBrowsing, virusTotal } = data;

  verdictCard.className = `verdict-card ${verdict.level}`;
  verdictBadge.textContent = BADGES[verdict.level] || '?';
  verdictLabel.textContent = verdict.label;
  verdictUrl.textContent = url;

  // Google Safe Browsing panel
  if (!googleSafeBrowsing.checked) {
    gsbStatus.textContent = 'Unavailable';
    gsbStatus.classList.remove('flagged');
    gsbBody.innerHTML = `<p>${googleSafeBrowsing.error || googleSafeBrowsing.reason || 'Could not complete this check.'}</p>`;
  } else if (googleSafeBrowsing.flagged) {
    gsbStatus.textContent = 'Flagged';
    gsbStatus.classList.add('flagged');
    gsbBody.innerHTML = `<p>Matched threat type(s):</p><p><strong>${googleSafeBrowsing.threatTypes.join(', ')}</strong></p>`;
  } else {
    gsbStatus.textContent = 'Clean';
    gsbStatus.classList.remove('flagged');
    gsbBody.innerHTML = `<p>No known threats matched by Google Safe Browsing.</p>`;
  }

  // VirusTotal panel
  if (!virusTotal.checked) {
    vtStatus.textContent = 'Unavailable';
    vtStatus.classList.remove('flagged');
    vtBody.innerHTML = `<p>${virusTotal.error || virusTotal.reason || 'Could not complete this check.'}</p>`;
  } else if (virusTotal.pending) {
    vtStatus.textContent = 'Pending';
    vtStatus.classList.remove('flagged');
    vtBody.innerHTML = `<p>This URL is still being analyzed. Try scanning again in a moment.</p>`;
  } else if (virusTotal.stats) {
    const s = virusTotal.stats;
    const flagged = (s.malicious || 0) > 0 || (s.suspicious || 0) > 0;
    vtStatus.textContent = flagged ? 'Flagged' : 'Clean';
    vtStatus.classList.toggle('flagged', flagged);
    vtBody.innerHTML = `
      <div class="stat-row"><span>Malicious</span><span>${s.malicious || 0}</span></div>
      <div class="stat-row"><span>Suspicious</span><span>${s.suspicious || 0}</span></div>
      <div class="stat-row"><span>Harmless</span><span>${s.harmless || 0}</span></div>
      <div class="stat-row"><span>Undetected</span><span>${s.undetected || 0}</span></div>
    `;
  } else {
    vtStatus.textContent = 'No data';
    vtBody.innerHTML = `<p>No analysis data returned.</p>`;
  }

  results.classList.remove('hidden');
}
