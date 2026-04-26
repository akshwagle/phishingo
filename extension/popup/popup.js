// PhishFilter Pro — Popup
// Uses module type; lib files imported inline for MV3 compatibility

const PROD_URL = 'https://phishingo-production.up.railway.app';
const DEFAULT_BACKEND = PROD_URL;

// circumference for r=24: 2π*24 ≈ 150.796
const CIRC = 150.796;

// ── DOM refs ───────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const dom = {
  statusDot: $('status-dot'),
  statusLabel: $('status-label'),
  domain: $('page-domain'),
  verdictBadge: $('verdict-badge'),
  summary: $('page-summary'),
  scoreRing: $('score-ring'),
  scoreNum: $('score-num'),
  scanPulse: $('scan-pulse'),
  flagsPreview: $('flags-preview'),
  btnScanPage: $('btn-scan-page'),
  btnViewDetails: $('btn-view-details'),
  statBlocked: $('stat-blocked'),
  statLinks: $('stat-links'),
  statPasswords: $('stat-passwords'),
  statPhishes: $('stat-phishes'),
  engQwen: $('eng-qwen'),
  engKimi: $('eng-kimi'),
  engDs: $('eng-ds'),
  engGem: $('eng-gem'),
  engGpt: $('eng-gpt'),
  engineNote: $('engine-note'),
  activitySection: $('activity-section'),
  activityList: $('activity-list'),
  settingsToggle: $('settings-toggle'),
  settingsBody: $('settings-body'),
  settingsChevron: $('settings-chevron'),
  settingBackend: $('setting-backend'),
  settingSensitivity: $('setting-sensitivity'),
  settingAutoblock: $('setting-autoblock'),
  btnSaveSettings: $('btn-save-settings'),
  btnWhitelist: $('btn-whitelist'),
  btnClipboard: $('btn-clipboard'),
  btnDashboard: $('btn-dashboard'),
  whitelistModal: $('whitelist-modal'),
  whitelistTextarea: $('whitelist-textarea'),
  whitelistSave: $('whitelist-save'),
  whitelistCancel: $('whitelist-cancel'),
  whitelistClose: $('whitelist-close'),
};

// ── Helpers ────────────────────────────────────────────────────────────────
function getBackendUrl() {
  return new Promise(resolve => {
    chrome.storage.local.get(['backendUrl'], d => {
      resolve((d.backendUrl || DEFAULT_BACKEND).replace(/\/$/, ''));
    });
  });
}

function verdictColor(v) {
  return { SAFE: '#16a34a', SUSPICIOUS: '#d97706', DANGEROUS: '#dc2626' }[v] || '#6b7280';
}

function setScoreRing(score, verdict) {
  const filled = Math.min(100, Math.max(0, score));
  const dash = (filled / 100) * CIRC;
  dom.scoreRing.setAttribute('stroke-dasharray', `${dash} ${CIRC}`);
  const col = verdictColor(verdict);
  dom.scoreRing.style.stroke = col;
  dom.scoreNum.style.fill = col;
  dom.scoreNum.textContent = score;
}

function setVerdict(verdict, score, summary, redFlags, lastScanId) {
  // hide pulse, show result
  dom.scanPulse.style.display = 'none';

  dom.verdictBadge.textContent = verdict || 'UNKNOWN';
  dom.verdictBadge.className = `verdict-badge ${verdict || 'UNKNOWN'}`;

  setScoreRing(score || 0, verdict);

  dom.summary.textContent = summary || (verdict === 'SAFE' ? 'No threats detected on this page.' :
    verdict === 'SUSPICIOUS' ? 'This page looks suspicious. Be cautious.' :
    verdict === 'DANGEROUS' ? 'Phishing site detected! Do not enter any information.' :
    'Scan this page to check for threats.');

  // Red flags
  if (redFlags && redFlags.length && verdict !== 'SAFE') {
    dom.flagsPreview.style.display = 'block';
    dom.flagsPreview.innerHTML = redFlags.slice(0, 3).map(f => {
      const text = typeof f === 'string' ? f : (f.description || f.flag || JSON.stringify(f));
      return `<div class="flag-item">${text.slice(0, 80)}</div>`;
    }).join('');
  } else {
    dom.flagsPreview.style.display = 'none';
  }

  // View report button
  if (lastScanId) {
    dom.btnViewDetails.style.display = 'inline-flex';
    dom.btnViewDetails.onclick = () => {
      chrome.tabs.create({ url: `https://phishingo-zk3c.vercel.app/analyze/${lastScanId}` });
    };
  } else {
    dom.btnViewDetails.style.display = 'none';
  }
}

function showScanning() {
  dom.scanPulse.style.display = 'flex';
  dom.verdictBadge.textContent = 'SCANNING';
  dom.verdictBadge.className = 'verdict-badge SCANNING';
  dom.scoreNum.textContent = '?';
  dom.scoreRing.setAttribute('stroke-dasharray', `0 ${CIRC}`);
  dom.scoreRing.style.stroke = '#1a56db';
  dom.summary.textContent = 'Analyzing this page...';
  dom.flagsPreview.style.display = 'none';
  dom.btnViewDetails.style.display = 'none';
}

async function loadStats() {
  chrome.storage.local.get(['sitesBlocked', 'linksScanned', 'passwordsProtected', 'phishesCaught'], d => {
    dom.statBlocked.textContent = d.sitesBlocked || 0;
    dom.statLinks.textContent = d.linksScanned || 0;
    dom.statPasswords.textContent = d.passwordsProtected || 0;
    const phishes = d.phishesCaught || 0;
    dom.statPhishes.textContent = phishes;
    if (phishes > 0) dom.statPhishes.classList.add('danger');
  });
}

async function loadActivity() {
  chrome.storage.local.get(['recentThreats', 'recent_threats'], d => {
    const threats = d.recentThreats || d.recent_threats || [];
    if (threats.length === 0) { dom.activitySection.style.display = 'none'; return; }
    dom.activitySection.style.display = 'block';
    dom.activityList.innerHTML = threats.slice(0, 4).map(t => `
      <div class="activity-item">
        <span class="activity-verdict ${t.verdict}">${t.verdict}</span>
        <span class="activity-domain">${t.domain || t.url || 'unknown'}</span>
        <span class="activity-time">${t.time || 'recent'}</span>
      </div>
    `).join('');
  });
}

async function checkHealth() {
  try {
    const base = await getBackendUrl();
    const res = await fetch(`${base}/api/health`, { signal: AbortSignal.timeout(4000) });
    if (res.ok) {
      const data = await res.json();
      dom.statusDot.className = 'status-dot online';
      dom.statusLabel.textContent = 'Online';

      // Engine status — use LLM model results if available
      const models = data.models || {};
      const engines = [
        { id: 'eng-qwen', keys: ['qwen3-32b', 'qwen'] },
        { id: 'eng-kimi', keys: ['kimi-k2', 'kimi'] },
        { id: 'eng-ds',   keys: ['deepseek-r1', 'deepseek'] },
        { id: 'eng-gem',  keys: ['gemini-2.5-flash', 'gemini'] },
        { id: 'eng-gpt',  keys: ['gpt-oss-120b', 'gpt'] },
      ];
      let okCount = 0;
      engines.forEach(e => {
        const el = $(e.id);
        const ok = e.keys.some(k => {
          const found = Object.keys(models).find(mk => mk.toLowerCase().includes(k));
          return found && models[found] === 'ok';
        });
        // If no model info, mark all green if backend is up
        const alive = ok || Object.keys(models).length === 0;
        if (alive) okCount++;
        el.className = `eng-dot ${alive ? 'ok' : 'err'}`;
      });
      dom.engineNote.textContent = `${okCount}/5 active`;
    } else {
      throw new Error('not ok');
    }
  } catch {
    dom.statusDot.className = 'status-dot offline';
    dom.statusLabel.textContent = 'Offline';
    dom.engineNote.textContent = 'unreachable';
    ['eng-qwen','eng-kimi','eng-ds','eng-gem','eng-gpt'].forEach(id => {
      const el = $(id);
      if (el) el.className = 'eng-dot';
    });
  }
}

async function loadCurrentTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) {
      setVerdict('UNKNOWN', 0, 'No active tab detected.');
      return;
    }

    // Extract and display domain
    let domain = 'Unknown';
    try { domain = new URL(tab.url).hostname; } catch {}
    dom.domain.textContent = domain;

    // Skip internal pages
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') ||
        tab.url.startsWith('about:') || tab.url.startsWith('edge://')) {
      setVerdict('UNKNOWN', 0, 'Cannot scan browser internal pages.');
      return;
    }

    // Try to get cached result from background
    chrome.runtime.sendMessage({ action: 'getTabResult', tabId: tab.id }, (cached) => {
      if (chrome.runtime.lastError) {
        // Service worker not ready, trigger scan directly
        triggerLiveScan(tab.url, tab.id);
        return;
      }
      if (cached && cached.verdict && cached.verdict !== 'UNKNOWN') {
        displayResult(cached);
      } else {
        // No cached result, trigger live scan
        triggerLiveScan(tab.url, tab.id);
      }
    });
  } catch (err) {
    console.error('[PhishFilter] Popup loadCurrentTab error:', err);
    setVerdict('UNKNOWN', 0, 'Error loading tab info.');
  }
}

function triggerLiveScan(url, tabId) {
  showScanning();
  // Timeout safety: if no response in 12s, fall back to direct scan
  let resolved = false;
  const timer = setTimeout(() => {
    if (!resolved) {
      resolved = true;
      directApiScan(url);
    }
  }, 12000);

  chrome.runtime.sendMessage({ action: 'scanTabUrl', url, tabId }, (result) => {
    clearTimeout(timer);
    if (resolved) return; // already timed out
    resolved = true;
    if (chrome.runtime.lastError || !result) {
      directApiScan(url);
      return;
    }
    if (result.offline) {
      setVerdict('UNKNOWN', 0, 'Backend offline. Check your connection.');
    } else {
      displayResult(result);
    }
  });
}

async function directApiScan(url) {
  try {
    const base = await getBackendUrl();
    const res = await fetch(`${base}/api/url-quick`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(8000),
    });
    if (res.ok) {
      const data = await res.json();
      displayResult(data);
    } else {
      setVerdict('UNKNOWN', 0, 'Scan failed. Try again.');
    }
  } catch {
    setVerdict('UNKNOWN', 0, 'Cannot reach backend. Check settings.');
  }
}

function displayResult(r) {
  const v = r.verdict || 'UNKNOWN';
  const score = r.risk_score || 0;
  const summary = r.summary || r.brand_impersonated
    ? `${v === 'SAFE' ? 'No threats' : 'Threat detected'}: ${r.brand_impersonated || ''} — risk ${score}/100`
    : null;
  const flags = r.red_flags || [];
  setVerdict(v, score, summary, flags, r.job_id);
}

// ── Settings ───────────────────────────────────────────────────────────────
function loadSettings() {
  chrome.storage.local.get(['backendUrl', 'sensitivity', 'autoblock'], d => {
    dom.settingBackend.value = d.backendUrl || DEFAULT_BACKEND;
    dom.settingSensitivity.value = d.sensitivity || 'medium';
    dom.settingAutoblock.checked = d.autoblock !== false;
  });
}

dom.settingsToggle.addEventListener('click', () => {
  const open = dom.settingsBody.style.display !== 'none';
  dom.settingsBody.style.display = open ? 'none' : 'block';
  dom.settingsChevron.style.transform = open ? '' : 'rotate(180deg)';
});

dom.btnSaveSettings.addEventListener('click', () => {
  chrome.storage.local.set({
    backendUrl: dom.settingBackend.value.trim() || DEFAULT_BACKEND,
    sensitivity: dom.settingSensitivity.value,
    autoblock: dom.settingAutoblock.checked,
  }, () => {
    dom.btnSaveSettings.textContent = 'Saved ✓';
    setTimeout(() => { dom.btnSaveSettings.textContent = 'Save'; }, 1500);
  });
});

// ── Whitelist ──────────────────────────────────────────────────────────────
dom.btnWhitelist.addEventListener('click', () => {
  chrome.storage.local.get(['whitelist'], d => {
    dom.whitelistTextarea.value = (d.whitelist || []).join('\n');
    dom.whitelistModal.style.display = 'flex';
  });
});
function closeWhitelist() { dom.whitelistModal.style.display = 'none'; }
dom.whitelistClose.addEventListener('click', closeWhitelist);
dom.whitelistCancel.addEventListener('click', closeWhitelist);
dom.whitelistSave.addEventListener('click', () => {
  const list = dom.whitelistTextarea.value.split('\n').map(s => s.trim()).filter(Boolean);
  chrome.storage.local.set({ whitelist: list }, () => { closeWhitelist(); });
});

// ── Scan page button ───────────────────────────────────────────────────────
dom.btnScanPage.addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) return;

  // Restricted pages where content scripts can't run
  const restricted = !tab.url || /^(chrome|edge|brave|about|chrome-extension|file):/i.test(tab.url);
  if (restricted) {
    chrome.tabs.create({ url: `https://phishingo-zk3c.vercel.app/?url=${encodeURIComponent(tab.url || '')}` });
    return;
  }

  // Try sending message — if content script isn't loaded, force-inject and retry
  const trySend = () => new Promise(resolve => {
    chrome.tabs.sendMessage(tab.id, { action: 'startPageScan' }, () => {
      resolve(!chrome.runtime.lastError);
    });
  });

  let ok = await trySend();
  if (!ok) {
    try {
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content/universal.js'] });
      await new Promise(r => setTimeout(r, 100));
      ok = await trySend();
    } catch { /* injection failed, restricted page */ }
  }

  // Close popup so the side panel is visible on the page
  window.close();
});

// ── Clipboard scan ─────────────────────────────────────────────────────────
dom.btnClipboard.addEventListener('click', async () => {
  try {
    // Request clipboard from active tab via content script
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    chrome.tabs.sendMessage(tab.id, { action: 'getClipboard' }, async (text) => {
      if (chrome.runtime.lastError || !text) {
        alert('Could not read clipboard. Try clicking inside the page first.');
        return;
      }
      // Check if it looks like a URL
      let url = text.trim();
      if (!url.startsWith('http')) url = 'https://' + url;
      try { new URL(url); } catch { alert('No URL found in clipboard.'); return; }

      dom.btnClipboard.textContent = 'Scanning...';
      const base = await getBackendUrl();
      const res = await fetch(`${base}/api/url-quick`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
        signal: AbortSignal.timeout(8000),
      });
      const data = await res.json();
      const v = data.verdict || 'UNKNOWN';
      alert(`Clipboard URL: ${url}\n\nVerdict: ${v}\nRisk score: ${data.risk_score || 0}/100\n${data.brand_impersonated ? `Brand: ${data.brand_impersonated}` : ''}`);
      dom.btnClipboard.textContent = 'Scan from clipboard';
    });
  } catch (err) {
    console.error('[PhishFilter] Clipboard scan error:', err);
  }
});

// ── Dashboard ──────────────────────────────────────────────────────────────
dom.btnDashboard.addEventListener('click', () => {
  chrome.tabs.create({ url: 'https://phishingo-zk3c.vercel.app' });
});

// ── Init ───────────────────────────────────────────────────────────────────
(async () => {
  showScanning();
  loadSettings();
  loadStats();
  loadActivity();
  checkHealth();
  loadCurrentTab();
})();
