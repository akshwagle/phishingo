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
// Strategy: inject a self-contained side-panel renderer directly into the page.
// This bypasses the content script entirely so the side panel ALWAYS opens
// regardless of timing, CSP, or whether the content script was already loaded.
dom.btnScanPage.addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) return;

  // Restricted pages where we cannot inject scripts at all
  const restricted = !tab.url || /^(chrome|edge|brave|about|chrome-extension|moz-extension|file|view-source):/i.test(tab.url);
  if (restricted) {
    chrome.tabs.create({ url: `https://phishingo-zk3c.vercel.app/?url=${encodeURIComponent(tab.url || '')}` });
    return;
  }

  const backend = await getBackendUrl();

  try {
    await chrome.scripting.executeScript({
      target: { tabId: tab.id, allFrames: false },
      world:  'ISOLATED',
      args:   [backend, tab.url || location.href],
      func:   injectSidePanelAndScan,
    });
  } catch (err) {
    // Page won't allow injection (e.g. Chrome Web Store, some Google services)
    chrome.tabs.create({ url: `https://phishingo-zk3c.vercel.app/?url=${encodeURIComponent(tab.url || '')}` });
    return;
  }

  window.close();
});

/**
 * Self-contained side-panel renderer + scanner.
 * Runs in the page's isolated world so it can call chrome.runtime / fetch.
 * Uses Shadow DOM so site CSS can't break it and our CSS can't leak.
 */
function injectSidePanelAndScan(backendUrl, tabUrl) {
  const HOST_ID = 'pfp-panel-host';
  const escHtml = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  // Remove any existing panel
  document.getElementById(HOST_ID)?.remove();

  const host = document.createElement('div');
  host.id = HOST_ID;
  Object.assign(host.style, {
    all: 'initial', position: 'fixed', top: '0', right: '0',
    width: '380px', height: '100vh', zIndex: '2147483647', display: 'block',
  });
  const shadow = host.attachShadow({ mode: 'closed' });
  (document.documentElement || document.body || document).appendChild(host);

  const css = `
    *{box-sizing:border-box;margin:0;padding:0;font-family:'Space Mono',ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
    .panel{background:#fff;border-left:2px solid #111;height:100vh;display:flex;flex-direction:column;
           box-shadow:-4px 0 0 #111;animation:slide .2s ease;color:#111}
    @keyframes slide{from{transform:translateX(380px)}to{transform:translateX(0)}}
    .hdr{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;
         border-bottom:2px solid #111;background:#fff;flex-shrink:0}
    .hdr-left{display:flex;align-items:center;gap:8px;font-weight:700;font-size:13px}
    .shield{width:28px;height:28px;border-radius:8px;background:#1a56db;border:2px solid #111;
            display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:14px}
    .close{background:none;border:none;font-size:18px;cursor:pointer;color:#5a5a5a;line-height:1;padding:4px}
    .body{flex:1;overflow-y:auto;padding:14px}
    .body.center{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;padding:24px}
    .verdict-card{border:2px solid #111;border-radius:12px;padding:14px;margin-bottom:12px;box-shadow:3px 3px 0 #111}
    .v-label{font-size:10px;color:#5a5a5a;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px}
    .v-badge{display:inline-block;padding:3px 10px;border-radius:6px;font-weight:700;font-size:12px;margin-bottom:4px;border:1.5px solid currentColor}
    .score-big{font-size:28px;font-weight:700;margin:4px 0}
    .section{margin-bottom:14px}
    .sec-title{font-weight:700;color:#374151;margin-bottom:6px;font-size:10px;text-transform:uppercase;letter-spacing:.5px}
    .item{background:#f9fafb;border:1.5px solid #e5e7eb;border-radius:8px;padding:6px 10px;margin-bottom:4px;font-size:11px;color:#374151;word-break:break-all}
    .item.danger{border-color:#fca5a5;background:#fff1f1;color:#dc2626}
    .item.warn{border-color:#fde68a;background:#fffbee;color:#92400e}
    .flag{display:flex;align-items:flex-start;gap:6px;margin-bottom:5px;font-size:11px;color:#374151;line-height:1.4}
    .flag-dot{width:6px;height:6px;border-radius:50%;background:#dc2626;flex-shrink:0;margin-top:5px}
    .footer{padding:12px 16px;border-top:2px solid #111;background:#fff;flex-shrink:0}
    .open-btn{display:block;width:100%;padding:10px;background:#1a56db;color:#fff;border:2px solid #111;
              border-radius:8px;box-shadow:2px 2px 0 #111;font-weight:700;cursor:pointer;text-align:center;
              font-family:inherit;font-size:12px}
    .dot{width:10px;height:10px;border-radius:50%;background:#1a56db;animation:pulse 1s infinite;display:inline-block;margin:0 3px}
    .dot:nth-child(2){animation-delay:.2s}.dot:nth-child(3){animation-delay:.4s}
    @keyframes pulse{0%,100%{opacity:.4}50%{opacity:1}}
    .meta-row{display:flex;justify-content:space-between;font-size:10px;color:#5a5a5a;margin-top:8px}
    .domain-line{font-size:10px;color:#5a5a5a;word-break:break-all;margin-top:4px}
  `;
  const styleEl = document.createElement('style');
  styleEl.textContent = css;
  shadow.appendChild(styleEl);

  const wrap = document.createElement('div');
  shadow.appendChild(wrap);

  const renderLoading = () => {
    wrap.innerHTML = `
      <div class="panel">
        <div class="hdr">
          <div class="hdr-left"><div class="shield">P</div>PhishFilter Pro</div>
          <button class="close" id="pfp-close">✕</button>
        </div>
        <div class="body center">
          <div><span class="dot"></span><span class="dot"></span><span class="dot"></span></div>
          <div style="font-size:12px;color:#5a5a5a;text-align:center;line-height:1.6">
            Scanning entire page…<br>
            <span style="font-size:10px;color:#9ca3af">Analyzing all links, forms & content with AI</span>
          </div>
          <div class="domain-line">${escHtml(location.hostname)}</div>
        </div>
      </div>
    `;
    shadow.getElementById('pfp-close').onclick = () => host.remove();
  };

  const renderResult = (r) => {
    const verdict = r?.verdict || 'UNKNOWN';
    const score   = r?.risk_score ?? 0;
    const summary = r?.summary || r?.llm?.summary || '';
    const llmFlags = r?.llm?.red_flags || r?.red_flags || [];
    const links = r?.links || {};
    const dangerLinks = links.dangerous || [];
    const suspLinks   = links.suspicious || [];
    const linksTotal  = links.total ?? (dangerLinks.length + suspLinks.length + (links.safe?.length || 0));
    const pwordFields = r?.forms?.password_fields ?? 0;

    const vColor =
      verdict === 'DANGEROUS'  ? '#dc2626' :
      verdict === 'SUSPICIOUS' ? '#d97706' :
      verdict === 'SAFE'       ? '#16a34a' : '#6b7280';
    const bgColor =
      verdict === 'DANGEROUS'  ? '#fff1f1' :
      verdict === 'SUSPICIOUS' ? '#fffbee' :
      verdict === 'SAFE'       ? '#f0fff6' : '#f9fafb';

    const threatCount = dangerLinks.length + suspLinks.length + pwordFields + llmFlags.length;

    wrap.innerHTML = `
      <div class="panel">
        <div class="hdr">
          <div class="hdr-left"><div class="shield">P</div>PhishFilter Pro</div>
          <button class="close" id="pfp-close">✕</button>
        </div>
        <div class="body">
          <div class="verdict-card" style="background:${bgColor}">
            <div class="v-label">Full page scan result</div>
            <span class="v-badge" style="color:${vColor}">${verdict}</span>
            <div class="score-big" style="color:${vColor}">${score}<span style="font-size:13px;color:#6b7280">/100</span></div>
            ${summary ? `<div style="font-size:11px;color:#374151;margin-top:6px;line-height:1.5">${escHtml(summary)}</div>` : ''}
            <div class="domain-line">${escHtml(location.hostname)}</div>
          </div>

          <div class="section">
            <div class="sec-title">Scan summary</div>
            <div class="item">Links analyzed: ${linksTotal || 'all on page'}</div>
            <div class="item">Form fields: ${pwordFields > 0 ? `${pwordFields} sensitive` : 'none flagged'}</div>
            <div class="item">AI red flags: ${llmFlags.length}</div>
          </div>

          ${dangerLinks.length + suspLinks.length > 0 ? `
            <div class="section">
              <div class="sec-title">Suspicious links (${dangerLinks.length + suspLinks.length})</div>
              ${dangerLinks.slice(0,8).map(u => `<div class="item danger">⛔ ${escHtml((u.url || u).slice(0,80))}</div>`).join('')}
              ${suspLinks.slice(0,8).map(u  => `<div class="item warn">⚠ ${escHtml((u.url || u).slice(0,80))}</div>`).join('')}
            </div>
          ` : ''}

          ${llmFlags.length > 0 ? `
            <div class="section">
              <div class="sec-title">AI red flags</div>
              ${llmFlags.slice(0,6).map(f => {
                const t = typeof f === 'string' ? f : (f.description || f.flag || '');
                return `<div class="flag"><div class="flag-dot"></div><div>${escHtml(t)}</div></div>`;
              }).join('')}
            </div>
          ` : ''}

          ${threatCount === 0 ? `
            <div style="text-align:center;padding:24px 0">
              <div style="width:60px;height:60px;margin:0 auto 12px;border-radius:14px;background:#f0fff6;border:2px solid #16a34a;display:flex;align-items:center;justify-content:center;color:#16a34a;font-size:28px;font-weight:700">✓</div>
              <div style="color:#16a34a;font-weight:700;font-size:14px">No threats detected</div>
              <div style="color:#6b7280;font-size:11px;margin-top:6px">This page appears safe to use</div>
            </div>
          ` : ''}
        </div>
        <div class="footer">
          <button class="open-btn" id="pfp-open">Open full report ↗</button>
        </div>
      </div>
    `;
    shadow.getElementById('pfp-close').onclick = () => host.remove();
    shadow.getElementById('pfp-open').onclick  = () => {
      const id = r?.job_id;
      window.open(id ? `https://phishingo-zk3c.vercel.app/analyze/${id}` : 'https://phishingo-zk3c.vercel.app', '_blank');
    };
  };

  const renderError = (msg) => {
    wrap.innerHTML = `
      <div class="panel">
        <div class="hdr">
          <div class="hdr-left"><div class="shield">P</div>PhishFilter Pro</div>
          <button class="close" id="pfp-close">✕</button>
        </div>
        <div class="body center">
          <div style="width:48px;height:48px;border-radius:12px;background:#fef2f2;border:2px solid #dc2626;display:flex;align-items:center;justify-content:center;color:#dc2626;font-size:24px;font-weight:700">!</div>
          <div style="font-size:13px;font-weight:700;color:#1a1a1a">Couldn't reach scanner</div>
          <div style="font-size:11px;color:#5a5a5a;text-align:center;line-height:1.5">${escHtml(msg)}</div>
          <button id="pfp-retry" style="margin-top:8px;padding:8px 16px;background:#1a56db;color:#fff;border:2px solid #111;border-radius:8px;font-family:inherit;font-size:12px;font-weight:700;cursor:pointer">Retry</button>
        </div>
      </div>
    `;
    shadow.getElementById('pfp-close').onclick = () => host.remove();
    shadow.getElementById('pfp-retry').onclick = runScan;
  };

  // Extract and POST page data
  const runScan = async () => {
    renderLoading();

    const links = [...document.querySelectorAll('a[href]')]
      .map(a => a.href)
      .filter(h => h && !h.startsWith('#') && !h.startsWith('javascript:') && !h.startsWith('mailto:'));
    const forms = [...document.querySelectorAll('input')].slice(0, 50).map(i => ({
      type: i.type, name: i.name, placeholder: i.placeholder, id: i.id,
    }));
    const images = [...document.querySelectorAll('img[src]')].slice(0, 20).map(i => ({ src: i.src, alt: i.alt }));

    const payload = {
      url:    tabUrl || location.href,
      title:  (document.title || '').slice(0, 200),
      text:   (document.body?.innerText || document.documentElement?.innerText || '').slice(0, 5000),
      links:  [...new Set(links)].slice(0, 50),
      forms,
      images,
    };

    try {
      const ctrl = new AbortController();
      const timeoutId = setTimeout(() => ctrl.abort(), 30000);
      const res = await fetch(`${backendUrl.replace(/\/$/, '')}/api/page-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: ctrl.signal,
      });
      clearTimeout(timeoutId);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      renderResult(data);
    } catch (err) {
      renderError(err?.name === 'AbortError' ? 'Request timed out (30s)' : (err?.message || 'Network error'));
    }
  };

  runScan();
}

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
