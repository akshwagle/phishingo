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
  dom.scanPulse.style.display = 'none';

  dom.verdictBadge.textContent = verdict || 'UNKNOWN';
  dom.verdictBadge.className = `badge ${verdict || 'UNKNOWN'}`;

  setScoreRing(score || 0, verdict);

  dom.summary.textContent = summary || (verdict === 'SAFE' ? 'No threats detected on this page.' :
    verdict === 'SUSPICIOUS' ? 'This page looks suspicious. Be cautious.' :
    verdict === 'DANGEROUS' ? 'Phishing site detected — do not enter any info.' :
    'Click "Scan this page" to run a full forensic scan.');

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
  dom.verdictBadge.className = 'badge SCANNING';
  dom.scoreNum.textContent = '·';
  dom.scoreRing.setAttribute('stroke-dasharray', `0 ${CIRC}`);
  dom.scoreRing.style.stroke = '#1a56db';
  dom.summary.textContent = 'Analyzing this page…';
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
    @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&display=swap');
    *{box-sizing:border-box;margin:0;padding:0;font-family:'Space Mono',ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;line-height:1.5}
    .panel{background:#fff;border-left:1px solid #1a1a1a;height:100vh;display:flex;flex-direction:column;
           box-shadow:-3px 0 0 #1a1a1a;animation:slide .22s ease;color:#1a1a1a}
    @keyframes slide{from{transform:translateX(380px)}to{transform:translateX(0)}}
    .hdr{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;
         border-bottom:1px solid #e8e8e3;background:#fff;flex-shrink:0}
    .hdr-left{display:flex;align-items:center;gap:9px;font-weight:700;font-size:13px}
    .shield{width:26px;height:26px;border-radius:7px;background:#1a56db;
            display:flex;align-items:center;justify-content:center;color:#fff;flex-shrink:0}
    .shield svg{width:13px;height:13px;stroke:#fff;fill:none;stroke-width:2.5;stroke-linecap:round;stroke-linejoin:round}
    .blue{color:#1a56db}
    .close{background:none;border:none;font-size:16px;cursor:pointer;color:#9ca3af;line-height:1;padding:4px;font-family:inherit}
    .close:hover{color:#1a1a1a}
    .body{flex:1;overflow-y:auto;padding:14px}
    .body.center{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;padding:24px}
    .verdict-card{border:1px solid #1a1a1a;border-radius:12px;padding:14px;margin-bottom:14px;box-shadow:3px 3px 0 #1a1a1a}
    .v-label{font-size:9px;color:#9ca3af;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px}
    .v-badge{display:inline-block;padding:3px 9px;border-radius:5px;font-weight:700;font-size:11px;margin-bottom:6px;border:1.5px solid currentColor;letter-spacing:.4px}
    .score-big{font-size:26px;font-weight:700;margin:2px 0 0}
    .score-big small{font-size:13px;color:#9ca3af;font-weight:400;margin-left:2px}
    .section{margin-bottom:14px}
    .sec-title{font-weight:700;color:#5a5a5a;margin-bottom:7px;font-size:9px;text-transform:uppercase;letter-spacing:.5px}
    .item{background:#fafaf7;border:1px solid #e8e8e3;border-radius:7px;padding:7px 10px;margin-bottom:5px;font-size:10px;color:#374151;word-break:break-all;line-height:1.4}
    .item.danger{border-color:#fca5a5;background:#fff5f5;color:#991b1b}
    .item.warn{border-color:#fde68a;background:#fffbeb;color:#92400e}
    .item .lead{display:inline-block;font-weight:700;margin-right:5px}
    .flag{display:flex;align-items:flex-start;gap:7px;margin-bottom:6px;font-size:11px;color:#374151;line-height:1.5}
    .flag::before{content:'▸';color:#dc2626;flex-shrink:0;font-weight:700}
    .footer{padding:12px 16px;border-top:1px solid #e8e8e3;background:#fafaf7;flex-shrink:0}
    .open-btn{display:block;width:100%;padding:10px;background:#1a56db;color:#fff;border:1.5px solid #1a1a1a;
              border-radius:8px;box-shadow:2px 2px 0 #1a1a1a;font-weight:700;cursor:pointer;text-align:center;
              font-family:inherit;font-size:11px}
    .open-btn:hover{background:#1447c0}
    .dots{display:flex;gap:6px}
    .dot{width:8px;height:8px;border-radius:50%;background:#1a56db;animation:pulse 1s infinite}
    .dot:nth-child(2){animation-delay:.2s}.dot:nth-child(3){animation-delay:.4s}
    @keyframes pulse{0%,100%{opacity:.4;transform:scale(1)}50%{opacity:1;transform:scale(1.3)}}
    .domain-line{font-size:10px;color:#9ca3af;word-break:break-all;margin-top:8px;text-transform:lowercase}
    .empty{text-align:center;padding:20px 0}
    .empty .check-icon{width:42px;height:42px;border-radius:12px;background:#f0fdf4;
                       border:1.5px solid #16a34a;display:inline-flex;align-items:center;justify-content:center;
                       color:#16a34a;margin-bottom:10px}
    .empty .check-icon svg{width:22px;height:22px}
    .empty-title{color:#16a34a;font-weight:700;font-size:13px}
    .empty-sub{color:#6b7280;font-size:11px;margin-top:4px}
  `;
  const styleEl = document.createElement('style');
  styleEl.textContent = css;
  shadow.appendChild(styleEl);

  const wrap = document.createElement('div');
  shadow.appendChild(wrap);

  const headerHtml = `
    <div class="hdr">
      <div class="hdr-left">
        <div class="shield"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
        <span>PhishFilter <span class="blue">Pro</span></span>
      </div>
      <button class="close" id="pfp-close">✕</button>
    </div>
  `;

  const renderLoading = () => {
    wrap.innerHTML = `
      <div class="panel">
        ${headerHtml}
        <div class="body center">
          <div class="dots"><span class="dot"></span><span class="dot"></span><span class="dot"></span></div>
          <div style="font-size:12px;color:#5a5a5a;text-align:center;line-height:1.6">
            Scanning entire page
            <div style="font-size:10px;color:#9ca3af;margin-top:4px">analyzing links, forms &amp; content</div>
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
        ${headerHtml}
        <div class="body">
          <div class="verdict-card" style="background:${bgColor}">
            <div class="v-label">Full page scan</div>
            <span class="v-badge" style="color:${vColor}">${verdict}</span>
            <div class="score-big" style="color:${vColor}">${score}<small>/100</small></div>
            ${summary ? `<div style="font-size:11px;color:#374151;margin-top:8px;line-height:1.5">${escHtml(summary)}</div>` : ''}
            <div class="domain-line">${escHtml(location.hostname)}</div>
          </div>

          <div class="section">
            <div class="sec-title">Scan summary</div>
            <div class="item"><span class="lead">Links</span>${linksTotal || 0} analyzed${dangerLinks.length + suspLinks.length > 0 ? ` · ${dangerLinks.length + suspLinks.length} flagged` : ''}</div>
            <div class="item"><span class="lead">Forms</span>${pwordFields > 0 ? `${pwordFields} sensitive field${pwordFields > 1 ? 's' : ''}` : 'no sensitive fields'}</div>
            <div class="item"><span class="lead">AI</span>${llmFlags.length > 0 ? `${llmFlags.length} red flag${llmFlags.length > 1 ? 's' : ''}` : 'no threats detected'}</div>
          </div>

          ${dangerLinks.length + suspLinks.length > 0 ? `
            <div class="section">
              <div class="sec-title">Flagged links · ${dangerLinks.length + suspLinks.length}</div>
              ${dangerLinks.slice(0,8).map(u => `<div class="item danger"><span class="lead">DANGER</span>${escHtml((u.url || u).slice(0,75))}</div>`).join('')}
              ${suspLinks.slice(0,8).map(u  => `<div class="item warn"><span class="lead">WARN</span>${escHtml((u.url || u).slice(0,75))}</div>`).join('')}
            </div>
          ` : ''}

          ${llmFlags.length > 0 ? `
            <div class="section">
              <div class="sec-title">AI red flags</div>
              ${llmFlags.slice(0,6).map(f => {
                const t = typeof f === 'string' ? f : (f.description || f.flag || '');
                return `<div class="flag">${escHtml(t)}</div>`;
              }).join('')}
            </div>
          ` : ''}

          ${threatCount === 0 ? `
            <div class="empty">
              <div class="check-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                  <polyline points="20 6 9 17 4 12"/>
                </svg>
              </div>
              <div class="empty-title">No threats detected</div>
              <div class="empty-sub">This page appears safe</div>
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
        ${headerHtml}
        <div class="body center">
          <div style="width:42px;height:42px;border-radius:12px;background:#fef2f2;border:1.5px solid #dc2626;display:flex;align-items:center;justify-content:center;color:#dc2626">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
          </div>
          <div style="font-size:13px;font-weight:700;color:#1a1a1a">Couldn't reach scanner</div>
          <div style="font-size:11px;color:#5a5a5a;text-align:center;line-height:1.5;max-width:280px">${escHtml(msg)}</div>
          <button id="pfp-retry" style="margin-top:6px;padding:8px 18px;background:#1a56db;color:#fff;border:1.5px solid #1a1a1a;border-radius:8px;box-shadow:2px 2px 0 #1a1a1a;font-family:inherit;font-size:11px;font-weight:700;cursor:pointer">Retry</button>
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

      const orig = dom.btnClipboard.innerHTML;
      dom.btnClipboard.textContent = 'Scanning…';
      const base = await getBackendUrl();
      try {
        const res = await fetch(`${base}/api/url-quick`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url }),
          signal: AbortSignal.timeout(8000),
        });
        const data = await res.json();
        const v = data.verdict || 'UNKNOWN';
        alert(`Clipboard URL: ${url}\n\nVerdict: ${v}\nRisk score: ${data.risk_score || 0}/100${data.brand_impersonated ? `\nBrand: ${data.brand_impersonated}` : ''}`);
      } finally {
        dom.btnClipboard.innerHTML = orig;
      }
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
