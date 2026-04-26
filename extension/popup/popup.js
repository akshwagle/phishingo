import { getStats, getSettings, saveSettings, getWhitelist, addToWhitelist, removeFromWhitelist } from '../lib/storage.js';
import { C } from '../lib/constants.js';

const log = (...a) => console.log(C.LOG_PREFIX, '[popup]', ...a);

// ── Boot ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await Promise.all([
    loadCurrentTabStatus(),
    loadStats(),
    loadEngineStatus(),
    loadSettings(),
  ]);
  attachListeners();
  log('Popup ready');
});

// ── Current tab status ────────────────────────────────────────────────────────
async function loadCurrentTabStatus() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  const domain = tab.url ? (() => { try { return new URL(tab.url).hostname; } catch { return tab.url; } })() : '—';
  document.getElementById('page-domain').textContent = domain;

  // Ask background for the result it already computed for this tab
  chrome.runtime.sendMessage({ action: 'getTabResult' }, (result) => {
    if (chrome.runtime.lastError || !result) {
      setPageVerdict('UNKNOWN', null);
      return;
    }
    setPageVerdict(result.verdict, result.risk_score, result.brand_impersonated);
  });
}

function setPageVerdict(verdict, score, brand) {
  const badge  = document.getElementById('verdict-badge');
  const circle = document.getElementById('score-circle');
  const sumEl  = document.getElementById('page-summary');
  const numEl  = document.getElementById('score-num');

  const cls = verdict === 'DANGEROUS' ? 'dangerous' : verdict === 'SUSPICIOUS' ? 'suspicious' : verdict === 'SAFE' ? 'safe' : '';
  badge.textContent = verdict;
  badge.className   = `verdict-badge ${cls}`;
  circle.className  = `score-circle ${cls}`;
  numEl.textContent = score != null ? score : '?';

  sumEl.textContent =
    verdict === 'DANGEROUS'  ? `Phishing detected${brand ? ` — impersonates ${brand}` : ''}. Do not enter any info.` :
    verdict === 'SUSPICIOUS' ? `This site looks suspicious${brand ? ` — may impersonate ${brand}` : ''}. Be cautious.` :
    verdict === 'SAFE'       ? 'No threats detected on this page.' :
    'Analysis pending — click "Scan this page" to check now.';
}

// ── Stats ─────────────────────────────────────────────────────────────────────
async function loadStats() {
  const stats = await getStats();
  document.getElementById('stat-blocked').textContent   = stats.sitesBlocked;
  document.getElementById('stat-links').textContent     = stats.linksScanned;
  document.getElementById('stat-passwords').textContent = stats.passwordsProtected;
  document.getElementById('stat-phishes').textContent   = stats.phishesCaught;
}

// ── Engine status ──────────────────────────────────────────────────────────────
async function loadEngineStatus() {
  const statusEl   = document.getElementById('status-dot');
  const statusLabel = document.getElementById('status-label');

  const { backendStatus, lastHealthCheck } = await chrome.storage.local.get(['backendStatus', 'lastHealthCheck']);
  const isOnline = backendStatus === 'online'
    || (lastHealthCheck && Date.now() - lastHealthCheck < 6 * 60 * 1000);

  statusEl.className   = `status-dot ${isOnline ? 'online' : 'offline'}`;
  statusLabel.textContent = isOnline ? 'Online' : 'Offline';

  // Ping health now for freshness
  try {
    const health = await chrome.runtime.sendMessage({ action: 'getHealth' });
    if (health) {
      statusEl.className   = 'status-dot online';
      statusLabel.textContent = 'Online';
      // Activate all engine dots when backend is alive
      ['eng-qwen','eng-kimi','eng-ds','eng-gem','eng-gpt'].forEach(id => {
        const dot = document.getElementById(id);
        if (dot) dot.className = 'engine-dot active';
      });
    } else {
      statusEl.className   = 'status-dot offline';
      statusLabel.textContent = 'Offline';
    }
  } catch { /* ignore */ }
}

// ── Settings ──────────────────────────────────────────────────────────────────
async function loadSettings() {
  const s = await getSettings();
  document.getElementById('setting-backend').value       = s.backendUrl || '';
  document.getElementById('setting-sensitivity').value   = s.sensitivity;
  document.getElementById('setting-autoblock').checked   = s.autoBlock;
  document.getElementById('setting-sound').checked       = s.soundAlerts;
}

async function saveAllSettings() {
  await saveSettings({
    backendUrl:  document.getElementById('setting-backend').value.trim(),
    sensitivity: document.getElementById('setting-sensitivity').value,
    autoBlock:   document.getElementById('setting-autoblock').checked,
    soundAlerts: document.getElementById('setting-sound').checked,
  });
  const btn = document.getElementById('btn-save-settings');
  btn.textContent = 'Saved!';
  setTimeout(() => { btn.textContent = 'Save settings'; }, 1500);
}

// ── Whitelist modal ───────────────────────────────────────────────────────────
async function openWhitelistModal() {
  const list = await getWhitelist();
  document.getElementById('whitelist-textarea').value = list.join('\n');
  document.getElementById('whitelist-modal').style.display = 'flex';
}

async function saveWhitelist() {
  const raw  = document.getElementById('whitelist-textarea').value;
  const domains = raw.split('\n').map(d => d.trim().toLowerCase()).filter(Boolean);
  await chrome.storage.local.set({ whitelist: domains });
  document.getElementById('whitelist-modal').style.display = 'none';
}

// ── Listeners ─────────────────────────────────────────────────────────────────
function attachListeners() {
  // Settings toggle
  document.getElementById('settings-toggle').addEventListener('click', () => {
    const body = document.getElementById('settings-body');
    const chevron = document.getElementById('settings-chevron');
    const open = body.style.display !== 'none';
    body.style.display    = open ? 'none' : 'flex';
    chevron.style.transform = open ? '' : 'rotate(180deg)';
  });

  // Scan page
  document.getElementById('btn-scan-page').addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;
    chrome.tabs.sendMessage(tab.id, { action: 'extractPageData' });
    window.close();
  });

  // View details
  document.getElementById('btn-view-details').addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url   = tab?.url ? `${C.PRODUCTION_APP}/?scan=${encodeURIComponent(tab.url)}` : C.PRODUCTION_APP;
    chrome.tabs.create({ url });
    window.close();
  });

  // Clipboard scan
  document.getElementById('btn-clipboard').addEventListener('click', async () => {
    try {
      const text = await navigator.clipboard.readText();
      const match = text.match(/https?:\/\/[^\s]+/);
      if (match) {
        chrome.runtime.sendMessage({ action: 'checkUrl', url: match[0] }, (result) => {
          if (result) setPageVerdict(result.verdict, result.risk_score, result.brand_impersonated);
        });
      }
    } catch { /* clipboard permission denied */ }
  });

  // Open dashboard
  document.getElementById('btn-dashboard').addEventListener('click', () => {
    chrome.tabs.create({ url: C.PRODUCTION_APP });
    window.close();
  });

  // Save settings
  document.getElementById('btn-save-settings').addEventListener('click', saveAllSettings);

  // Whitelist
  document.getElementById('btn-whitelist').addEventListener('click', openWhitelistModal);
  document.getElementById('whitelist-close').addEventListener('click', () => {
    document.getElementById('whitelist-modal').style.display = 'none';
  });
  document.getElementById('whitelist-cancel').addEventListener('click', () => {
    document.getElementById('whitelist-modal').style.display = 'none';
  });
  document.getElementById('whitelist-save').addEventListener('click', saveWhitelist);
}
