import { checkUrlQuick, analyzeFull, analyzePage, getHealth } from './lib/api.js';
import { cache, QUICK_TTL } from './lib/cache.js';
import { isWhitelisted, extractDomain } from './lib/whitelist.js';
import { incrementStat } from './lib/storage.js';
import { C } from './lib/constants.js';

const log = (...a) => console.log(C.LOG_PREFIX, ...a);

let failCount = 0;
let offline   = false;

// ── Install ──────────────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: 'scan-page',  title: 'PhishFilter: Scan this entire page', contexts: ['page'] });
    chrome.contextMenus.create({ id: 'scan-link',  title: 'PhishFilter: Scan this link',        contexts: ['link'] });
    chrome.contextMenus.create({ id: 'scan-text',  title: 'PhishFilter: Scan selected text',    contexts: ['selection'] });
    chrome.contextMenus.create({ id: 'scan-image', title: 'PhishFilter: Scan this image',       contexts: ['image'] });
  });
  chrome.alarms.create('healthCheck', { periodInMinutes: 5 });
  log('Installed — service worker ready');
});

// ── Context menus ────────────────────────────────────────────────────────────
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab?.id) return;
  try {
    if (info.menuItemId === 'scan-link' && info.linkUrl) {
      const result = await doQuickCheck(info.linkUrl);
      safeSend(tab.id, { action: 'showScanResult', result, url: info.linkUrl });
    } else if (info.menuItemId === 'scan-text' && info.selectionText) {
      const result = await doFullAnalysis(info.selectionText, 'text');
      safeSend(tab.id, { action: 'showScanResult', result, text: info.selectionText });
    } else if (info.menuItemId === 'scan-page') {
      safeSend(tab.id, { action: 'extractPageData' });
    } else if (info.menuItemId === 'scan-image' && info.srcUrl) {
      const result = await doQuickCheck(info.srcUrl);
      safeSend(tab.id, { action: 'showScanResult', result, url: info.srcUrl });
    }
  } catch (e) { log('Context menu error:', e); }
});

// ── Tab guard ────────────────────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  const url = tab.url || '';
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) return;

  try {
    if (await isWhitelisted(url)) return;

    const result = await doQuickCheck(url);
    if (!result || result.offline) return;

    // Store for popup
    await chrome.storage.session.set({ [`tab_${tabId}`]: { ...result, url, checkedAt: Date.now() } });

    const { autoBlock = true } = await chrome.storage.local.get('autoBlock');

    if (result.verdict === C.DANGEROUS && autoBlock) {
      await incrementStat('sitesBlocked');
      await incrementStat('phishesCaught');
      safeSend(tabId, { action: 'showBlockPage', result });
      chrome.action.setBadgeText({ tabId, text: result.risk_score.toString() });
      chrome.action.setBadgeBackgroundColor({ tabId, color: C.COLOR_DANGER });
    } else if (result.verdict === C.SUSPICIOUS) {
      safeSend(tabId, { action: 'showSuspiciousBanner', result });
      chrome.action.setBadgeText({ tabId, text: result.risk_score.toString() });
      chrome.action.setBadgeBackgroundColor({ tabId, color: C.COLOR_WARNING });
    } else {
      chrome.action.setBadgeText({ tabId, text: '' });
    }
  } catch (e) { log('Tab guard error:', e); }
});

// ── Message handler ──────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handleMessage(msg, sender)
    .then(sendResponse)
    .catch(err => { log('Message error:', err); sendResponse({ error: err.message }); });
  return true; // keep channel open for async response
});

async function handleMessage(msg, sender) {
  switch (msg.action) {

    case 'checkUrl':
      return doQuickCheck(msg.url);

    case 'analyzeContent':
      return doFullAnalysis(msg.content, msg.inputType || 'text');

    case 'analyzePage': {
      const r = await analyzePage(msg.pageData);
      await incrementStat('linksScanned');
      return r;
    }

    case 'getTabResult': {
      const tabId = sender.tab?.id;
      if (!tabId) return null;
      const d = await chrome.storage.session.get(`tab_${tabId}`);
      return d[`tab_${tabId}`] || null;
    }

    case 'getHealth':
      return getHealth();

    case 'openApp': {
      const url = msg.jobId
        ? `${C.PRODUCTION_APP}/analyze/${msg.jobId}`
        : C.PRODUCTION_APP;
      await chrome.tabs.create({ url });
      return null;
    }

    case 'passwordBlocked':
      await incrementStat('passwordsProtected');
      return null;

    case 'clipboardUrl':
      return handleClipboard(msg.url);

    case 'getOfflineStatus':
      return { offline };

    default:
      return null;
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────
async function doQuickCheck(url) {
  const key = `q_${url}`;
  const hit = await cache.get(key);
  if (hit) return { ...hit, cached: true };

  try {
    const r = await checkUrlQuick(url);
    await cache.set(key, r, QUICK_TTL);
    failCount = 0; offline = false;
    await incrementStat('linksScanned');
    return r;
  } catch (e) {
    if (++failCount >= 3) { offline = true; await chrome.storage.local.set({ backendStatus: 'offline' }); }
    return { verdict: 'UNKNOWN', risk_score: 0, offline };
  }
}

async function doFullAnalysis(content, type) {
  try {
    const r = await analyzeFull(content, type);
    failCount = 0; offline = false;
    return r;
  } catch (e) {
    if (++failCount >= 3) offline = true;
    throw e;
  }
}

async function handleClipboard(url) {
  const result = await doQuickCheck(url);
  if ((result.risk_score || 0) >= 50) {
    const domain = extractDomain(url);
    try {
      chrome.notifications.create(`clip_${Date.now()}`, {
        type:     'basic',
        iconUrl:  'assets/icons/128.png',
        title:    C.MSG.CLIPBOARD_TITLE,
        message:  C.MSG.CLIPBOARD_BODY(domain, result.risk_score),
        buttons:  [{ title: 'View report' }, { title: 'Ignore' }],
        priority: 1,
      });
    } catch (e) { log('Notification error:', e); }
  }
  return result;
}

function safeSend(tabId, msg) {
  chrome.tabs.sendMessage(tabId, msg).catch(() => { /* tab may not have content script */ });
}

// ── Periodic health check ────────────────────────────────────────────────────
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'healthCheck') {
    const health = await getHealth();
    const status = health ? 'online' : 'offline';
    await chrome.storage.local.set({ backendStatus: status, lastHealthCheck: Date.now() });
    offline = !health;
    if (health) failCount = 0;
    log('Health check:', status);
  }
});

log('Service worker initialized');
