(function () {
  'use strict';
  if (window.__pfpOutlookLoaded) return;
  window.__pfpOutlookLoaded = true;

  const LOG = '[PhishFilter:Outlook]';
  const log  = (...a) => console.log(LOG, ...a);

  const scannedIds = new Set();
  const PROD_APP   = 'https://phishingo-zk3c.vercel.app';
  const BTN_CLASS  = 'pfp-outlook-btn';

  const $  = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];

  // ─────────────────────────────────────────────────────────────────────────────
  // Outlook DOM helpers — supports new Outlook + OWA
  // ─────────────────────────────────────────────────────────────────────────────
  function getEmailBodyEl() {
    for (const sel of [
      '[aria-label="Message body"]',
      '[data-app-section="ReadingPaneContent"] [contenteditable]',
      '.allowTextSelection',
      '.ReadingPaneContent',
      '[role="document"]',
      '[aria-label="Email message"]',
    ]) {
      const el = $(sel);
      if (el?.innerText?.trim()) return el;
    }
    return null;
  }

  function getSender() {
    for (const sel of [
      '[aria-label="From"] span[title]',
      '.ms-Persona-primaryText',
      '[title*="@"]',
      '.sender .text span',
    ]) {
      const el = $(sel);
      if (el) return el.getAttribute('title') || el.innerText || '';
    }
    return '';
  }

  function getSubject() {
    for (const sel of ['[role="heading"]', '.subject', '.ItemSubject', 'h1', 'h2']) {
      const el = $(sel);
      const text = el?.innerText?.trim();
      if (text && text.length < 200) return text;
    }
    return document.title || '';
  }

  function getEmailId() {
    // Use a combination of subject + sender as a stable ID for deduplication
    return `${getSubject()}::${getSender()}`.slice(0, 100);
  }

  function getToolbar() {
    for (const sel of [
      '[data-app-section="CommandBar"]',
      '[role="toolbar"][aria-label]',
      '.ms-CommandBar',
      '[aria-label="Message actions"]',
    ]) {
      const el = $(sel);
      if (el) return el;
    }
    return null;
  }

  function buildEmailContent() {
    const bodyEl = getEmailBodyEl();
    if (!bodyEl) return null;

    const body    = bodyEl.innerText.trim();
    const sender  = getSender();
    const subject = getSubject();
    const links   = $$('a[href]', bodyEl)
      .map(a => a.href)
      .filter(h => h && !h.startsWith('mailto:') && !h.startsWith('javascript:'));

    return [
      `From: ${sender}`,
      `Subject: ${subject}`,
      `\nBody:\n${body.slice(0, 4000)}`,
      links.length ? `\nLinks found:\n${links.slice(0, 30).join('\n')}` : '',
    ].join('');
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Inline verdict banner
  // ─────────────────────────────────────────────────────────────────────────────
  function removeBanner(bodyEl) {
    bodyEl?.parentElement?.querySelector('.pfp-ol-banner')?.remove();
  }

  function showLoadingBanner(bodyEl) {
    removeBanner(bodyEl);
    const div = document.createElement('div');
    div.className = 'pfp-ol-banner';
    div.style.cssText = bannerBase('#f5f0e8', '#9ca3af');
    div.innerHTML = `
      <span style="${mono()}font-size:12px;font-weight:700;color:#5a5a5a">PhishFilter is scanning this email...</span>
      <style>@keyframes pfpSpin{to{transform:rotate(360deg)}}</style>
    `;
    bodyEl.parentElement.insertBefore(div, bodyEl);
  }

  function showResultBanner(bodyEl, result) {
    removeBanner(bodyEl);
    const verdict  = result?.verdict || 'UNKNOWN';
    const score    = result?.risk_score ?? 0;
    const flags    = (result?.red_flags || []).slice(0, 4);
    const summary  = result?.summary || '';
    const jobId    = result?.job_id;

    const P = {
      DANGEROUS:  { bg: '#fff0f0', border: '#dc2626', text: '#7f1d1d', badge: '#dc2626', icon: '⛔' },
      SUSPICIOUS: { bg: '#fffbee', border: '#d97706', text: '#78350f', badge: '#d97706', icon: '⚠️' },
      SAFE:       { bg: '#f0fff6', border: '#16a34a', text: '#14532d', badge: '#16a34a', icon: '✅' },
      UNKNOWN:    { bg: '#f5f5f5', border: '#9ca3af', text: '#374151', badge: '#9ca3af', icon: '?' },
    }[verdict] || { bg: '#f5f5f5', border: '#9ca3af', text: '#374151', badge: '#9ca3af', icon: '?' };

    const div = document.createElement('div');
    div.className = 'pfp-ol-banner';
    div.style.cssText = bannerBase(P.bg, P.border);

    div.innerHTML = `
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px">
        <div style="flex:1">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap">
            <span style="${mono()}background:${P.badge};color:#fff;padding:3px 10px;border-radius:5px;font-size:11px;font-weight:700">
              ${P.icon} ${verdict}
            </span>
            <span style="${mono()}font-size:13px;font-weight:700;color:${P.text}">Risk score: ${score}/100</span>
          </div>
          ${summary ? `<div style="${mono()}font-size:11px;color:${P.text};line-height:1.6;margin-bottom:6px">${esc(summary)}</div>` : ''}
          ${flags.map(f => `
            <div style="${mono()}display:flex;gap:6px;font-size:10px;color:${P.text};margin-bottom:3px;line-height:1.5">
              <span style="color:${P.badge};font-weight:700">•</span>
              <span>${esc(typeof f === 'string' ? f : (f.description || ''))}</span>
            </div>
          `).join('')}
          ${jobId ? `
            <div style="margin-top:8px">
              <a href="${PROD_APP}/analyze/${jobId}" target="_blank"
                style="${mono()}color:${P.badge};font-size:10px;font-weight:700;text-decoration:underline">
                View full forensic report →
              </a>
            </div>
          ` : ''}
        </div>
        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;flex-shrink:0">
          <button class="pfp-dismiss" style="${mono()}background:none;border:none;cursor:pointer;color:#9ca3af;font-size:16px;line-height:1">✕</button>
          <button class="pfp-rescan" style="${mono()}background:none;border:1.5px solid ${P.border};color:${P.text};
            border-radius:6px;padding:3px 8px;font-size:10px;font-weight:700;cursor:pointer">Rescan</button>
        </div>
      </div>
    `;

    div.querySelector('.pfp-dismiss').onclick = () => div.remove();
    div.querySelector('.pfp-rescan').onclick  = () => { div.remove(); scanCurrentEmail(true); };

    bodyEl.parentElement.insertBefore(div, bodyEl);
  }

  function bannerBase(bg, border) {
    return `all:initial;display:block;margin:0 0 14px 0;padding:14px 16px;
      background:${bg};border:2px solid ${border};border-radius:12px;
      box-shadow:3px 3px 0 ${border}44;`;
  }
  function mono() { return "font-family:'Space Mono','Courier New',monospace;"; }
  function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

  // ─────────────────────────────────────────────────────────────────────────────
  // Scan button
  // ─────────────────────────────────────────────────────────────────────────────
  function injectButton(toolbar) {
    if (toolbar.querySelector(`.${BTN_CLASS}`)) return;
    const btn = document.createElement('button');
    btn.className = BTN_CLASS;
    btn.title = 'PhishFilter: Scan this email';
    btn.style.cssText = `
      all:initial;display:inline-flex;align-items:center;gap:5px;padding:5px 12px;
      margin:0 6px;border:2px solid #1a1a1a;border-radius:8px;background:#4f46e5;
      color:#fff;font-family:'Space Mono',monospace;font-size:11px;font-weight:700;
      cursor:pointer;box-shadow:2px 2px 0 #1a1a1a;
    `;
    btn.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      Scan email
    `;
    btn.addEventListener('click', () => scanCurrentEmail(true));
    try { toolbar.insertBefore(btn, toolbar.firstChild); }
    catch { toolbar.appendChild(btn); }
    log('Button injected');
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Core scan
  // ─────────────────────────────────────────────────────────────────────────────
  function scanCurrentEmail(manual = false) {
    const bodyEl = getEmailBodyEl();
    if (!bodyEl) { log('No body found'); return; }

    const content = buildEmailContent();
    if (!content?.trim()) { log('No content'); return; }

    log('Scanning', manual ? '(manual)' : '(auto)');
    showLoadingBanner(bodyEl);

    chrome.runtime.sendMessage(
      { action: 'analyzeContent', content, inputType: 'email' },
      (result) => {
        if (chrome.runtime.lastError) { log('Error:', chrome.runtime.lastError.message); removeBanner(bodyEl); return; }
        showResultBanner(bodyEl, result);
      }
    );
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Observer
  // ─────────────────────────────────────────────────────────────────────────────
  let debounceTimer = null;

  function onDomChange() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      const toolbar = getToolbar();
      if (toolbar) injectButton(toolbar);

      const id = getEmailId();
      if (!id || scannedIds.has(id)) return;
      const bodyEl = getEmailBodyEl();
      if (!bodyEl?.innerText?.trim()) return;

      scannedIds.add(id);
      scanCurrentEmail(false);
    }, 800);
  }

  const root = $('[role="main"]') || document.body;
  new MutationObserver(onDomChange).observe(root, { childList: true, subtree: true });
  setTimeout(onDomChange, 1500);

  log('Outlook content script loaded on', location.hostname);
})();
