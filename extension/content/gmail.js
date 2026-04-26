(function () {
  'use strict';
  if (window.__pfpGmailLoaded) return;
  window.__pfpGmailLoaded = true;

  const LOG = '[PhishFilter:Gmail]';
  const log  = (...a) => console.log(LOG, ...a);

  const scannedThreads = new Set(); // thread IDs we've already scanned this session
  const PROD_APP       = 'https://phishingo-zk3c.vercel.app';
  const BTN_CLASS      = 'pfp-scan-btn';

  // ─────────────────────────────────────────────────────────────────────────────
  // DOM helpers — Gmail changes its class names; we use multiple fallbacks
  // ─────────────────────────────────────────────────────────────────────────────
  const $  = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];

  function getThreadId() {
    // data-thread-perm-id is the most stable identifier
    const el = $('[data-thread-perm-id]') || $('[data-thread-id]') || $('[data-legacy-thread-id]');
    return el?.getAttribute('data-thread-perm-id')
        || el?.getAttribute('data-thread-id')
        || el?.getAttribute('data-legacy-thread-id')
        || null;
  }

  function getEmailBodyEl() {
    for (const sel of ['.a3s.aiL', '.ii.gt .a3s', '.a3s', '[data-message-id] .a3s']) {
      const el = $(sel);
      if (el?.innerText?.trim()) return el;
    }
    return null;
  }

  function getSender() {
    const el = $('.gD[email]') || $('[data-hovercard-id]') || $('[email]');
    return el?.getAttribute('email') || el?.getAttribute('data-hovercard-id') || '';
  }

  function getSubject() {
    return ($('h2.hP') || $('title'))?.innerText?.trim() || document.title || '';
  }

  function getReplyToolbar() {
    // Gmail toolbar that holds Reply / Forward / More — try multiple selectors
    for (const sel of ['.ade', '.hc .hl', '[data-tooltip="Reply"]', '[aria-label="Reply"]']) {
      const el = $(sel);
      if (el) return el.closest('[role="toolbar"]') || el.parentElement || el;
    }
    return null;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Build email content string to send to backend
  // ─────────────────────────────────────────────────────────────────────────────
  function buildEmailContent() {
    const bodyEl  = getEmailBodyEl();
    if (!bodyEl) return null;

    const body    = bodyEl.innerText.trim();
    const sender  = getSender();
    const subject = getSubject();
    const links   = $$('a[href]', bodyEl)
      .map(a => a.href)
      .filter(h => h && !h.startsWith('mailto:') && !h.startsWith('javascript:') && !h.startsWith('https://mail.google'));

    // Gather as many real headers as Gmail exposes in the UI
    const headerRows = $$('.ajz,.ajA,.ajy,.ajx', document);
    const headers = headerRows.map(r => r.innerText.trim()).filter(Boolean).join('\n');

    // Suspicious structural signals
    const hasPasswordField = $$('input[type="password"]', bodyEl).length > 0;
    const hasForms         = $$('form', bodyEl).length > 0;

    return [
      `From: ${sender}`,
      `Subject: ${subject}`,
      headers ? `\nHeaders:\n${headers}` : '',
      `\nBody:\n${body.slice(0, 4000)}`,
      links.length ? `\nLinks found:\n${links.slice(0, 30).join('\n')}` : '',
      hasPasswordField ? '\n[ALERT: email body contains password input fields — high risk]' : '',
      hasForms         ? '\n[ALERT: email body contains HTML form elements]' : '',
    ].join('');
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Inline verdict banner injected at the TOP of the email body
  // ─────────────────────────────────────────────────────────────────────────────
  function removeBanner(bodyEl) {
    bodyEl?.closest('.ii.gt, .adn.ads')?.querySelector('.pfp-banner')?.remove();
    bodyEl?.parentElement?.querySelector('.pfp-banner')?.remove();
  }

  function showLoadingBanner(bodyEl) {
    removeBanner(bodyEl);
    const parent = bodyEl.parentElement;
    const div = document.createElement('div');
    div.className = 'pfp-banner';
    div.style.cssText = bannerBaseStyle('#f5f0e8', '#9ca3af');
    div.innerHTML = `
      <div style="display:flex;align-items:center;gap:10px">
        <div class="pfp-spinner" style="width:14px;height:14px;border:2px solid #d1d5db;border-top-color:#4f46e5;border-radius:50%;animation:pfpSpin .7s linear infinite"></div>
        <span style="${monoStyle()}font-size:12px;font-weight:700;color:#5a5a5a">PhishFilter is scanning this email...</span>
      </div>
      <style>@keyframes pfpSpin{to{transform:rotate(360deg)}}</style>
    `;
    parent.insertBefore(div, bodyEl);
  }

  function showResultBanner(bodyEl, result) {
    removeBanner(bodyEl);
    const verdict  = result?.verdict || 'UNKNOWN';
    const score    = result?.risk_score ?? 0;
    const flags    = (result?.red_flags || []).slice(0, 4);
    const summary  = result?.summary || '';
    const jobId    = result?.job_id;
    const auth     = result?.authentication || {};

    const palettes = {
      DANGEROUS:  { bg: '#fff0f0', border: '#dc2626', text: '#7f1d1d', badge: '#dc2626', badgeText: '#fff', icon: '⛔' },
      SUSPICIOUS: { bg: '#fffbee', border: '#d97706', text: '#78350f', badge: '#d97706', badgeText: '#fff', icon: '⚠️' },
      SAFE:       { bg: '#f0fff6', border: '#16a34a', text: '#14532d', badge: '#16a34a', badgeText: '#fff', icon: '✅' },
      UNKNOWN:    { bg: '#f5f5f5', border: '#9ca3af', text: '#374151', badge: '#9ca3af', badgeText: '#fff', icon: '?' },
    };
    const p = palettes[verdict] || palettes.UNKNOWN;

    const authBadges = Object.entries({
      SPF: auth.spf, DKIM: auth.dkim, DMARC: auth.dmarc,
    }).map(([k, v]) => {
      if (!v || v === 'unknown') return '';
      const ok = v === 'pass';
      return `<span style="display:inline-block;padding:1px 6px;border-radius:4px;font-size:9px;font-weight:700;margin-right:4px;
        background:${ok ? '#f0fff6' : '#fff0f0'};color:${ok ? '#16a34a' : '#dc2626'};
        border:1px solid ${ok ? '#86efac' : '#fca5a5'};font-family:'Space Mono',monospace">${k} ${ok ? '✓' : '✗'}</span>`;
    }).join('');

    const parent = bodyEl.parentElement;
    const div = document.createElement('div');
    div.className = 'pfp-banner';
    div.style.cssText = bannerBaseStyle(p.bg, p.border);
    div.innerHTML = `
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px">
        <div style="flex:1">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px">
            <span style="${monoStyle()}background:${p.badge};color:${p.badgeText};padding:3px 10px;
              border-radius:5px;font-size:11px;font-weight:700">${p.icon} ${verdict}</span>
            <span style="${monoStyle()}font-size:13px;font-weight:700;color:${p.text}">Risk score: ${score}/100</span>
            ${authBadges ? `<span style="margin-left:4px">${authBadges}</span>` : ''}
          </div>
          ${summary ? `<div style="${monoStyle()}font-size:11px;color:${p.text};line-height:1.6;margin-bottom:6px">${escHtml(summary)}</div>` : ''}
          ${flags.length ? `
            <div style="margin-top:4px">
              ${flags.map(f => `
                <div style="${monoStyle()}display:flex;gap:6px;font-size:10px;color:${p.text};margin-bottom:2px;line-height:1.5">
                  <span style="color:${p.badge};font-weight:700;flex-shrink:0">•</span>
                  <span>${escHtml(typeof f === 'string' ? f : (f.description || JSON.stringify(f)))}</span>
                </div>
              `).join('')}
            </div>
          ` : ''}
          ${jobId ? `
            <div style="margin-top:8px">
              <a href="${PROD_APP}/analyze/${jobId}" target="_blank"
                 style="${monoStyle()}color:${p.badge};font-size:10px;font-weight:700;text-decoration:underline">
                View full forensic report (10 engines + 5 AI models) →
              </a>
            </div>
          ` : ''}
        </div>
        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;flex-shrink:0">
          <button class="pfp-dismiss" style="${monoStyle()}background:none;border:none;cursor:pointer;
            color:#9ca3af;font-size:16px;line-height:1;padding:0">✕</button>
          <button class="pfp-rescan" style="${monoStyle()}background:none;border:1.5px solid ${p.border};
            color:${p.text};border-radius:6px;padding:3px 8px;font-size:10px;font-weight:700;cursor:pointer">
            Rescan
          </button>
        </div>
      </div>
    `;

    div.querySelector('.pfp-dismiss').onclick  = () => div.remove();
    div.querySelector('.pfp-rescan').onclick   = () => {
      div.remove();
      scanCurrentEmail(true);
    };

    parent.insertBefore(div, bodyEl);
  }

  function bannerBaseStyle(bg, border) {
    return `all:initial;display:block;margin:0 0 14px 0;padding:14px 16px;
      background:${bg};border:2px solid ${border};border-radius:12px;
      box-shadow:3px 3px 0 ${border}44;`;
  }

  function monoStyle() {
    return "font-family:'Space Mono','Courier New',monospace;";
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Scan button injection into Gmail toolbar
  // ─────────────────────────────────────────────────────────────────────────────
  function injectScanButton(toolbar) {
    if (toolbar.querySelector(`.${BTN_CLASS}`)) return;
    const btn = document.createElement('button');
    btn.className = BTN_CLASS;
    btn.title = 'PhishFilter: Scan this email for phishing';
    btn.style.cssText = `
      all:initial;display:inline-flex;align-items:center;gap:5px;padding:5px 12px;
      margin:0 4px;border:2px solid #1a1a1a;border-radius:8px;background:#4f46e5;
      color:#fff;font-family:'Space Mono',monospace;font-size:11px;font-weight:700;
      cursor:pointer;box-shadow:2px 2px 0 #1a1a1a;line-height:1;
    `;
    btn.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      Scan email
    `;
    btn.addEventListener('click', () => scanCurrentEmail(true));
    try { toolbar.insertBefore(btn, toolbar.firstChild); }
    catch { toolbar.appendChild(btn); }
    log('Scan button injected');
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Core scan function
  // ─────────────────────────────────────────────────────────────────────────────
  function scanCurrentEmail(manual = false) {
    const bodyEl = getEmailBodyEl();
    if (!bodyEl) { log('No email body found'); return; }

    const content = buildEmailContent();
    if (!content?.trim()) { log('Could not extract email content'); return; }

    log('Scanning email', manual ? '(manual)' : '(auto)');
    showLoadingBanner(bodyEl);

    chrome.runtime.sendMessage(
      { action: 'analyzeContent', content, inputType: 'email' },
      (result) => {
        if (chrome.runtime.lastError) {
          log('Analysis error:', chrome.runtime.lastError.message);
          removeBanner(bodyEl);
          return;
        }
        showResultBanner(bodyEl, result);
        log('Scan complete:', result?.verdict, result?.risk_score);
      }
    );
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // MutationObserver — detect email opens and auto-scan
  // ─────────────────────────────────────────────────────────────────────────────
  let debounceTimer = null;

  function onDomChange() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(handleEmailView, 600);
  }

  function handleEmailView() {
    // Inject scan button into toolbar
    const toolbar = getReplyToolbar();
    if (toolbar && !toolbar.querySelector(`.${BTN_CLASS}`)) {
      injectScanButton(toolbar);
    }

    // Auto-scan if this is a new thread
    const threadId = getThreadId();
    if (!threadId || scannedThreads.has(threadId)) return;

    const bodyEl = getEmailBodyEl();
    if (!bodyEl?.innerText?.trim()) return;

    scannedThreads.add(threadId);
    log('Auto-scanning thread:', threadId);
    scanCurrentEmail(false);
  }

  // Start observing Gmail's main container
  function startObserver() {
    const root = $('[role="main"]') || $('.AO') || $('.bkK') || document.body;
    const obs  = new MutationObserver(onDomChange);
    obs.observe(root, { childList: true, subtree: true });
    log('Observer attached to', root.tagName, root.className?.slice(0, 30));
    // Run once immediately in case email is already open
    setTimeout(handleEmailView, 1000);
  }

  // Gmail's main panel may not exist on initial load — wait for it
  if ($('[role="main"]') || $('.AO')) {
    startObserver();
  } else {
    const bootstrap = new MutationObserver(() => {
      if ($('[role="main"]') || $('.AO')) {
        bootstrap.disconnect();
        startObserver();
      }
    });
    bootstrap.observe(document.body, { childList: true, subtree: true });
  }

  function escHtml(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  log('Gmail content script loaded on', location.hostname);
})();
