(function () {
  'use strict';
  const LOG = '[PhishFilter:Gmail]';
  const log = (...a) => console.log(LOG, ...a);

  const INJECTED_CLASS = 'pfp-gmail-btn-injected';
  let panelHost = null;

  // ── Watch for email opens ────────────────────────────────────────────────
  const observer = new MutationObserver(() => tryInjectButton());
  observer.observe(document.body, { childList: true, subtree: true });
  tryInjectButton();

  function tryInjectButton() {
    // Gmail email reading pane
    const toolbars = document.querySelectorAll('[data-thread-perm-id] [gh="mtb"]:not(.' + INJECTED_CLASS + ')');
    toolbars.forEach(toolbar => {
      toolbar.classList.add(INJECTED_CLASS);
      injectScanButton(toolbar);
    });
  }

  function injectScanButton(toolbar) {
    const btn = document.createElement('div');
    btn.setAttribute('role', 'button');
    btn.setAttribute('title', 'PhishFilter: Forensic scan this email');
    btn.style.cssText = `
      display:inline-flex; align-items:center; gap:5px; padding:4px 10px;
      margin:0 4px; border-radius:6px; border:1.5px solid #1a1a1a;
      background:#4f46e5; color:#fff; font-family:'Space Mono',monospace;
      font-size:11px; font-weight:700; cursor:pointer; box-shadow:2px 2px 0 #1a1a1a;
      user-select:none;
    `;
    btn.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      Scan
    `;
    btn.onclick = () => scanCurrentEmail();
    toolbar.insertBefore(btn, toolbar.firstChild);
    log('Button injected');
  }

  async function scanCurrentEmail() {
    const email = extractEmailContent();
    if (!email) { log('Could not extract email content'); return; }

    showLoadingPanel();

    chrome.runtime.sendMessage(
      { action: 'analyzeContent', content: email, inputType: 'email' },
      (result) => {
        if (chrome.runtime.lastError) { log('Analysis error:', chrome.runtime.lastError); return; }
        showResultPanel(result);
      }
    );
  }

  function extractEmailContent() {
    // Try to get email body from multiple Gmail DOM patterns
    const selectors = [
      '[data-message-id] .a3s.aiL',
      '.gs .ii.gt div',
      '.a3s',
      'div[dir="ltr"]',
    ];

    let body = '';
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el?.innerText?.trim()) { body = el.innerText.trim(); break; }
    }

    // Headers
    const from    = document.querySelector('[email][name]')?.getAttribute('email') || '';
    const subject = document.querySelector('h2[data-legacy-thread-id]')?.innerText
                 || document.querySelector('.hP')?.innerText || '';

    const links = [...document.querySelectorAll('.a3s a[href]')].map(a => a.href).filter(Boolean);

    return `From: ${from}\nSubject: ${subject}\n\n${body}\n\nLinks found:\n${links.join('\n')}`;
  }

  // ── Side panel ───────────────────────────────────────────────────────────
  function showLoadingPanel() {
    if (panelHost) panelHost.remove();
    panelHost = buildPanelHost(`
      <div class="body" style="display:flex;align-items:center;justify-content:center;flex:1;color:#5a5a5a">
        Analyzing email...
      </div>
    `);
  }

  function showResultPanel(result) {
    if (panelHost) panelHost.remove();
    const verdict = result?.verdict || 'UNKNOWN';
    const score   = result?.risk_score || 0;
    const vColor  = verdict === 'DANGEROUS' ? '#dc2626' : verdict === 'SUSPICIOUS' ? '#d97706' : '#16a34a';
    const summary = result?.summary || '';
    const flags   = result?.red_flags || [];
    const jobId   = result?.job_id;

    panelHost = buildPanelHost(`
      <div class="body">
        <div class="verdict-card" style="background:${vColor}11;border-color:${vColor}55">
          <div class="v-label">Email verdict</div>
          <span class="v-badge" style="background:${vColor}22;color:${vColor};border:1px solid ${vColor}55">${verdict}</span>
          <div style="font-size:22px;font-weight:700;color:${vColor}">${score}/100</div>
          ${summary ? `<p class="summary">${escHtml(summary)}</p>` : ''}
        </div>
        ${flags.length ? `
          <div class="section">
            <div class="sec-title">Red flags</div>
            ${flags.slice(0, 6).map(f => `
              <div class="flag-row">
                <span class="flag-dot"></span>
                <span>${escHtml(typeof f === 'string' ? f : f.description || '')}</span>
              </div>
            `).join('')}
          </div>
        ` : '<div class="safe-msg">No phishing signals detected.</div>'}
        <button class="open-btn" id="pfp-open-app">Open full forensic report</button>
      </div>
    `, jobId);
  }

  function buildPanelHost(bodyHtml, jobId) {
    const host = document.createElement('div');
    host.id = 'pfp-gmail-panel';
    Object.assign(host.style, {
      position: 'fixed', top: '0', right: '0', width: '360px', height: '100vh',
      zIndex: '2147483646', display: 'block',
    });
    const shadow = host.attachShadow({ mode: 'closed' });

    const style = document.createElement('style');
    style.textContent = `
      *{box-sizing:border-box;margin:0;padding:0;font-family:'Space Mono',monospace;font-size:12px}
      .panel{background:#fffefb;border-left:2px solid #1a1a1a;height:100vh;display:flex;flex-direction:column;box-shadow:-3px 0 0 #1a1a1a}
      .hdr{display:flex;align-items:center;justify-content:space-between;padding:12px 14px;border-bottom:2px solid #1a1a1a}
      .hdr-left{display:flex;align-items:center;gap:8px;font-weight:700;font-size:13px}
      .shield{width:26px;height:26px;background:#4f46e5;border:2px solid #1a1a1a;border-radius:8px;display:flex;align-items:center;justify-content:center}
      .shield svg{stroke:#fff;fill:none;stroke-width:2.5;width:12px;height:12px}
      .close{background:none;border:none;font-size:18px;cursor:pointer;color:#5a5a5a}
      .body{flex:1;overflow-y:auto;padding:14px}
      .verdict-card{border:2px solid #1a1a1a;border-radius:12px;padding:14px;margin-bottom:12px;box-shadow:2px 2px 0 #1a1a1a}
      .v-label{font-size:10px;color:#5a5a5a;margin-bottom:4px}
      .v-badge{display:inline-block;padding:2px 8px;border-radius:5px;font-weight:700;font-size:11px;margin-bottom:4px}
      .summary{font-size:11px;color:#5a5a5a;margin-top:8px;line-height:1.5}
      .section{margin-bottom:10px}
      .sec-title{font-weight:700;color:#1a1a1a;margin-bottom:6px;font-size:10px;text-transform:uppercase}
      .flag-row{display:flex;gap:6px;margin-bottom:4px;font-size:11px;color:#5a5a5a}
      .flag-dot{width:6px;height:6px;border-radius:50%;background:#dc2626;flex-shrink:0;margin-top:3px}
      .safe-msg{color:#16a34a;font-weight:700;text-align:center;padding:16px 0}
      .open-btn{display:block;width:100%;margin-top:12px;padding:10px;background:#4f46e5;color:#fff;
                border:2px solid #1a1a1a;border-radius:10px;box-shadow:2px 2px 0 #1a1a1a;
                font-weight:700;cursor:pointer;font-family:inherit;font-size:11px}
    `;
    shadow.appendChild(style);

    const panelEl = document.createElement('div');
    panelEl.className = 'panel';
    panelEl.innerHTML = `
      <div class="hdr">
        <div class="hdr-left">
          <div class="shield"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
          PhishFilter Pro
        </div>
        <button class="close" id="pfp-close">✕</button>
      </div>
      ${bodyHtml}
    `;
    shadow.appendChild(panelEl);

    const closeBtn = shadow.getElementById('pfp-close');
    if (closeBtn) closeBtn.onclick = () => { host.remove(); panelHost = null; };

    const openBtn = shadow.getElementById('pfp-open-app');
    if (openBtn) openBtn.onclick = () => chrome.runtime.sendMessage({ action: 'openApp', jobId });

    document.body.appendChild(host);
    return host;
  }

  function escHtml(str) {
    return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  log('Gmail content script loaded');
})();
