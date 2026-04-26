(function () {
  'use strict';
  const LOG = '[PhishFilter:Outlook]';
  const log = (...a) => console.log(LOG, ...a);

  const INJECTED = 'pfp-outlook-injected';
  let panelHost  = null;

  const obs = new MutationObserver(() => tryInject());
  obs.observe(document.body, { childList: true, subtree: true });
  tryInject();

  function tryInject() {
    // Outlook reading pane toolbar (modern web)
    const toolbars = document.querySelectorAll(
      '[data-app-section="MailCompose"] [role="toolbar"]:not(.' + INJECTED + '),' +
      '.ms-CommandBar-primaryCommand:not(.' + INJECTED + '),' +
      '[aria-label="Message actions"]:not(.' + INJECTED + ')'
    );
    toolbars.forEach(tb => {
      tb.classList.add(INJECTED);
      injectButton(tb);
    });
  }

  function injectButton(toolbar) {
    const btn = document.createElement('button');
    btn.setAttribute('title', 'PhishFilter: Scan this email');
    btn.style.cssText = `
      display:inline-flex; align-items:center; gap:5px; padding:4px 10px; margin:0 4px;
      border:1.5px solid #1a1a1a; border-radius:6px; background:#4f46e5; color:#fff;
      font-family:'Space Mono',monospace; font-size:11px; font-weight:700;
      cursor:pointer; box-shadow:2px 2px 0 #1a1a1a;
    `;
    btn.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      Scan
    `;
    btn.onclick = () => scanCurrentEmail();
    toolbar.appendChild(btn);
    log('Button injected into Outlook toolbar');
  }

  async function scanCurrentEmail() {
    const content = extractEmailContent();
    if (!content) { log('Could not extract email'); return; }

    showPanel(`
      <div class="body" style="display:flex;align-items:center;justify-content:center;flex:1;color:#5a5a5a">
        Analyzing email...
      </div>
    `);

    chrome.runtime.sendMessage(
      { action: 'analyzeContent', content, inputType: 'email' },
      (result) => {
        if (chrome.runtime.lastError) { log('Error:', chrome.runtime.lastError); return; }
        const verdict = result?.verdict || 'UNKNOWN';
        const score   = result?.risk_score || 0;
        const vColor  = verdict === 'DANGEROUS' ? '#dc2626' : verdict === 'SUSPICIOUS' ? '#d97706' : '#16a34a';
        const flags   = result?.red_flags || [];
        const jobId   = result?.job_id;

        showPanel(`
          <div class="body">
            <div class="vcard" style="background:${vColor}11;border-color:${vColor}55">
              <div style="font-size:10px;color:#5a5a5a;margin-bottom:4px">Email verdict</div>
              <span class="badge" style="background:${vColor}22;color:${vColor};border:1px solid ${vColor}55">${verdict}</span>
              <div style="font-size:22px;font-weight:700;color:${vColor};margin-top:4px">${score}/100</div>
            </div>
            ${flags.length ? `
              <div class="sec-title">Red flags</div>
              ${flags.slice(0, 5).map(f => `
                <div class="flag"><span class="dot"></span><span>${escHtml(typeof f === 'string' ? f : f.description || '')}</span></div>
              `).join('')}
            ` : '<div style="color:#16a34a;font-weight:700;text-align:center;padding:16px">No phishing signals detected.</div>'}
            <button class="open-btn" id="pfp-open">Open full report</button>
          </div>
        `, jobId);
      }
    );
  }

  function extractEmailContent() {
    const bodySelectors = [
      '[aria-label="Message body"]',
      '.ReadingPaneContent',
      '.allowTextSelection',
      '[role="document"]',
    ];
    let body = '';
    for (const s of bodySelectors) {
      const el = document.querySelector(s);
      if (el?.innerText?.trim()) { body = el.innerText.trim(); break; }
    }

    const subject  = document.querySelector('[aria-label="subject"] span, .subject')?.innerText || '';
    const fromEl   = document.querySelector('[aria-label="From"] .ms-Persona-primaryText, .sender');
    const from     = fromEl?.innerText || '';
    const links    = [...(document.querySelector('[role="document"]')?.querySelectorAll('a[href]') || [])]
                       .map(a => a.href).filter(Boolean);

    return `From: ${from}\nSubject: ${subject}\n\n${body}\n\nLinks:\n${links.join('\n')}`;
  }

  function showPanel(bodyHtml, jobId) {
    if (panelHost) panelHost.remove();
    panelHost = document.createElement('div');
    Object.assign(panelHost.style, {
      position: 'fixed', top: '0', right: '0', width: '360px', height: '100vh', zIndex: '2147483646',
    });
    const shadow = panelHost.attachShadow({ mode: 'closed' });

    const style = document.createElement('style');
    style.textContent = `
      *{box-sizing:border-box;margin:0;padding:0;font-family:'Space Mono',monospace;font-size:12px}
      .panel{background:#fffefb;border-left:2px solid #1a1a1a;height:100vh;display:flex;flex-direction:column;box-shadow:-3px 0 0 #1a1a1a}
      .hdr{display:flex;align-items:center;justify-content:space-between;padding:12px 14px;border-bottom:2px solid #1a1a1a}
      .hdr-title{font-weight:700;font-size:13px;display:flex;align-items:center;gap:8px}
      .shield{width:26px;height:26px;background:#4f46e5;border:2px solid #1a1a1a;border-radius:8px;
              display:flex;align-items:center;justify-content:center}
      .shield svg{stroke:#fff;fill:none;stroke-width:2.5;width:12px;height:12px}
      .close{background:none;border:none;font-size:16px;cursor:pointer;color:#5a5a5a}
      .body{flex:1;overflow-y:auto;padding:14px}
      .vcard{border:2px solid #1a1a1a;border-radius:12px;padding:14px;margin-bottom:12px;box-shadow:2px 2px 0 #1a1a1a}
      .badge{display:inline-block;padding:2px 8px;border-radius:5px;font-weight:700;font-size:11px}
      .sec-title{font-weight:700;color:#1a1a1a;margin:10px 0 6px;font-size:10px;text-transform:uppercase}
      .flag{display:flex;gap:6px;margin-bottom:4px;color:#5a5a5a;font-size:11px}
      .dot{width:6px;height:6px;border-radius:50%;background:#dc2626;flex-shrink:0;margin-top:3px}
      .open-btn{display:block;width:100%;margin-top:14px;padding:10px;background:#4f46e5;color:#fff;
                border:2px solid #1a1a1a;border-radius:10px;box-shadow:2px 2px 0 #1a1a1a;
                font-weight:700;cursor:pointer;font-family:inherit;font-size:11px}
    `;
    shadow.appendChild(style);

    const wrap = document.createElement('div');
    wrap.className = 'panel';
    wrap.innerHTML = `
      <div class="hdr">
        <div class="hdr-title">
          <div class="shield"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
          PhishFilter Pro
        </div>
        <button class="close" id="pfp-close">✕</button>
      </div>
      ${bodyHtml}
    `;
    shadow.appendChild(wrap);

    shadow.getElementById('pfp-close')?.addEventListener('click', () => { panelHost?.remove(); panelHost = null; });
    shadow.getElementById('pfp-open')?.addEventListener('click', () => chrome.runtime.sendMessage({ action: 'openApp', jobId }));

    document.body.appendChild(panelHost);
  }

  function escHtml(str) {
    return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  log('Outlook content script loaded');
})();
