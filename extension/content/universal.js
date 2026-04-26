(function () {
  'use strict';

  const LOG = '[PhishFilter]';
  const log = (...a) => console.log(LOG, ...a);

  // Verdict constants
  const DANGEROUS  = 'DANGEROUS';
  const SUSPICIOUS = 'SUSPICIOUS';

  // ── State ────────────────────────────────────────────────────────────────
  let pageResult    = null;    // result from background for current URL
  let blockShown    = false;
  let bannerShown   = false;
  let sentinelAcked = false;   // user dismissed password sentinel this session
  let tooltipTimer  = null;
  let tooltipHost   = null;
  let panelHost     = null;

  // ── Shadow DOM factory ───────────────────────────────────────────────────
  function makeShadow(id, positionStyle) {
    let existing = document.getElementById(id);
    if (existing) existing.remove();
    const host = document.createElement('div');
    host.id = id;
    Object.assign(host.style, {
      all:            'initial',
      position:       'fixed',
      zIndex:         '2147483647',
      display:        'block',
      pointerEvents:  'auto',
      ...positionStyle,
    });
    const shadow = host.attachShadow({ mode: 'closed' });
    (document.documentElement || document.body).appendChild(host);
    return { host, shadow };
  }

  function shadowStyles(shadow, css) {
    const s = document.createElement('style');
    s.textContent = css;
    shadow.appendChild(s);
  }

  // ── FEATURE 1: Block page ────────────────────────────────────────────────
  function showBlockPage(result) {
    if (blockShown) return;
    blockShown = true;
    document.body.style.overflow = 'hidden';

    const { host, shadow } = makeShadow('pfp-block-host', { inset: '0', width: '100vw', height: '100vh' });

    shadowStyles(shadow, `
      @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&display=swap');
      *{box-sizing:border-box;margin:0;padding:0;font-family:'Space Mono',monospace}
      .overlay{position:fixed;inset:0;background:rgba(0,0,0,0.82);display:flex;align-items:center;justify-content:center}
      .card{background:#fff;width:480px;max-width:90vw;border-radius:16px;border:2px solid #1a1a1a;
            box-shadow:6px 6px 0 #1a1a1a;padding:32px;text-align:center}
      .shield-box{width:64px;height:64px;border-radius:14px;background:#fef2f2;border:2px solid #dc2626;
                  display:flex;align-items:center;justify-content:center;margin:0 auto 20px}
      .shield-box svg{width:32px;height:32px;color:#dc2626}
      h1{font-size:20px;font-weight:700;color:#1a1a1a;margin-bottom:8px}
      .sub{font-size:13px;color:#5a5a5a;line-height:1.5;margin-bottom:20px}
      .stats{display:flex;gap:8px;margin-bottom:24px;justify-content:center}
      .stat{flex:1;background:#fef2f2;border:1px solid #fca5a5;border-radius:10px;padding:10px 8px;font-size:11px;font-weight:700;color:#dc2626}
      .stat span{display:block;font-size:10px;font-weight:400;color:#5a5a5a;margin-bottom:2px}
      .btn-primary{display:block;width:100%;padding:12px;background:#4f46e5;color:#fff;border:2px solid #1a1a1a;
                   border-radius:10px;box-shadow:3px 3px 0 #1a1a1a;font-size:13px;font-weight:700;cursor:pointer;margin-bottom:10px}
      .btn-secondary{background:none;border:none;color:#5a5a5a;font-size:12px;cursor:pointer;text-decoration:underline}
      .fp-link{display:block;margin-top:14px;font-size:10px;color:#9ca3af;text-decoration:none}
    `);

    const brand = result.brand_impersonated || 'a trusted service';
    const score = result.risk_score || 0;
    const sources = (result.sources_flagged || []).length;

    const wrap = document.createElement('div');
    wrap.className = 'overlay';
    wrap.innerHTML = `
      <div class="card">
        <div class="shield-box">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
        </div>
        <h1>Phishing site detected</h1>
        <p class="sub">This site impersonates <strong>${escHtml(brand)}</strong>. Do not enter any passwords or personal information.</p>
        <div class="stats">
          <div class="stat"><span>Risk score</span>${score}/100</div>
          <div class="stat"><span>Flagged by</span>${sources} source${sources !== 1 ? 's' : ''}</div>
          <div class="stat"><span>Status</span>Blocked</div>
        </div>
        <button class="btn-primary" id="pfp-go-back">Go back to safety</button>
        <button class="btn-secondary" id="pfp-dismiss">I understand the risk, proceed anyway</button>
        <a class="fp-link" href="mailto:support@phishfilterpro.com?subject=False+positive+report&body=${encodeURIComponent(location.href)}" target="_blank">Report a false positive</a>
      </div>
    `;

    shadow.appendChild(wrap);

    shadow.getElementById('pfp-go-back').onclick = () => { history.back(); if (!history.length) window.close(); };
    shadow.getElementById('pfp-dismiss').onclick = () => {
      document.body.style.overflow = '';
      host.remove();
      blockShown = false;
    };

    // Re-inject if site JS removes the host
    const obs = new MutationObserver(() => {
      if (!document.getElementById('pfp-block-host')) showBlockPage(result);
    });
    obs.observe(document.documentElement, { childList: true, subtree: false });
  }

  // ── FEATURE 1: Suspicious banner ─────────────────────────────────────────
  function showSuspiciousBanner(result) {
    if (bannerShown || document.getElementById('pfp-banner-host')) return;
    bannerShown = true;

    const { host, shadow } = makeShadow('pfp-banner-host', { top: '0', left: '0', right: '0', width: '100%' });

    shadowStyles(shadow, `
      *{box-sizing:border-box;margin:0;padding:0;font-family:'Space Mono',monospace}
      .banner{width:100%;height:44px;background:#fffbeb;border-bottom:2px solid #d97706;
              display:flex;align-items:center;justify-content:space-between;padding:0 16px;gap:12px}
      .left{display:flex;align-items:center;gap:8px;font-size:12px;font-weight:700;color:#92400e}
      .warn-icon{font-size:16px}
      .actions{display:flex;align-items:center;gap:12px}
      .learn{font-size:11px;color:#4f46e5;cursor:pointer;font-weight:700;text-decoration:underline;background:none;border:none}
      .dismiss{font-size:11px;color:#9ca3af;cursor:pointer;background:none;border:none;font-family:inherit}
    `);

    const score = result.risk_score || 0;
    const div = document.createElement('div');
    div.innerHTML = `
      <div class="banner">
        <div class="left">
          <span class="warn-icon">⚠</span>
          <span>This site looks suspicious — risk score ${score}/100</span>
        </div>
        <div class="actions">
          <button class="learn" id="pfp-learn">Learn why</button>
          <button class="dismiss" id="pfp-banner-dismiss">Dismiss</button>
        </div>
      </div>
    `;
    shadow.appendChild(div);

    shadow.getElementById('pfp-learn').onclick = () => {
      chrome.runtime.sendMessage({ action: 'openApp' });
    };
    shadow.getElementById('pfp-banner-dismiss').onclick = () => {
      host.remove();
      bannerShown = false;
    };

    // Push page content down
    document.body.style.marginTop = (parseInt(document.body.style.marginTop || '0') + 44) + 'px';
  }

  // ── FEATURE 2: Password sentinel ─────────────────────────────────────────
  function attachPasswordSentinel(result) {
    if (sentinelAcked) return;
    const brand = result.brand_impersonated || 'a suspicious site';
    const score = result.risk_score || 0;

    function showModal(input) {
      if (sentinelAcked || document.getElementById('pfp-sentinel-host')) return;
      chrome.runtime.sendMessage({ action: 'passwordBlocked' });

      const { host, shadow } = makeShadow('pfp-sentinel-host', { inset: '0', width: '100vw', height: '100vh' });
      shadowStyles(shadow, `
        *{box-sizing:border-box;margin:0;padding:0;font-family:'Space Mono',monospace}
        .overlay{position:fixed;inset:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center}
        .card{background:#fff;width:420px;max-width:90vw;border-radius:16px;border:2px solid #1a1a1a;
              box-shadow:5px 5px 0 #1a1a1a;padding:28px;text-align:center}
        .icon-box{width:52px;height:52px;background:#fef2f2;border-radius:12px;border:2px solid #fca5a5;
                  display:flex;align-items:center;justify-content:center;margin:0 auto 16px;font-size:24px}
        h2{font-size:16px;font-weight:700;color:#1a1a1a;margin-bottom:8px}
        p{font-size:12px;color:#5a5a5a;line-height:1.6;margin-bottom:16px}
        .score{display:inline-block;background:#fef2f2;border:1px solid #fca5a5;border-radius:6px;
               padding:4px 10px;font-size:11px;font-weight:700;color:#dc2626;margin-bottom:20px}
        .btn-primary{display:block;width:100%;padding:10px;background:#4f46e5;color:#fff;border:2px solid #1a1a1a;
                     border-radius:10px;box-shadow:2px 2px 0 #1a1a1a;font-size:12px;font-weight:700;cursor:pointer;margin-bottom:8px}
        .btn-ghost{background:none;border:none;color:#9ca3af;font-size:11px;cursor:pointer;text-decoration:underline}
      `);

      const d = document.createElement('div');
      d.innerHTML = `
        <div class="overlay">
          <div class="card">
            <div class="icon-box">🔒</div>
            <h2>Stop — this site is suspicious</h2>
            <p>This site may be impersonating <strong>${escHtml(brand)}</strong>. Entering your password could give attackers access to your real account.</p>
            <div class="score">Risk score: ${score}/100</div>
            <button class="btn-primary" id="pfp-cancel-leave">Cancel and leave this site</button>
            <button class="btn-ghost" id="pfp-proceed">I'm sure this is safe, let me type</button>
          </div>
        </div>
      `;
      shadow.appendChild(d);

      shadow.getElementById('pfp-cancel-leave').onclick = () => { history.back(); host.remove(); };
      shadow.getElementById('pfp-proceed').onclick = () => {
        sentinelAcked = true;
        host.remove();
        input && input.focus();
      };
    }

    // Attach to all existing password inputs
    function attachToInput(input) {
      input.addEventListener('focus', () => showModal(input), { once: false });
      input.addEventListener('keydown', (e) => {
        if (!sentinelAcked) { e.preventDefault(); showModal(input); }
      }, { once: false });
    }

    document.querySelectorAll('input[type="password"]').forEach(attachToInput);

    // Watch for dynamically added inputs
    new MutationObserver((mutations) => {
      for (const m of mutations) {
        m.addedNodes.forEach(node => {
          if (node.nodeType !== 1) return;
          if (node.matches?.('input[type="password"]')) attachToInput(node);
          node.querySelectorAll?.('input[type="password"]').forEach(attachToInput);
        });
      }
    }).observe(document.body, { childList: true, subtree: true });
  }

  // ── FEATURE 3: Link hover preview ────────────────────────────────────────
  const urlCache = new Map(); // session-level in-content cache

  document.addEventListener('mouseover', (e) => {
    const a = e.target.closest('a[href]');
    if (!a) return;
    const href = a.href || '';
    if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:')
        || href.startsWith('javascript:') || href.startsWith('chrome:')
        || isSameDomain(href)) return;

    clearTimeout(tooltipTimer);
    tooltipTimer = setTimeout(() => showLinkTooltip(a, href), 800);
  });

  document.addEventListener('mouseout', (e) => {
    if (e.target.closest('a[href]')) {
      clearTimeout(tooltipTimer);
      if (tooltipHost && !tooltipHost.matches(':hover')) removeTooltip();
    }
  });

  function isSameDomain(href) {
    try { return new URL(href).hostname === location.hostname; } catch { return false; }
  }

  function removeTooltip() {
    if (tooltipHost) { tooltipHost.remove(); tooltipHost = null; }
  }

  async function showLinkTooltip(anchor, url) {
    removeTooltip();
    const rect = anchor.getBoundingClientRect();

    const { host, shadow } = makeShadow('pfp-tooltip-host', {
      top:   Math.max(0, rect.top - 90) + 'px',
      left:  rect.left + 'px',
      width: '280px',
    });
    tooltipHost = host;

    shadowStyles(shadow, `
      *{box-sizing:border-box;margin:0;padding:0;font-family:'Space Mono',monospace}
      .tip{background:#fff;border:2px solid #1a1a1a;border-radius:10px;box-shadow:3px 3px 0 #1a1a1a;
           padding:10px 12px;font-size:11px;width:280px}
      .row1{display:flex;align-items:center;gap:6px;margin-bottom:6px}
      .badge{padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700}
      .safe{background:#f0fff6;color:#16a34a;border:1px solid #86efac}
      .warn{background:#fffbee;color:#d97706;border:1px solid #fde68a}
      .danger{background:#fef2f2;color:#dc2626;border:1px solid #fca5a5}
      .loading{color:#9ca3af}
      .url{color:#5a5a5a;word-break:break-all;font-size:10px;margin-bottom:4px}
      .meta{color:#9ca3af;font-size:10px}
    `);

    const d = document.createElement('div');
    d.innerHTML = `<div class="tip"><div class="loading">Checking link...</div></div>`;
    shadow.appendChild(d);

    let result;
    if (urlCache.has(url)) {
      result = urlCache.get(url);
    } else {
      try {
        result = await new Promise((resolve, reject) => {
          chrome.runtime.sendMessage({ action: 'checkUrl', url }, (r) => {
            if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
            else resolve(r);
          });
        });
        urlCache.set(url, result);
      } catch { result = { verdict: 'UNKNOWN', risk_score: 0 }; }
    }

    if (!tooltipHost || tooltipHost !== host) return; // moused out

    const verdict = result?.verdict || 'UNKNOWN';
    const score   = result?.risk_score || 0;
    const cls     = verdict === 'DANGEROUS' ? 'danger' : verdict === 'SUSPICIOUS' ? 'warn' : 'safe';
    const truncated = url.length > 45 ? url.slice(0, 22) + '…' + url.slice(-18) : url;
    const sources = (result?.sources_flagged || []).length;

    d.innerHTML = `
      <div class="tip${verdict === 'DANGEROUS' ? '" style="border-color:#dc2626;background:#fff8f8' : ''}">
        <div class="row1">
          <span class="badge ${cls}">${verdict}</span>
          <span style="color:#5a5a5a">${score}/100</span>
        </div>
        <div class="url">→ ${escHtml(truncated)}</div>
        <div class="meta">${sources > 0 ? `Flagged by ${sources} source${sources > 1 ? 's' : ''}` : 'No known threats'}</div>
      </div>
    `;
  }

  // ── FEATURE 4: Page data extraction (for context menu "Scan page") ────────
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.action === 'extractPageData') {
      const data = extractPageData();
      chrome.runtime.sendMessage({ action: 'analyzePage', pageData: data }, (result) => {
        if (!chrome.runtime.lastError) showSidePanel(result);
        sendResponse({ ok: true });
      });
      return true;
    }

    if (msg.action === 'showBlockPage') { showBlockPage(msg.result); sendResponse({}); return; }
    if (msg.action === 'showSuspiciousBanner') { showSuspiciousBanner(msg.result); sendResponse({}); return; }
    if (msg.action === 'showScanResult') { showScanResult(msg); sendResponse({}); return; }
  });

  function extractPageData() {
    const links = [...document.querySelectorAll('a[href]')]
      .map(a => a.href)
      .filter(h => h && !h.startsWith('#') && !h.startsWith('javascript:'));

    const forms = [...document.querySelectorAll('input')].map(i => ({
      type:        i.type,
      name:        i.name,
      placeholder: i.placeholder,
      id:          i.id,
    }));

    const images = [...document.querySelectorAll('img[src]')].slice(0, 30).map(i => ({
      src: i.src,
      alt: i.alt,
    }));

    const iframes = [...document.querySelectorAll('iframe[src]')].map(i => i.src);

    return {
      url:    location.href,
      title:  document.title,
      text:   (document.body?.innerText || '').slice(0, 5000),
      links:  [...new Set(links)].slice(0, 50),
      forms,
      images,
      iframes,
    };
  }

  // ── Side panel ───────────────────────────────────────────────────────────
  function showSidePanel(result) {
    if (panelHost) panelHost.remove();

    const { host, shadow } = makeShadow('pfp-panel-host', {
      top: '0', right: '0', width: '380px', height: '100vh',
    });
    panelHost = host;

    const verdict = result?.verdict || 'UNKNOWN';
    const score   = result?.risk_score || 0;
    const dangerLinks  = result?.links?.dangerous || [];
    const suspLinks    = result?.links?.suspicious || [];
    const pwordFields  = result?.forms?.password_fields || 0;
    const llmFlags     = result?.llm?.red_flags || [];

    const vColor = verdict === 'DANGEROUS' ? '#dc2626' : verdict === 'SUSPICIOUS' ? '#d97706' : '#16a34a';

    shadowStyles(shadow, `
      *{box-sizing:border-box;margin:0;padding:0;font-family:'Space Mono',monospace;font-size:12px}
      .panel{background:#fffefb;border-left:2px solid #1a1a1a;height:100vh;display:flex;flex-direction:column;
             box-shadow:-4px 0 0 #1a1a1a;animation:slide .2s ease}
      @keyframes slide{from{transform:translateX(380px)}to{transform:translateX(0)}}
      .hdr{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;
           border-bottom:2px solid #1a1a1a;background:#fffefb}
      .hdr-left{display:flex;align-items:center;gap:8px;font-weight:700;font-size:13px}
      .shield{width:28px;height:28px;border-radius:8px;background:#4f46e5;border:2px solid #1a1a1a;
              display:flex;align-items:center;justify-content:center}
      .shield svg{width:14px;height:14px;stroke:#fff;fill:none;stroke-width:2}
      .close{background:none;border:none;font-size:18px;cursor:pointer;color:#5a5a5a;line-height:1;padding:4px}
      .body{flex:1;overflow-y:auto;padding:14px}
      .verdict-card{border:2px solid #1a1a1a;border-radius:12px;padding:14px;margin-bottom:12px;
                    box-shadow:3px 3px 0 #1a1a1a}
      .v-label{font-size:10px;color:#5a5a5a;margin-bottom:6px}
      .v-badge{display:inline-block;padding:3px 8px;border-radius:6px;font-weight:700;font-size:12px;margin-bottom:4px}
      .section{margin-bottom:12px}
      .sec-title{font-weight:700;color:#1a1a1a;margin-bottom:6px;font-size:11px;text-transform:uppercase}
      .item{background:#f5f0e8;border:1px solid #1a1a1a;border-radius:8px;padding:6px 10px;
            margin-bottom:4px;font-size:10px;color:#5a5a5a;word-break:break-all}
      .flag{display:flex;align-items:flex-start;gap:6px;margin-bottom:4px}
      .dot{width:6px;height:6px;border-radius:50%;background:#dc2626;flex-shrink:0;margin-top:4px}
      .footer{padding:14px 16px;border-top:2px solid #1a1a1a;background:#fffefb}
      .open-btn{display:block;width:100%;padding:10px;background:#4f46e5;color:#fff;
                border:2px solid #1a1a1a;border-radius:10px;box-shadow:2px 2px 0 #1a1a1a;
                font-weight:700;cursor:pointer;text-align:center;font-family:inherit}
    `);

    const bgColor = verdict === 'DANGEROUS' ? '#fff1f1' : verdict === 'SUSPICIOUS' ? '#fffbee' : '#f0fff6';

    const d = document.createElement('div');
    d.innerHTML = `
      <div class="panel">
        <div class="hdr">
          <div class="hdr-left">
            <div class="shield">
              <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </div>
            PhishFilter Pro
          </div>
          <button class="close" id="pfp-panel-close">✕</button>
        </div>
        <div class="body">
          <div class="verdict-card" style="background:${bgColor}">
            <div class="v-label">Page verdict</div>
            <span class="v-badge" style="background:${vColor}22;color:${vColor};border:1px solid ${vColor}66">${verdict}</span>
            <div style="font-size:18px;font-weight:700;color:${vColor}">${score}/100</div>
          </div>
          ${dangerLinks.length + suspLinks.length > 0 ? `
            <div class="section">
              <div class="sec-title">Suspicious links (${dangerLinks.length + suspLinks.length})</div>
              ${dangerLinks.map(u => `<div class="item" style="border-color:#dc2626">⛔ ${escHtml(u.slice(0, 60))}</div>`).join('')}
              ${suspLinks.map(u => `<div class="item" style="border-color:#d97706">⚠ ${escHtml(u.slice(0, 60))}</div>`).join('')}
            </div>
          ` : ''}
          ${pwordFields > 0 ? `
            <div class="section">
              <div class="sec-title">Form fields</div>
              <div class="item" style="border-color:#d97706">⚠ ${pwordFields} password field${pwordFields > 1 ? 's' : ''} on suspicious page</div>
            </div>
          ` : ''}
          ${llmFlags.length > 0 ? `
            <div class="section">
              <div class="sec-title">AI red flags</div>
              ${llmFlags.slice(0, 5).map(f => `
                <div class="flag"><div class="dot"></div><div>${escHtml(typeof f === 'string' ? f : f.description || JSON.stringify(f))}</div></div>
              `).join('')}
            </div>
          ` : ''}
          ${dangerLinks.length + suspLinks.length + pwordFields + llmFlags.length === 0 ? `
            <div style="color:#16a34a;font-weight:700;margin:20px 0;text-align:center">No threats detected on this page</div>
          ` : ''}
        </div>
        <div class="footer">
          <button class="open-btn" id="pfp-open-app">Open full report in PhishFilter Pro</button>
        </div>
      </div>
    `;
    shadow.appendChild(d);

    shadow.getElementById('pfp-panel-close').onclick = () => { host.remove(); panelHost = null; };
    shadow.getElementById('pfp-open-app').onclick = () => chrome.runtime.sendMessage({ action: 'openApp' });
  }

  // ── FEATURE 6: Scan result popup (near selection / from context menu) ─────
  function showScanResult({ result, url, text }) {
    const verdict = result?.verdict || 'UNKNOWN';
    const score   = result?.risk_score || 0;
    const flags   = result?.red_flags || result?.llm?.red_flags || [];

    // Position near mouse or just center-ish
    const vColor = verdict === 'DANGEROUS' ? '#dc2626' : verdict === 'SUSPICIOUS' ? '#d97706' : '#16a34a';

    if (document.getElementById('pfp-result-host')) document.getElementById('pfp-result-host').remove();
    const { host, shadow } = makeShadow('pfp-result-host', {
      top: '80px', right: '20px', width: '300px',
    });

    shadowStyles(shadow, `
      *{box-sizing:border-box;margin:0;padding:0;font-family:'Space Mono',monospace}
      .card{background:#fff;border:2px solid #1a1a1a;border-radius:12px;box-shadow:4px 4px 0 #1a1a1a;padding:16px}
      .row{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
      .badge{padding:3px 8px;border-radius:6px;font-size:11px;font-weight:700}
      .score{font-size:20px;font-weight:700}
      .label{font-size:10px;color:#5a5a5a;margin-bottom:4px}
      .subject{font-size:11px;color:#1a1a1a;word-break:break-all;margin-bottom:10px;padding:6px;
               background:#f5f0e8;border-radius:6px}
      .flag{font-size:10px;color:#5a5a5a;margin-bottom:3px;display:flex;gap:4px}
      .close{background:none;border:none;cursor:pointer;color:#9ca3af;font-size:14px}
      .link{display:block;margin-top:12px;text-align:center;color:#4f46e5;font-size:11px;
            font-weight:700;cursor:pointer;text-decoration:underline;background:none;border:none}
    `);

    const subject = url || (text ? text.slice(0, 60) + (text.length > 60 ? '…' : '') : '');

    const d = document.createElement('div');
    d.innerHTML = `
      <div class="card">
        <div class="row">
          <span class="badge" style="background:${vColor}22;color:${vColor};border:1px solid ${vColor}66">${verdict}</span>
          <span class="score" style="color:${vColor}">${score}</span>
          <button class="close" id="pfp-result-close">✕</button>
        </div>
        ${subject ? `<div class="subject">${escHtml(subject)}</div>` : ''}
        ${flags.slice(0, 3).map(f => `<div class="flag"><span>•</span><span>${escHtml(typeof f === 'string' ? f : f.description || '')}</span></div>`).join('')}
        <button class="link" id="pfp-result-full">Open full report →</button>
      </div>
    `;
    shadow.appendChild(d);

    shadow.getElementById('pfp-result-close').onclick = () => host.remove();
    shadow.getElementById('pfp-result-full').onclick = () => chrome.runtime.sendMessage({ action: 'openApp' });

    // Auto-close after 12 seconds
    setTimeout(() => { if (document.getElementById('pfp-result-host')) host.remove(); }, 12000);
  }

  // ── FEATURE 6: Clipboard guardian ────────────────────────────────────────
  document.addEventListener('copy', () => {
    setTimeout(async () => {
      try {
        const text = await navigator.clipboard.readText().catch(() => null);
        if (!text) return;
        const urlPattern = /https?:\/\/[^\s]+/;
        const match = text.match(urlPattern);
        if (match) {
          chrome.runtime.sendMessage({ action: 'clipboardUrl', url: match[0] });
        }
      } catch { /* clipboard access may be denied */ }
    }, 100);
  });

  // ── Init: get current page result from background ────────────────────────
  chrome.runtime.sendMessage({ action: 'getTabResult' }, (result) => {
    if (chrome.runtime.lastError || !result) return;
    pageResult = result;

    // If domain is suspicious, arm password sentinel proactively
    if (result.risk_score >= 50) {
      attachPasswordSentinel(result);
    }
  });

  // ── Utility ───────────────────────────────────────────────────────────────
  function escHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  log('Universal content script loaded on', location.hostname);
})();
