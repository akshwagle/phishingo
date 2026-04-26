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
      *{box-sizing:border-box;margin:0;padding:0;font-family:'Space Mono',ui-monospace,monospace}
      .overlay{position:fixed;inset:0;background:rgba(0,0,0,0.78);display:flex;align-items:center;justify-content:center;padding:16px}
      .card{background:#fff;width:480px;max-width:100%;border-radius:14px;border:1px solid #1a1a1a;
            box-shadow:4px 4px 0 #1a1a1a;padding:28px;text-align:center;color:#1a1a1a}
      .shield-box{width:60px;height:60px;border-radius:14px;background:#fef2f2;border:1.5px solid #dc2626;
                  display:flex;align-items:center;justify-content:center;margin:0 auto 18px}
      .shield-box svg{width:28px;height:28px;color:#dc2626}
      h1{font-size:18px;font-weight:700;color:#1a1a1a;margin-bottom:6px}
      .sub{font-size:12px;color:#5a5a5a;line-height:1.6;margin-bottom:18px}
      .sub strong{color:#dc2626}
      .stats{display:flex;gap:6px;margin-bottom:20px}
      .stat{flex:1;background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:8px 6px;font-size:12px;font-weight:700;color:#dc2626}
      .stat span{display:block;font-size:9px;font-weight:400;color:#9ca3af;margin-bottom:3px;text-transform:uppercase;letter-spacing:.5px}
      .btn-primary{display:block;width:100%;padding:10px;background:#1a56db;color:#fff;border:1.5px solid #1a1a1a;
                   border-radius:8px;box-shadow:2px 2px 0 #1a1a1a;font-size:12px;font-weight:700;cursor:pointer;margin-bottom:8px;font-family:inherit}
      .btn-secondary{background:none;border:none;color:#9ca3af;font-size:11px;cursor:pointer;text-decoration:underline;font-family:inherit}
      .fp-link{display:block;margin-top:12px;font-size:10px;color:#9ca3af;text-decoration:none}
      .fp-link:hover{color:#1a56db}
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
      *{box-sizing:border-box;margin:0;padding:0;font-family:'Space Mono',ui-monospace,monospace}
      .banner{width:100%;height:42px;background:#fffbeb;border-bottom:1.5px solid #d97706;
              display:flex;align-items:center;justify-content:space-between;padding:0 16px;gap:12px;
              box-shadow:0 1px 0 rgba(217,119,6,0.15)}
      .left{display:flex;align-items:center;gap:8px;font-size:12px;font-weight:700;color:#92400e}
      .warn-icon{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:4px;background:#fef3c7;color:#d97706;font-weight:700}
      .actions{display:flex;align-items:center;gap:14px}
      .learn{font-size:11px;color:#1a56db;cursor:pointer;font-weight:700;text-decoration:underline;background:none;border:none;font-family:inherit}
      .dismiss{font-size:11px;color:#9ca3af;cursor:pointer;background:none;border:none;font-family:inherit}
      .dismiss:hover{color:#5a5a5a}
    `);

    const score = result.risk_score || 0;
    const div = document.createElement('div');
    div.innerHTML = `
      <div class="banner">
        <div class="left">
          <span class="warn-icon">!</span>
          <span>This site looks suspicious — risk ${score}/100</span>
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

    if (document.body) {
      document.body.style.marginTop = (parseInt(document.body.style.marginTop || '0') + 42) + 'px';
    }
  }

  // ── FEATURE 2: Sensitive-field & form guard ──────────────────────────────
  // Protects passwords, credit cards, SSN, OTP codes, and form submissions.
  // Triggered on any site scoring >= 30 (SUSPICIOUS or DANGEROUS).
  function attachSensitiveFieldGuard(result) {
    if (sentinelAcked) return;

    const score    = result.risk_score || 0;
    const verdict  = result.verdict || 'SUSPICIOUS';
    const brand    = result.brand_impersonated || location.hostname;
    const isDanger = verdict === 'DANGEROUS';

    // ── Classify input fields ────────────────────────────────────────────
    function classifyField(input) {
      const type   = (input.type        || '').toLowerCase();
      const name   = (input.name        || '').toLowerCase();
      const ph     = (input.placeholder || '').toLowerCase();
      const ac     = (input.autocomplete|| '').toLowerCase();
      const id     = (input.id          || '').toLowerCase();
      const all    = `${name} ${ph} ${ac} ${id}`;

      if (type === 'password')                                  return { kind: 'password',  label: 'your password' };
      if (ac.includes('cc-') || /card.?num|credit|debit|cvv|cvc|expir/i.test(all)) return { kind: 'card', label: 'credit/debit card details' };
      if (/ssn|social.?sec|national.?id|passport/i.test(all))  return { kind: 'identity',  label: 'government ID' };
      if (/otp|one.?time|verify.?code|auth.?code/i.test(all))  return { kind: 'otp',       label: 'verification/OTP code' };
      if (ac === 'current-password' || ac === 'new-password')   return { kind: 'password',  label: 'your password' };
      // Hidden text fields that look like they capture sensitive data
      if (type === 'tel' && isDanger)                           return { kind: 'phone',     label: 'your phone number' };
      return null;
    }

    // ── Modal ──────────────────────────────────────────────────────────
    function showSentinelModal(input, field) {
      if (sentinelAcked) return;
      if (document.getElementById('pfp-sentinel-host')) return;

      chrome.runtime.sendMessage({ action: 'passwordBlocked' });

      const { host, shadow } = makeShadow('pfp-sentinel-host', { inset: '0', width: '100vw', height: '100vh' });
      shadowStyles(shadow, `
        @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&display=swap');
        *{box-sizing:border-box;margin:0;padding:0;font-family:'Space Mono',ui-monospace,monospace}
        .overlay{position:fixed;inset:0;background:rgba(0,0,0,0.78);display:flex;align-items:center;justify-content:center;padding:16px}
        .card{background:#fff;width:440px;max-width:100%;border-radius:14px;border:1px solid #1a1a1a;
              box-shadow:4px 4px 0 #1a1a1a;padding:24px;text-align:center;color:#1a1a1a}
        .icon{width:54px;height:54px;background:#fef2f2;border:1.5px solid #dc2626;border-radius:12px;
              display:flex;align-items:center;justify-content:center;margin:0 auto 16px;color:#dc2626}
        .icon svg{width:28px;height:28px}
        h2{font-size:16px;font-weight:700;color:#1a1a1a;margin-bottom:6px;line-height:1.3}
        .sub{font-size:12px;color:#5a5a5a;line-height:1.6;margin-bottom:12px}
        .sub strong{color:#dc2626}
        .field-pill{display:inline-block;background:#fef2f2;border:1px solid #fca5a5;border-radius:5px;
                    padding:3px 10px;font-size:10px;font-weight:700;color:#dc2626;margin-bottom:14px;letter-spacing:.3px}
        .stats{display:flex;gap:6px;margin-bottom:18px}
        .stat{flex:1;background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:8px 6px;font-size:11px;font-weight:700;color:#dc2626}
        .stat span{display:block;font-size:9px;font-weight:400;color:#9ca3af;margin-bottom:3px;text-transform:uppercase;letter-spacing:.5px}
        .btn-primary{display:block;width:100%;padding:10px;background:#1a56db;color:#fff;border:1.5px solid #1a1a1a;
                     border-radius:8px;box-shadow:2px 2px 0 #1a1a1a;font-size:12px;font-weight:700;cursor:pointer;margin-bottom:8px;font-family:inherit}
        .btn-ghost{background:none;border:none;color:#9ca3af;font-size:10px;cursor:pointer;text-decoration:underline;font-family:inherit;
                   display:${isDanger ? 'none' : 'inline'}}
        .lock-note{font-size:9px;color:#9ca3af;margin-top:12px;line-height:1.6}
      `);

      const div = document.createElement('div');
      div.innerHTML = `
        <div class="overlay">
          <div class="card">
            <div class="icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
            </div>
            <h2>${isDanger ? 'Phishing site — input blocked' : 'Suspicious site detected'}</h2>
            <p class="sub">
              ${isDanger
                ? `This site is <strong>impersonating ${escHtml(brand)}</strong>. Entering <strong>${field?.label || 'sensitive information'}</strong> here will send it directly to attackers.`
                : `This site may be impersonating <strong>${escHtml(brand)}</strong>. Are you sure you trust this site with <strong>${field?.label || 'your information'}</strong>?`}
            </p>
            <div class="field-pill">Blocked: ${field?.label || 'sensitive input'}</div>
            <div class="stats">
              <div class="stat"><span>Risk score</span>${score}/100</div>
              <div class="stat"><span>Verdict</span>${verdict}</div>
              <div class="stat"><span>Domain</span>${escHtml(location.hostname.slice(0, 18))}</div>
            </div>
            <button class="btn-primary" id="pfp-go-safe">Leave this site now</button>
            <button class="btn-ghost" id="pfp-proceed-anyway">I know the risk — let me type</button>
            <div class="lock-note">
              PhishFilter Pro blocked this input to protect your account.<br>
              If this is a false positive, add ${escHtml(location.hostname)} to your whitelist in the extension popup.
            </div>
          </div>
        </div>
      `;
      shadow.appendChild(div);

      shadow.getElementById('pfp-go-safe').onclick = () => {
        host.remove();
        history.back();
        if (!history.length) window.close();
      };

      const proceedBtn = shadow.getElementById('pfp-proceed-anyway');
      if (!isDanger && proceedBtn) {
        proceedBtn.onclick = () => {
          sentinelAcked = true;
          host.remove();
          input?.focus();
        };
      }

      // DANGEROUS: don't let page JS remove our overlay
      new MutationObserver(() => {
        if (!document.getElementById('pfp-sentinel-host') && !sentinelAcked) {
          showSentinelModal(input, field);
        }
      }).observe(document.documentElement, { childList: true });
    }

    // ── Attach guard to a single field ────────────────────────────────
    const guardedInputs = new WeakSet();

    function guardField(input) {
      if (guardedInputs.has(input)) return;
      const field = classifyField(input);
      if (!field) return;
      guardedInputs.add(input);

      // Block focus
      input.addEventListener('focus', () => {
        if (!sentinelAcked) showSentinelModal(input, field);
      }, true);

      // Block keystrokes (capture phase — runs before page JS)
      input.addEventListener('keydown', (e) => {
        if (!sentinelAcked) { e.preventDefault(); e.stopImmediatePropagation(); showSentinelModal(input, field); }
      }, true);

      // Block paste
      input.addEventListener('paste', (e) => {
        if (!sentinelAcked) { e.preventDefault(); e.stopImmediatePropagation(); showSentinelModal(input, field); }
      }, true);

      // Block input (in case page JS sets value directly)
      input.addEventListener('input', (e) => {
        if (!sentinelAcked) { input.value = ''; e.preventDefault(); }
      }, true);

      // Visually mark the field
      if (!sentinelAcked) {
        input.style.setProperty('border', '2px solid #dc2626', 'important');
        input.style.setProperty('background', '#fff8f8', 'important');
        input.setAttribute('placeholder', '[PhishFilter: blocked on suspicious site]');
      }
    }

    // ── Block ALL form submissions on DANGEROUS sites ──────────────────
    function blockForms() {
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          if (!sentinelAcked) {
            e.preventDefault();
            e.stopImmediatePropagation();
            showSentinelModal(null, { label: 'form data' });
          }
        }, true);
      });
    }

    if (isDanger) blockForms();

    // ── Scan all current inputs ────────────────────────────────────────
    document.querySelectorAll('input').forEach(guardField);

    // ── Watch for dynamically added inputs and forms ───────────────────
    new MutationObserver((mutations) => {
      for (const m of mutations) {
        m.addedNodes.forEach(node => {
          if (node.nodeType !== 1) return;
          const inputs = node.matches?.('input') ? [node] : [...(node.querySelectorAll?.('input') || [])];
          inputs.forEach(guardField);
          if (isDanger) {
            const forms = node.matches?.('form') ? [node] : [...(node.querySelectorAll?.('form') || [])];
            forms.forEach(form => {
              form.addEventListener('submit', (e) => {
                if (!sentinelAcked) { e.preventDefault(); e.stopImmediatePropagation(); showSentinelModal(null, { label: 'form data' }); }
              }, true);
            });
          }
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
      *{box-sizing:border-box;margin:0;padding:0;font-family:'Space Mono',ui-monospace,monospace}
      .tip{background:#fff;border:1px solid #1a1a1a;border-radius:8px;box-shadow:2px 2px 0 #1a1a1a;
           padding:9px 11px;font-size:11px;width:280px;color:#1a1a1a}
      .row1{display:flex;align-items:center;justify-content:space-between;gap:6px;margin-bottom:6px}
      .badge{padding:2px 7px;border-radius:4px;font-size:9px;font-weight:700;letter-spacing:.4px}
      .score{font-size:11px;font-weight:700;color:#5a5a5a}
      .safe{background:#f0fdf4;color:#16a34a;border:1px solid #86efac}
      .warn{background:#fffbeb;color:#d97706;border:1px solid #fde68a}
      .danger{background:#fef2f2;color:#dc2626;border:1px solid #fca5a5}
      .loading{color:#9ca3af;font-size:11px}
      .url{color:#5a5a5a;word-break:break-all;font-size:10px;margin-bottom:4px;line-height:1.5}
      .meta{color:#9ca3af;font-size:9px;text-transform:uppercase;letter-spacing:.3px}
    `);

    const d = document.createElement('div');
    d.innerHTML = `<div class="tip"><div class="loading">Checking link…</div></div>`;
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
      <div class="tip" ${verdict === 'DANGEROUS' ? 'style="border-color:#dc2626;background:#fff8f8"' : ''}>
        <div class="row1">
          <span class="badge ${cls}">${verdict}</span>
          <span class="score">${score}/100</span>
        </div>
        <div class="url">→ ${escHtml(truncated)}</div>
        <div class="meta">${sources > 0 ? `Flagged by ${sources} source${sources > 1 ? 's' : ''}` : 'No known threats'}</div>
      </div>
    `;
  }

  // ── Message listener ────────────────────────────────────────────────────
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    // "Scan this entire page" — from context menu or popup button
    if (msg.action === 'extractPageData' || msg.action === 'startPageScan') {
      log('startPageScan received');
      // ACK immediately so popup knows we're alive
      sendResponse({ ok: true });

      // Show loading panel right away — regardless of safe/unsafe
      showSidePanel(null);

      const data = extractPageData();

      // Run the scan via background, with direct-fetch fallback
      const directFetch = () => getBackendUrlDirect().then(base =>
        fetch(`${base}/api/page-scan`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data),
          signal: AbortSignal.timeout(25000),
        })
        .then(r => r.json())
        .then(r => showSidePanel(r))
      );

      try {
        chrome.runtime.sendMessage({ action: 'analyzePage', pageData: data }, (result) => {
          if (chrome.runtime.lastError || !result) {
            log('background scan failed, trying direct fetch:', chrome.runtime.lastError?.message);
            directFetch().catch(err => {
              log('direct fetch also failed:', err);
              showSidePanel({ verdict: 'UNKNOWN', risk_score: 0, summary: 'Could not reach backend. Please try again.', error: true });
            });
          } else {
            showSidePanel(result);
          }
        });
      } catch (err) {
        log('runtime.sendMessage threw:', err);
        directFetch().catch(() => {
          showSidePanel({ verdict: 'UNKNOWN', risk_score: 0, summary: 'Could not reach backend. Please try again.', error: true });
        });
      }
      return false;  // sync ack already sent
    }

    if (msg.action === 'showBlockPage') { showBlockPage(msg.result); sendResponse({}); return; }
    if (msg.action === 'showSuspiciousBanner') { showSuspiciousBanner(msg.result); sendResponse({}); return; }
    if (msg.action === 'showScanResult') { showScanResult(msg); sendResponse({}); return; }

    // Clipboard text request from popup
    if (msg.action === 'getClipboard') {
      navigator.clipboard.readText()
        .then(text => sendResponse(text))
        .catch(() => sendResponse(''));
      return true;
    }
  });

  function getBackendUrlDirect() {
    return new Promise(resolve => {
      chrome.storage.local.get(['backendUrl'], d =>
        resolve((d.backendUrl || 'https://phishingo-production.up.railway.app').replace(/\/$/, ''))
      );
    });
  }

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
    // Loading state
    if (!result) {
      const { host, shadow } = makeShadow('pfp-panel-host', {
        top: '0', right: '0', width: '380px', height: '100vh',
      });
      panelHost = host;
      shadowStyles(shadow, `
        @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&display=swap');
        *{box-sizing:border-box;margin:0;padding:0;font-family:'Space Mono',ui-monospace,monospace}
        .panel{background:#fff;border-left:1px solid #1a1a1a;height:100vh;display:flex;flex-direction:column;
               box-shadow:-3px 0 0 #1a1a1a;animation:slide .2s ease;color:#1a1a1a}
        @keyframes slide{from{transform:translateX(380px)}to{transform:translateX(0)}}
        .hdr{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;
             border-bottom:1px solid #e8e8e3;background:#fff}
        .hdr-left{display:flex;align-items:center;gap:9px;font-weight:700;font-size:13px}
        .shield{width:26px;height:26px;border-radius:7px;background:#1a56db;display:flex;align-items:center;justify-content:center}
        .shield svg{width:13px;height:13px;stroke:#fff;fill:none;stroke-width:2.5;stroke-linecap:round;stroke-linejoin:round}
        .close{background:none;border:none;font-size:16px;cursor:pointer;color:#9ca3af;line-height:1;padding:4px;font-family:inherit}
        .close:hover{color:#1a1a1a}
        .body{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;padding:20px}
        .dots{display:flex;gap:6px}
        .dot{width:8px;height:8px;border-radius:50%;background:#1a56db;animation:pulse 1s infinite}
        .dot:nth-child(2){animation-delay:.2s}.dot:nth-child(3){animation-delay:.4s}
        @keyframes pulse{0%,100%{opacity:.4;transform:scale(1)}50%{opacity:1;transform:scale(1.3)}}
        .loading-text{font-size:12px;color:#5a5a5a;text-align:center;line-height:1.6}
        .loading-sub{font-size:10px;color:#9ca3af}
      `);
      const d = document.createElement('div');
      d.innerHTML = `<div class="panel">
        <div class="hdr">
          <div class="hdr-left">
            <div class="shield"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
            PhishFilter <span style="color:#1a56db">Pro</span>
          </div>
          <button class="close" id="pfp-panel-close">✕</button>
        </div>
        <div class="body">
          <div class="dots"><span class="dot"></span><span class="dot"></span><span class="dot"></span></div>
          <div class="loading-text">Scanning entire page<div class="loading-sub">analyzing links &amp; content</div></div>
        </div>
      </div>`;
      shadow.appendChild(d);
      shadow.getElementById('pfp-panel-close').onclick = () => { host.remove(); panelHost = null; };
      return;
    }

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
      @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&display=swap');
      *{box-sizing:border-box;margin:0;padding:0;font-family:'Space Mono',ui-monospace,monospace;font-size:12px}
      .panel{background:#fff;border-left:1px solid #1a1a1a;height:100vh;display:flex;flex-direction:column;
             box-shadow:-3px 0 0 #1a1a1a;animation:slide .2s ease;color:#1a1a1a}
      @keyframes slide{from{transform:translateX(380px)}to{transform:translateX(0)}}
      .hdr{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;
           border-bottom:1px solid #e8e8e3;background:#fff}
      .hdr-left{display:flex;align-items:center;gap:9px;font-weight:700;font-size:13px}
      .shield{width:26px;height:26px;border-radius:7px;background:#1a56db;display:flex;align-items:center;justify-content:center}
      .shield svg{width:13px;height:13px;stroke:#fff;fill:none;stroke-width:2.5;stroke-linecap:round;stroke-linejoin:round}
      .close{background:none;border:none;font-size:16px;cursor:pointer;color:#9ca3af;line-height:1;padding:4px;font-family:inherit}
      .close:hover{color:#1a1a1a}
      .body{flex:1;overflow-y:auto;padding:14px}
      .verdict-card{border:1px solid #1a1a1a;border-radius:12px;padding:14px;margin-bottom:14px;
                    box-shadow:3px 3px 0 #1a1a1a}
      .v-label{font-size:9px;color:#9ca3af;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
      .v-badge{display:inline-block;padding:3px 9px;border-radius:5px;font-weight:700;font-size:11px;
               margin-bottom:6px;border:1.5px solid currentColor;letter-spacing:.4px}
      .score-big{font-size:26px;font-weight:700;margin:2px 0 0}
      .score-big small{font-size:13px;color:#9ca3af;font-weight:400;margin-left:2px}
      .section{margin-bottom:14px}
      .sec-title{font-weight:700;color:#5a5a5a;margin-bottom:7px;font-size:9px;text-transform:uppercase;letter-spacing:.5px}
      .item{background:#fafaf7;border:1px solid #e8e8e3;border-radius:7px;padding:7px 10px;
            margin-bottom:5px;font-size:10px;color:#374151;word-break:break-all;line-height:1.4}
      .item.danger{border-color:#fca5a5;background:#fff5f5;color:#991b1b}
      .item.warn{border-color:#fde68a;background:#fffbeb;color:#92400e}
      .item .lead{display:inline-block;font-weight:700;margin-right:5px}
      .flag{display:flex;align-items:flex-start;gap:7px;margin-bottom:6px;font-size:11px;color:#374151;line-height:1.5}
      .flag::before{content:'▸';color:#dc2626;flex-shrink:0;font-weight:700}
      .empty{text-align:center;padding:30px 16px}
      .empty .check-icon{width:42px;height:42px;border-radius:12px;background:#f0fdf4;
                         border:1.5px solid #16a34a;display:inline-flex;align-items:center;justify-content:center;
                         color:#16a34a;margin-bottom:10px}
      .empty .check-icon svg{width:22px;height:22px}
      .empty-title{color:#16a34a;font-weight:700;font-size:13px}
      .empty-sub{color:#6b7280;font-size:11px;margin-top:4px}
      .footer{padding:12px 16px;border-top:1px solid #e8e8e3;background:#fafaf7}
      .open-btn{display:block;width:100%;padding:10px;background:#1a56db;color:#fff;
                border:1.5px solid #1a1a1a;border-radius:8px;box-shadow:2px 2px 0 #1a1a1a;
                font-weight:700;cursor:pointer;text-align:center;font-family:inherit;font-size:11px}
      .open-btn:hover{background:#1447c0}
    `);

    const bgColor = verdict === 'DANGEROUS' ? '#fff5f5' : verdict === 'SUSPICIOUS' ? '#fffbeb' : '#f0fdf4';
    const allLinks = result?.links || {};
    const dangerLinksAll = allLinks.dangerous || [];
    const suspLinksAll = allLinks.suspicious || [];
    const safeLinkCount = (allLinks.safe?.length || 0);
    const summary = result?.summary || result?.llm?.summary || '';

    const d = document.createElement('div');
    d.innerHTML = `
      <div class="panel">
        <div class="hdr">
          <div class="hdr-left">
            <div class="shield">
              <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </div>
            PhishFilter <span style="color:#1a56db">Pro</span>
          </div>
          <button class="close" id="pfp-panel-close">✕</button>
        </div>
        <div class="body">
          <div class="verdict-card" style="background:${bgColor}">
            <div class="v-label">Full page scan</div>
            <span class="v-badge" style="color:${vColor}">${verdict}</span>
            <div class="score-big" style="color:${vColor}">${score}<small>/100</small></div>
            ${summary ? `<div style="font-size:11px;color:#374151;margin-top:8px;line-height:1.5">${escHtml(summary)}</div>` : ''}
          </div>

          <div class="section">
            <div class="sec-title">Scan summary</div>
            <div class="item"><span class="lead">Links</span>${dangerLinksAll.length + suspLinksAll.length + safeLinkCount || 0} analyzed${dangerLinksAll.length + suspLinksAll.length > 0 ? ` · <strong style="color:#dc2626">${dangerLinksAll.length + suspLinksAll.length} flagged</strong>` : ''}</div>
            <div class="item"><span class="lead">Forms</span>${pwordFields > 0 ? `${pwordFields} sensitive field${pwordFields > 1 ? 's' : ''}` : 'no sensitive fields'}</div>
            <div class="item"><span class="lead">AI</span>${llmFlags.length > 0 ? `${llmFlags.length} red flag${llmFlags.length > 1 ? 's' : ''} detected` : 'no threats'}</div>
          </div>

          ${dangerLinksAll.length + suspLinksAll.length > 0 ? `
            <div class="section">
              <div class="sec-title">Flagged links · ${dangerLinksAll.length + suspLinksAll.length}</div>
              ${dangerLinksAll.map(u => `<div class="item danger"><span class="lead">DANGER</span>${escHtml((u.url || u).slice(0, 70))}</div>`).join('')}
              ${suspLinksAll.map(u => `<div class="item warn"><span class="lead">WARN</span>${escHtml((u.url || u).slice(0, 70))}</div>`).join('')}
            </div>
          ` : ''}

          ${llmFlags.length > 0 ? `
            <div class="section">
              <div class="sec-title">AI red flags</div>
              ${llmFlags.slice(0, 6).map(f => {
                const text = typeof f === 'string' ? f : (f.description || f.flag || JSON.stringify(f));
                return `<div class="flag">${escHtml(text)}</div>`;
              }).join('')}
            </div>
          ` : ''}

          ${dangerLinksAll.length + suspLinksAll.length + pwordFields + llmFlags.length === 0 ? `
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
          <button class="open-btn" id="pfp-open-app">Open full report ↗</button>
        </div>
      </div>
    `;
    shadow.appendChild(d);

    shadow.getElementById('pfp-panel-close').onclick = () => { host.remove(); panelHost = null; };
    const jobId = result?.job_id;
    shadow.getElementById('pfp-open-app').onclick = () => {
      if (jobId) {
        window.open(`https://phishingo-zk3c.vercel.app/analyze/${jobId}`, '_blank');
      } else {
        window.open('https://phishingo-zk3c.vercel.app', '_blank');
      }
    };
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
      @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&display=swap');
      *{box-sizing:border-box;margin:0;padding:0;font-family:'Space Mono',ui-monospace,monospace}
      .card{background:#fff;border:1px solid #1a1a1a;border-radius:10px;box-shadow:3px 3px 0 #1a1a1a;padding:14px;color:#1a1a1a}
      .row{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:10px}
      .badge{padding:3px 9px;border-radius:5px;font-size:10px;font-weight:700;letter-spacing:.4px}
      .score{font-size:18px;font-weight:700}
      .subject{font-size:11px;color:#1a1a1a;word-break:break-all;margin-bottom:10px;padding:7px 9px;
               background:#fafaf7;border:1px solid #e8e8e3;border-radius:6px;line-height:1.4}
      .flags-title{font-size:9px;text-transform:uppercase;letter-spacing:.5px;color:#9ca3af;margin-bottom:4px}
      .flag{font-size:10px;color:#5a5a5a;margin-bottom:3px;display:flex;gap:5px;line-height:1.5}
      .flag::before{content:'▸';color:#dc2626;flex-shrink:0}
      .close{background:none;border:none;cursor:pointer;color:#9ca3af;font-size:14px;font-family:inherit}
      .close:hover{color:#1a1a1a}
      .link{display:block;width:100%;margin-top:12px;text-align:center;color:#1a56db;font-size:11px;
            font-weight:700;cursor:pointer;text-decoration:none;background:#eef4ff;border:1px solid #1a56db;
            border-radius:6px;padding:7px;font-family:inherit}
      .link:hover{background:#1a56db;color:#fff}
    `);

    const subject = url || (text ? text.slice(0, 60) + (text.length > 60 ? '…' : '') : '');

    const d = document.createElement('div');
    const flagItems = flags.slice(0, 3)
      .map(f => `<div class="flag">${escHtml(typeof f === 'string' ? f : f.description || '')}</div>`)
      .join('');
    d.innerHTML = `
      <div class="card">
        <div class="row">
          <span class="badge" style="background:${vColor}1a;color:${vColor};border:1px solid ${vColor}66">${verdict}</span>
          <span class="score" style="color:${vColor}">${score}</span>
          <button class="close" id="pfp-result-close" aria-label="Close">✕</button>
        </div>
        ${subject ? `<div class="subject">${escHtml(subject)}</div>` : ''}
        ${flagItems ? `<div class="flags-title">Red flags</div>${flagItems}` : ''}
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

  // ── Init: get or trigger a scan for this page ────────────────────────────
  chrome.runtime.sendMessage({ action: 'getTabResult' }, (cached) => {
    if (!chrome.runtime.lastError && cached) {
      pageResult = cached;
      // Arm field guard on SUSPICIOUS (>= 30) and DANGEROUS sites
      if (pageResult.risk_score >= 30) attachSensitiveFieldGuard(pageResult);
      return;
    }

    // No cached result yet — trigger a fresh scan
    chrome.runtime.sendMessage(
      { action: 'scanTabUrl', url: location.href },
      (result) => {
        if (chrome.runtime.lastError || !result || result.offline) return;
        pageResult = result;
        if (result.risk_score >= 30) attachSensitiveFieldGuard(result);
      }
    );
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
