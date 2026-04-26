// PhishFilter Pro — Outlook Web content script
(function () {
  'use strict';

  const BACKEND = new Promise(resolve => {
    chrome.storage.local.get(['backendUrl'], d =>
      resolve((d.backendUrl || 'https://phishingo-production.up.railway.app').replace(/\/$/, ''))
    );
  });

  // ── State ───────────────────────────────────────────────────────────────
  let lastUrl = location.href;
  let scanInFlight = false;

  // ── URL polling — Outlook is an SPA, detect navigation ────────────────
  function pollUrl() {
    if (location.href === lastUrl) return;
    lastUrl = location.href;
    // Outlook email view contains /mail/id/ in URL
    if (location.href.includes('/mail/') || location.href.includes('/inbox/')) {
      setTimeout(() => tryInjectAndScan(), 1500);
    }
  }

  setInterval(pollUrl, 500);

  // MutationObserver fallback
  let mutationTimer = null;
  const observer = new MutationObserver(() => {
    clearTimeout(mutationTimer);
    mutationTimer = setTimeout(tryInjectScanButton, 1000);
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      observer.observe(document.body, { childList: true, subtree: true });
    });
  } else {
    observer.observe(document.body, { childList: true, subtree: true });
  }

  // ── Outlook DOM selectors ──────────────────────────────────────────────
  function getEmailBody() {
    const selectors = [
      '[aria-label="Message body"]',
      '.ReadingPaneContent',
      '[data-testid="message-body"]',
      '.allowTextSelection',
      '#UniqueMessageBody',
      '.x_WordSection1',
    ];
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el && el.innerText.trim().length > 5) return el;
    }
    return null;
  }

  function getReplyToolbar() {
    return (
      document.querySelector('[aria-label="Reply"]')?.closest('[role="toolbar"]') ||
      document.querySelector('.ms-CommandBar') ||
      document.querySelector('[data-testid="reply-button"]')?.parentElement
    );
  }

  function extractEmailContent() {
    const bodyEl = getEmailBody();
    const body = bodyEl ? bodyEl.innerText.trim().slice(0, 5000) : '';

    const fromEl = document.querySelector('[aria-label*="From"]') ||
                   document.querySelector('.from-address') ||
                   document.querySelector('[data-testid="from"]');
    const subjectEl = document.querySelector('[aria-label*="Subject"]') ||
                      document.querySelector('.subject') ||
                      document.querySelector('h1');

    const links = [];
    if (bodyEl) {
      bodyEl.querySelectorAll('a[href]').forEach(a => {
        if (a.href && !a.href.startsWith('mailto:') && !a.href.startsWith('#')) {
          links.push(a.href);
        }
      });
    }

    const forms = [];
    if (bodyEl) {
      bodyEl.querySelectorAll('input[type="password"], input[type="email"]').forEach(inp => {
        forms.push({ type: inp.type, name: inp.name || '' });
      });
    }

    return {
      from: fromEl ? fromEl.innerText.trim() : '',
      subject: subjectEl ? subjectEl.innerText.trim() : document.title,
      body: body || '[No body text extracted]',
      links: links.slice(0, 30),
      forms,
    };
  }

  // ── Banner ─────────────────────────────────────────────────────────────
  function removeBanner() {
    const existing = document.getElementById('pfp-outlook-banner-host');
    if (existing) existing.remove();
  }

  function showLoadingBanner(targetEl) {
    removeBanner();
    const host = document.createElement('div');
    host.id = 'pfp-outlook-banner-host';
    host.style.cssText = 'all:initial;display:block;';
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = `
      <style>
        .banner { display:flex;align-items:center;gap:10px;background:#eff6ff;
          border:2px solid #1a56db;border-radius:8px;padding:10px 14px;margin:8px 0;
          font-family:'Space Mono',monospace;font-size:12px;color:#1e40af; }
        .dot{width:8px;height:8px;border-radius:50%;background:#1a56db;
          animation:pulse 1s infinite;display:inline-block;}
        .dot:nth-child(2){animation-delay:.2s}.dot:nth-child(3){animation-delay:.4s}
        @keyframes pulse{0%,100%{opacity:.4}50%{opacity:1}}
      </style>
      <div class="banner">
        <span class="dot"></span><span class="dot"></span><span class="dot"></span>
        <strong>PhishFilter</strong>&nbsp;scanning this email...
      </div>
    `;
    if (targetEl && targetEl.parentNode) {
      targetEl.parentNode.insertBefore(host, targetEl);
    }
    return host;
  }

  function showResultBanner(targetEl, result) {
    removeBanner();
    const v = result.verdict || 'UNKNOWN';
    const score = result.risk_score || 0;
    const colors = {
      SAFE:       { bg: '#f0fdf4', border: '#16a34a', text: '#166534', badge: '#dcfce7', icon: '✅' },
      SUSPICIOUS: { bg: '#fffbeb', border: '#d97706', text: '#92400e', badge: '#fef3c7', icon: '⚠️' },
      DANGEROUS:  { bg: '#fef2f2', border: '#dc2626', text: '#991b1b', badge: '#fee2e2', icon: '🚨' },
      UNKNOWN:    { bg: '#f9fafb', border: '#9ca3af', text: '#374151', badge: '#f3f4f6', icon: '❓' },
    };
    const c = colors[v] || colors.UNKNOWN;
    const summary = result.summary || (v === 'SAFE' ? 'No phishing indicators found.' : 'Suspicious patterns detected.');
    const flags = (result.red_flags || []).slice(0, 3);
    const spfVal = result.authentication?.spf || 'unknown';
    const dkimVal = result.authentication?.dkim || 'unknown';

    const authBadge = (label, val) => {
      const ok = val === 'pass' || val === true;
      return `<span style="padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;
        background:${ok?'#dcfce7':'#fee2e2'};color:${ok?'#166534':'#991b1b'};
        border:1px solid ${ok?'#16a34a':'#dc2626'}">${label} ${ok?'✓':'✗'}</span>`;
    };

    const host = document.createElement('div');
    host.id = 'pfp-outlook-banner-host';
    host.style.cssText = 'all:initial;display:block;';
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = `
      <style>
        :host{display:block}
        .banner{background:${c.bg};border:2px solid ${c.border};border-radius:8px;
          padding:12px 14px;margin:8px 0;font-family:'Space Mono',monospace;
          font-size:12px;color:${c.text}}
        .top{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:6px}
        .left{display:flex;align-items:center;gap:8px}
        .title{font-weight:700;font-size:13px}
        .pill{padding:2px 8px;border-radius:12px;font-size:10px;font-weight:700;
          background:${c.badge};color:${c.text};border:1px solid ${c.border};white-space:nowrap}
        .actions{display:flex;gap:6px}
        .btn{padding:3px 9px;border-radius:5px;font-size:10px;font-weight:700;cursor:pointer;
          border:1.5px solid ${c.border};background:${c.badge};color:${c.text};
          font-family:'Space Mono',monospace}
        .btn-dismiss{background:transparent;border-color:transparent;opacity:.6}
        .summary{font-size:11px;line-height:1.5;margin-bottom:6px}
        .auth-row{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:6px}
        .flags{border-top:1px solid ${c.border}40;padding-top:6px;margin-top:2px}
        .flag{font-size:10px;padding:2px 0;opacity:.85}
        .flag::before{content:'▸ '}
        .link{font-size:10px;opacity:.7;text-decoration:underline;cursor:pointer}
      </style>
      <div class="banner">
        <div class="top">
          <div class="left">
            <span style="font-size:18px">${c.icon}</span>
            <span class="title">PhishFilter: ${v}</span>
            <span class="pill">Score ${score}/100</span>
          </div>
          <div class="actions">
            <button class="btn" id="rescan">↻ Rescan</button>
            <button class="btn btn-dismiss" id="dismiss">✕</button>
          </div>
        </div>
        <div class="summary">${summary}</div>
        <div class="auth-row">
          ${authBadge('SPF', spfVal)}${authBadge('DKIM', dkimVal)}
        </div>
        ${flags.length ? `<div class="flags">${flags.map(f => {
          const t = typeof f === 'string' ? f : (f.description || f.flag || '');
          return `<div class="flag">${t.slice(0,100)}</div>`;
        }).join('')}</div>` : ''}
        ${result.job_id ? `<div style="margin-top:6px"><a class="link" id="report">Open full report →</a></div>` : ''}
      </div>
    `;

    shadow.getElementById('dismiss').addEventListener('click', () => host.remove());
    shadow.getElementById('rescan').addEventListener('click', () => runScan(true));
    if (result.job_id) {
      shadow.getElementById('report').addEventListener('click', () => {
        window.open(`https://phishingo-zk3c.vercel.app/analyze/${result.job_id}`, '_blank');
      });
    }

    if (targetEl && targetEl.parentNode) {
      targetEl.parentNode.insertBefore(host, targetEl);
    }
  }

  // ── Scan button ────────────────────────────────────────────────────────
  function tryInjectScanButton() {
    if (document.getElementById('pfp-outlook-btn')) return;
    const toolbar = getReplyToolbar();
    if (!toolbar) return;

    const btn = document.createElement('button');
    btn.id = 'pfp-outlook-btn';
    btn.title = 'PhishFilter: Scan this email';
    btn.style.cssText = `
      display:inline-flex;align-items:center;gap:5px;padding:4px 10px;margin:0 4px;
      background:#eff6ff;color:#1e40af;border:1.5px solid #1a56db;border-radius:6px;
      font-size:11px;font-weight:700;cursor:pointer;font-family:'Space Mono',monospace;
    `;
    btn.innerHTML = '🛡 Scan email';
    btn.addEventListener('click', () => runScan(true));
    toolbar.appendChild(btn);
  }

  // ── Main scan ──────────────────────────────────────────────────────────
  async function runScan(force = false) {
    if (scanInFlight && !force) return;
    const bodyEl = getEmailBody();
    if (!bodyEl) return;
    if (!force && document.getElementById('pfp-outlook-banner-host')) return;

    scanInFlight = true;
    const loadingHost = showLoadingBanner(bodyEl);

    try {
      const content = extractEmailContent();
      const emailText = [
        content.from ? `From: ${content.from}` : '',
        content.subject ? `Subject: ${content.subject}` : '',
        content.body,
        content.links.length ? `\nLinks:\n${content.links.join('\n')}` : '',
        content.forms.length ? '\n[WARNING: Email contains form inputs — phishing indicator]' : '',
      ].filter(Boolean).join('\n');

      const base = await BACKEND;
      const res = await fetch(`${base}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: emailText,
          input_type: 'email',
          metadata: { from: content.from, subject: content.subject },
        }),
        signal: AbortSignal.timeout(30000),
      });

      try { loadingHost.remove(); } catch {}

      if (res.ok) {
        const data = await res.json();
        showResultBanner(bodyEl, data);

        if (data.verdict && data.verdict !== 'SAFE') {
          chrome.storage.local.get(['stats', 'recent_threats'], d => {
            const s = d.stats || {};
            if (data.verdict === 'DANGEROUS') s.phishes_caught = (s.phishes_caught || 0) + 1;
            const threats = d.recent_threats || [];
            threats.unshift({ verdict: data.verdict, domain: content.from || 'Outlook email', time: 'just now' });
            chrome.storage.local.set({ stats: s, recent_threats: threats.slice(0, 20) });
          });
        }
      } else {
        try { loadingHost.remove(); } catch {}
        showResultBanner(bodyEl, { verdict: 'UNKNOWN', risk_score: 0, summary: 'Scan failed.' });
      }
    } catch (err) {
      console.error('[PhishFilter] Outlook scan error:', err);
      try { loadingHost.remove(); } catch {}
      showResultBanner(bodyEl, { verdict: 'UNKNOWN', risk_score: 0, summary: 'Error: ' + err.message });
    } finally {
      scanInFlight = false;
    }
  }

  async function tryInjectAndScan() {
    let attempts = 0;
    while (attempts < 10 && !getEmailBody()) {
      await new Promise(r => setTimeout(r, 300));
      attempts++;
    }
    if (!getEmailBody()) return;
    tryInjectScanButton();
    await runScan();
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.action === 'outlookScan') {
      runScan(true).then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
      return true;
    }
  });

  console.log('[PhishFilter] Outlook content script loaded');
})();
