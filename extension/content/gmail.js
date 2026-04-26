// PhishFilter Pro — Gmail content script
// Uses URL hash polling (Gmail uses #inbox/THREADID) for reliable detection
(function () {
  'use strict';

  const BACKEND = (() => {
    return new Promise(resolve => {
      chrome.storage.local.get(['backendUrl'], d =>
        resolve((d.backendUrl || 'https://phishingo-production.up.railway.app').replace(/\/$/, ''))
      );
    });
  })();

  // ── State ───────────────────────────────────────────────────────────────
  let lastHash = '';
  let lastThreadId = '';
  let scanInFlight = false;
  let scanButtonInjected = false;

  // ── Hash polling — most reliable way to detect Gmail email opens ────────
  function pollHash() {
    const hash = location.hash;
    if (hash === lastHash) return;
    lastHash = hash;

    // Gmail email view: #inbox/THREADID, #sent/THREADID, #spam/THREADID, etc.
    const threadMatch = hash.match(/\/([\da-f]{16,}|thread-[^/]+)$/i);
    if (threadMatch && threadMatch[1] !== lastThreadId) {
      lastThreadId = threadMatch[1];
      // Wait for Gmail to render email body
      setTimeout(() => tryInjectAndScan(), 1200);
    }
  }

  setInterval(pollHash, 400);

  // Also use MutationObserver as a fallback
  let mutationTimer = null;
  const observer = new MutationObserver(() => {
    clearTimeout(mutationTimer);
    mutationTimer = setTimeout(tryInjectScanButton, 800);
  });

  // Start observing once Gmail main container exists
  function startObserving() {
    const container = document.querySelector('[role="main"]') || document.body;
    observer.observe(container, { childList: true, subtree: true });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startObserving);
  } else {
    startObserving();
  }

  // ── Email body selectors (Gmail's DOM) ────────────────────────────────
  function getEmailContainer() {
    // Gmail renders emails in elements with role="listitem" or specific data attrs
    return (
      document.querySelector('[data-message-id]') ||
      document.querySelector('.ii.gt') ||
      document.querySelector('[role="listitem"] .a3s') ||
      document.querySelector('.a3s.aiL') ||
      document.querySelector('.gs') // email thread
    );
  }

  function getEmailBody() {
    // Try multiple selectors in order of specificity
    const selectors = [
      '.a3s.aiL', // most common
      '.a3s',
      '.ii.gt .a3s',
      '[role="listitem"] .a3s',
      '.gmail_quote', // quoted text
    ];
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el && el.innerText.trim().length > 10) return el;
    }
    return null;
  }

  function getReplyToolbar() {
    // Gmail toolbar above emails — try to find a place to inject our button
    return (
      document.querySelector('.ade') ||
      document.querySelector('[gh="mtb"]') ||
      document.querySelector('.G-atb') ||
      document.querySelector('[data-tooltip="More"]')?.closest('.G-Ni') ||
      document.querySelector('.iH')
    );
  }

  // ── Extract email content ──────────────────────────────────────────────
  function extractEmailContent() {
    const bodyEl = getEmailBody();
    const body = bodyEl ? bodyEl.innerText.trim().slice(0, 5000) : '';

    // Extract headers from the email view
    const fromEl = document.querySelector('[email]') || document.querySelector('.gD');
    const subjectEl = document.querySelector('[data-thread-perm-id]') ||
                      document.querySelector('h2[data-legacy-thread-id]') ||
                      document.querySelector('.hP');

    const links = [];
    if (bodyEl) {
      bodyEl.querySelectorAll('a[href]').forEach(a => {
        const href = a.href;
        if (href && !href.startsWith('mailto:') && !href.startsWith('#')) {
          links.push(href);
        }
      });
    }

    // Check for credential-harvesting forms (phishing red flag)
    const forms = [];
    if (bodyEl) {
      bodyEl.querySelectorAll('input[type="password"], input[type="email"]').forEach(inp => {
        forms.push({ type: inp.type, name: inp.name || '', placeholder: inp.placeholder || '' });
      });
    }

    return {
      from: fromEl ? (fromEl.getAttribute('email') || fromEl.innerText.trim()) : '',
      subject: subjectEl ? subjectEl.innerText.trim() : document.title.replace(' - Gmail', ''),
      body: body || '[No body text extracted]',
      links: links.slice(0, 30),
      forms,
    };
  }

  // ── Inject banner ──────────────────────────────────────────────────────
  function removeBanner() {
    const existing = document.getElementById('pfp-gmail-banner-host');
    if (existing) existing.remove();
  }

  function showLoadingBanner(targetEl) {
    removeBanner();
    const host = document.createElement('div');
    host.id = 'pfp-gmail-banner-host';
    host.style.cssText = 'all:initial;display:block;';

    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = `
      <style>
        :host { display: block; }
        .banner {
          display: flex; align-items: center; gap: 10px;
          background: #eff6ff; border: 2px solid #1a56db;
          border-radius: 8px; padding: 10px 14px;
          margin: 8px 0; font-family: 'Space Mono', monospace;
          font-size: 12px; color: #1e40af;
        }
        .dot { width: 8px; height: 8px; border-radius: 50%; background: #1a56db;
               animation: pulse 1s infinite; display: inline-block; }
        .dot:nth-child(2) { animation-delay: .2s; }
        .dot:nth-child(3) { animation-delay: .4s; }
        @keyframes pulse { 0%,100%{opacity:.4} 50%{opacity:1} }
      </style>
      <div class="banner">
        <span class="dot"></span><span class="dot"></span><span class="dot"></span>
        <strong>PhishFilter</strong>&nbsp;scanning this email...
      </div>
    `;

    if (targetEl && targetEl.parentNode) {
      targetEl.parentNode.insertBefore(host, targetEl);
    } else {
      const body = getEmailBody();
      if (body && body.parentNode) body.parentNode.insertBefore(host, body);
    }
    return host;
  }

  function showResultBanner(targetEl, result) {
    removeBanner();

    const v = result.verdict || 'UNKNOWN';
    const score = result.risk_score || 0;
    const colors = {
      SAFE:       { bg: '#f0fdf4', border: '#16a34a', text: '#166534', badge: '#dcfce7', icon: '✓' },
      SUSPICIOUS: { bg: '#fffbeb', border: '#d97706', text: '#92400e', badge: '#fef3c7', icon: '!' },
      DANGEROUS:  { bg: '#fef2f2', border: '#dc2626', text: '#991b1b', badge: '#fee2e2', icon: '!' },
      UNKNOWN:    { bg: '#f9fafb', border: '#9ca3af', text: '#374151', badge: '#f3f4f6', icon: '?' },
    };
    const c = colors[v] || colors.UNKNOWN;

    const summary = result.summary || (v === 'SAFE' ? 'No phishing indicators found.' : 'Suspicious patterns detected.');
    const flags = (result.red_flags || []).slice(0, 3);

    const host = document.createElement('div');
    host.id = 'pfp-gmail-banner-host';
    host.style.cssText = 'all:initial;display:block;';
    const shadow = host.attachShadow({ mode: 'open' });

    const spfVal = result.authentication?.spf || result.spf || 'unknown';
    const dkimVal = result.authentication?.dkim || result.dkim || 'unknown';
    const dmarcVal = result.authentication?.dmarc || result.dmarc || 'unknown';

    const authBadge = (label, val) => {
      const ok = val === 'pass' || val === true || val === 'true';
      return `<span style="padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;
        background:${ok ? '#dcfce7' : '#fee2e2'};color:${ok ? '#166534' : '#991b1b'};
        border:1px solid ${ok ? '#16a34a' : '#dc2626'}">${label} ${ok ? '✓' : '✗'}</span>`;
    };

    shadow.innerHTML = `
      <style>
        :host { display: block; }
        .banner {
          background: ${c.bg}; border: 2px solid ${c.border};
          border-radius: 8px; padding: 12px 14px; margin: 8px 0;
          font-family: 'Space Mono', monospace; font-size: 12px; color: ${c.text};
        }
        .top { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 6px; }
        .left { display: flex; align-items: center; gap: 8px; }
        .icon { display: inline-flex; align-items: center; justify-content: center;
          width: 22px; height: 22px; border-radius: 5px;
          background: ${c.badge}; color: ${c.border}; border: 1.5px solid ${c.border};
          font-size: 12px; font-weight: 700; line-height: 1; }
        .title { font-weight: 700; font-size: 13px; letter-spacing: 0.3px; }
        .score-pill { padding: 2px 8px; border-radius: 12px; font-size: 10px; font-weight: 700;
          background: ${c.badge}; color: ${c.text}; border: 1px solid ${c.border}; white-space: nowrap; }
        .actions { display: flex; gap: 6px; }
        .btn { padding: 3px 9px; border-radius: 5px; font-size: 10px; font-weight: 700;
          cursor: pointer; border: 1.5px solid ${c.border}; background: ${c.badge};
          color: ${c.text}; font-family: 'Space Mono', monospace; }
        .btn:hover { opacity: 0.8; }
        .btn-dismiss { background: transparent; border-color: transparent; color: ${c.text}; opacity: 0.6; }
        .summary { font-size: 11px; line-height: 1.5; margin-bottom: 6px; }
        .auth-row { display: flex; gap: 5px; flex-wrap: wrap; margin-bottom: 6px; }
        .flags { border-top: 1px solid ${c.border}40; padding-top: 6px; margin-top: 2px; }
        .flag { font-size: 10px; color: ${c.text}; padding: 2px 0; opacity: 0.85; }
        .flag::before { content: '▸ '; }
        .report-link { font-size: 10px; opacity: 0.7; text-decoration: underline; cursor: pointer; }
      </style>
      <div class="banner" id="pfp-banner">
        <div class="top">
          <div class="left">
            <span class="icon">${c.icon}</span>
            <span class="title">PhishFilter: ${v}</span>
            <span class="score-pill">Score ${score}/100</span>
          </div>
          <div class="actions">
            <button class="btn" id="rescan-btn">↻ Rescan</button>
            <button class="btn btn-dismiss" id="dismiss-btn">✕</button>
          </div>
        </div>
        <div class="summary">${summary}</div>
        <div class="auth-row">
          ${authBadge('SPF', spfVal)}
          ${authBadge('DKIM', dkimVal)}
          ${authBadge('DMARC', dmarcVal)}
        </div>
        ${flags.length ? `
          <div class="flags">
            ${flags.map(f => {
              const t = typeof f === 'string' ? f : (f.description || f.flag || '');
              return `<div class="flag">${t.slice(0, 100)}</div>`;
            }).join('')}
          </div>
        ` : ''}
        ${result.job_id ? `<div style="margin-top:6px"><a class="report-link" id="report-link">Open full forensic report →</a></div>` : ''}
      </div>
    `;

    shadow.getElementById('dismiss-btn').addEventListener('click', () => host.remove());
    shadow.getElementById('rescan-btn').addEventListener('click', () => runScan(true));
    if (result.job_id) {
      shadow.getElementById('report-link').addEventListener('click', () => {
        chrome.runtime.sendMessage({ action: 'openTab', url: `https://phishingo-zk3c.vercel.app/analyze/${result.job_id}` });
      });
    }

    if (targetEl && targetEl.parentNode) {
      targetEl.parentNode.insertBefore(host, targetEl);
    } else {
      const body = getEmailBody();
      if (body && body.parentNode) body.parentNode.insertBefore(host, body);
    }
  }

  // ── Scan button in toolbar ─────────────────────────────────────────────
  function tryInjectScanButton() {
    if (document.getElementById('pfp-gmail-scan-btn')) return;
    const toolbar = getReplyToolbar();
    if (!toolbar) return;

    scanButtonInjected = true;
    const btn = document.createElement('button');
    btn.id = 'pfp-gmail-scan-btn';
    btn.title = 'PhishFilter: Scan this email';
    btn.style.cssText = `
      display: inline-flex; align-items: center; gap: 6px;
      padding: 5px 11px; margin: 0 4px;
      background: #eef4ff; color: #1a56db;
      border: 1.5px solid #1a56db; border-radius: 6px;
      font-size: 11px; font-weight: 700; cursor: pointer;
      font-family: 'Space Mono', monospace;
      transition: background 0.15s;
    `;
    btn.onmouseenter = () => { btn.style.background = '#1a56db'; btn.style.color = '#fff'; };
    btn.onmouseleave = () => { btn.style.background = '#eef4ff'; btn.style.color = '#1a56db'; };
    btn.innerHTML = `
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      <span>Scan email</span>
    `;
    btn.addEventListener('click', () => runScan(true));
    toolbar.appendChild(btn);
  }

  // ── Main scan function ─────────────────────────────────────────────────
  async function runScan(force = false) {
    if (scanInFlight && !force) return;
    const bodyEl = getEmailBody();
    if (!bodyEl) return;

    // Check if banner already exists and not forcing
    if (!force && document.getElementById('pfp-gmail-banner-host')) return;

    scanInFlight = true;
    const loadingHost = showLoadingBanner(bodyEl);

    try {
      const content = extractEmailContent();

      // Build email text for analysis
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
          metadata: {
            from: content.from,
            subject: content.subject,
            url_count: content.links.length,
            has_forms: content.forms.length > 0,
          },
        }),
        signal: AbortSignal.timeout(30000),
      });

      loadingHost.remove();

      if (res.ok) {
        const data = await res.json();
        showResultBanner(bodyEl, data);

        // Save to recent threats if suspicious
        if (data.verdict && data.verdict !== 'SAFE') {
          saveToRecentThreats({
            verdict: data.verdict,
            domain: content.from || content.subject || 'Gmail email',
            time: 'just now',
          });
        }

        // Update stats
        chrome.storage.local.get(['stats'], d => {
          const s = d.stats || {};
          s.links_scanned = (s.links_scanned || 0) + content.links.length + 1;
          if (data.verdict === 'DANGEROUS') s.phishes_caught = (s.phishes_caught || 0) + 1;
          chrome.storage.local.set({ stats: s });
        });
      } else {
        loadingHost.remove();
        showResultBanner(bodyEl, { verdict: 'UNKNOWN', risk_score: 0, summary: 'Scan failed — backend error.' });
      }
    } catch (err) {
      console.error('[PhishFilter] Gmail scan error:', err);
      try { loadingHost.remove(); } catch {}
      showResultBanner(bodyEl, { verdict: 'UNKNOWN', risk_score: 0, summary: 'Scan failed: ' + err.message });
    } finally {
      scanInFlight = false;
    }
  }

  function saveToRecentThreats(threat) {
    chrome.storage.local.get(['recent_threats'], d => {
      const threats = d.recent_threats || [];
      threats.unshift(threat);
      chrome.storage.local.set({ recent_threats: threats.slice(0, 20) });
    });
  }

  // ── Main trigger: inject button + auto-scan ────────────────────────────
  async function tryInjectAndScan() {
    // Wait for email to render
    let attempts = 0;
    while (attempts < 10 && !getEmailBody()) {
      await new Promise(r => setTimeout(r, 300));
      attempts++;
    }

    const bodyEl = getEmailBody();
    if (!bodyEl) {
      console.log('[PhishFilter] Gmail: No email body found after waiting');
      return;
    }

    tryInjectScanButton();
    // Auto-scan every email
    await runScan();
  }

  // ── Listen for messages from popup ─────────────────────────────────────
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.action === 'gmailScan') {
      runScan(true).then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
      return true;
    }
    if (msg.action === 'openTab') {
      chrome.tabs.create({ url: msg.url });
    }
  });

  console.log('[PhishFilter] Gmail content script loaded — hash polling started');
})();
