'use client'
import { useEffect, useState, useRef, Suspense } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import { Shield, Mail, Bell, CheckCircle, AlertTriangle, ArrowRight, Zap, Lock, Globe, RefreshCw, Send } from 'lucide-react'

const BACKEND = process.env.NEXT_PUBLIC_BACKEND_URL || 'https://phishingo-production.up.railway.app'
const TG_BOT  = 'phishfilter_bot'

// Tiny UUID-ish token generator (no crypto dependency)
function makeToken() {
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2)
}

// ── Google G icon ─────────────────────────────────────────────────────────────
function GoogleIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 48 48">
      <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
      <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
      <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
      <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
      <path fill="none" d="M0 0h48v48H0z"/>
    </svg>
  )
}

// ── Telegram Plane icon ───────────────────────────────────────────────────────
function TelegramIcon({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
      <path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/>
    </svg>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
function SafeMailsContent() {
  const searchParams = useSearchParams()

  // Connection state machine: idle → tg_pending → tg_linked → gmail_pending → connected
  const [phase, setPhase] = useState<'idle' | 'tg_pending' | 'tg_linked' | 'gmail_pending' | 'connected'>('idle')
  const [tgToken, setTgToken]         = useState('')
  const [connectedEmail, setConnectedEmail] = useState('')
  const [sessionId, setSessionId]     = useState('')
  const [errorMsg, setErrorMsg]       = useState('')
  const [faqOpen, setFaqOpen]         = useState<number | null>(null)
  const [stats, setStats]             = useState({ alerts_sent: 0, emails_scanned: 0 })
  const pollRef = useRef<NodeJS.Timeout | null>(null)

  // Read OAuth callback query params
  useEffect(() => {
    const s    = searchParams.get('status')
    const sess = searchParams.get('session')
    const em   = searchParams.get('email')
    const tg   = searchParams.get('tg_token')
    const err  = searchParams.get('error')

    if (s === 'connected' && sess) {
      setPhase('connected')
      setSessionId(sess)
      setConnectedEmail(decodeURIComponent(em || ''))
      if (tg) setTgToken(tg)
      window.history.replaceState({}, '', '/safe-mails')
    } else if (err) {
      setErrorMsg(err === 'cancelled' ? 'Google sign-in was cancelled.' : `Auth failed: ${err}`)
    }

    // Restore tg_token from localStorage if coming back from Gmail OAuth
    const saved = localStorage.getItem('pfp_tg_token')
    if (saved && !tg) setTgToken(saved)
  }, [searchParams])

  // Poll for Telegram link (waiting for user to /start the bot)
  useEffect(() => {
    if (phase !== 'tg_pending' || !tgToken) return
    pollRef.current = setInterval(async () => {
      try {
        const res  = await fetch(`${BACKEND}/api/safe-mails/tg-status/${tgToken}`)
        const data = await res.json()
        if (data.linked) {
          clearInterval(pollRef.current!)
          setPhase('tg_linked')
        }
      } catch { /* ignore */ }
    }, 2500)
    return () => clearInterval(pollRef.current!)
  }, [phase, tgToken])

  // Poll live stats when connected
  useEffect(() => {
    if (phase !== 'connected' || !sessionId) return
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${BACKEND}/api/safe-mails/status/${sessionId}`)
        if (res.ok) {
          const d = await res.json()
          setStats({ alerts_sent: d.alerts_sent, emails_scanned: d.emails_scanned })
        }
      } catch { /* ignore */ }
    }, 8000)
    return () => clearInterval(interval)
  }, [phase, sessionId])

  // ── Step 1: open Telegram bot ────────────────────────────────────────────────
  function handleConnectTelegram() {
    const token = makeToken()
    setTgToken(token)
    localStorage.setItem('pfp_tg_token', token)
    setPhase('tg_pending')
    // Deep-link opens the bot with the token as start payload
    window.open(`https://t.me/${TG_BOT}?start=${token}`, '_blank')
  }

  // ── Step 2: connect Gmail ────────────────────────────────────────────────────
  async function handleConnectGmail() {
    setErrorMsg('')
    setPhase('gmail_pending')
    try {
      const res  = await fetch(`${BACKEND}/api/safe-mails/auth-url`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ tg_token: tgToken }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed')
      window.location.href = data.auth_url
    } catch (err: unknown) {
      setPhase('tg_linked')
      setErrorMsg(err instanceof Error ? err.message : 'Backend error')
    }
  }

  async function handleDisconnect() {
    if (sessionId) {
      await fetch(`${BACKEND}/api/safe-mails/disconnect`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ session_id: sessionId }),
      }).catch(() => {})
    }
    setPhase('idle')
    setSessionId('')
    setConnectedEmail('')
    setTgToken('')
    setStats({ alerts_sent: 0, emails_scanned: 0 })
    localStorage.removeItem('pfp_tg_token')
  }

  const faqs = [
    { q: 'Why does it ask me to open Telegram first?', a: 'We need your Telegram chat ID before we can send you alerts. The easiest way is a deep link — click our button, the bot gets your chat ID automatically, no manual entry needed.' },
    { q: 'What Gmail permissions do you request?', a: 'Read-only (gmail.readonly). We cannot send, delete, or modify any email. You can revoke access anytime in myaccount.google.com → Security → Third-party apps.' },
    { q: 'How fast are Telegram alerts?', a: 'We check your inbox every 2 minutes. When a new email arrives, analysis takes 5-15 seconds, then Telegram delivers instantly.' },
    { q: 'Which emails trigger an alert?', a: 'Only emails scoring 30+ on our risk scale. Safe, legitimate emails are silently marked clean — zero notification noise.' },
    { q: 'Is the Telegram bot secure?', a: 'Yes. The bot only sends messages to your chat — it cannot read your Telegram messages. Your Gmail credentials never touch Telegram.' },
    { q: 'How do I stop monitoring?', a: 'Click Disconnect on this page. All stored tokens are immediately deleted, Gmail access revoked, and the bot stops sending alerts.' },
  ]

  return (
    <div className="min-h-screen bg-[#f5f0e8] text-[#1a1a1a]" style={{ fontFamily: "'Space Mono', monospace" }}>

      {/* Navbar */}
      <header className="h-14 bg-[#fffefb] border-b-2 border-[#1a1a1a]" style={{ boxShadow: '0 2px 0 #1a1a1a' }}>
        <div className="mx-auto max-w-6xl h-full px-6 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2.5 no-underline">
            <div className="h-8 w-8 rounded-xl border-2 border-[#1a1a1a] bg-[#4f46e5] flex items-center justify-center"
              style={{ boxShadow: '2px 2px 0 #1a1a1a' }}>
              <Shield className="h-4 w-4 text-white" />
            </div>
            <span className="text-[16px] font-bold">PhishFilter <span className="text-[#4f46e5]">Pro</span></span>
          </Link>
          <nav className="hidden sm:flex items-center gap-5 text-[12px] font-bold">
            <Link href="/" className="text-[#5a5a5a] hover:text-[#4f46e5] no-underline transition-colors">Scanner</Link>
            <Link href="/features" className="text-[#5a5a5a] hover:text-[#4f46e5] no-underline transition-colors">Features</Link>
            <Link href="/extension" className="text-[#5a5a5a] hover:text-[#4f46e5] no-underline transition-colors">Extension</Link>
            <Link href="/safe-mails" className="text-[#16a34a] border-b-2 border-[#16a34a] pb-0.5 no-underline">Safe Mails</Link>
          </nav>
          <div className="flex items-center gap-2 text-[12px] text-[#5a5a5a]">
            <span className="h-2 w-2 rounded-full bg-[#16a34a]" />
            <span className="hidden sm:inline">All engines online</span>
          </div>
        </div>
      </header>

      <main className="px-6 py-12">

        {/* Hero */}
        <section className="mx-auto max-w-3xl text-center mb-12">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-[12px] font-bold mb-6"
            style={{ background: '#dcfce7', border: '2px solid #16a34a', color: '#166534' }}>
            <span className="h-2 w-2 rounded-full bg-[#16a34a]" /> Free · Read-only Gmail · Instant Telegram alerts
          </div>
          <h1 className="text-[34px] sm:text-[42px] font-bold leading-[1.15] mb-5">
            Phishing email? You&apos;ll know<br />
            <span className="text-[#16a34a]">before you even open it.</span>
          </h1>
          <p className="text-[16px] text-[#5a5a5a] leading-relaxed max-w-[580px] mx-auto">
            Connect Gmail + Telegram in 30 seconds. Every new email runs through our 10-engine detector.
            If something looks like phishing, your Telegram gets a plain-English alert instantly.
          </p>
        </section>

        {/* Steps */}
        <section className="mx-auto max-w-[800px] mb-12">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[
              { icon: TelegramIcon, color: '#0088cc', bg: '#e8f4fd', num: '1', title: 'Open the bot', desc: 'Click "Connect Telegram" — it opens @phishfilter_bot and links your chat ID automatically.' },
              { icon: Mail,         color: '#4f46e5', bg: '#eff4ff', num: '2', title: 'Connect Gmail', desc: 'Sign in with Google. Read-only access. We never see your password or write any emails.' },
              { icon: Bell,         color: '#16a34a', bg: '#f0fff6', num: '3', title: 'Get alerts', desc: 'Suspicious email arrives → Telegram message with verdict, score, and a short plain-English summary.' },
            ].map(({ icon: Icon, color, bg, num, title, desc }) => (
              <div key={num} className="clay p-5">
                <div className="flex items-center gap-3 mb-3">
                  <div className="h-9 w-9 rounded-xl flex items-center justify-center flex-shrink-0"
                    style={{ background: bg, border: `2px solid ${color}`, color }}>
                    <Icon size={16} />
                  </div>
                  <div>
                    <div className="text-[10px] font-bold text-[#5a5a5a]">STEP {num}</div>
                    <div className="text-[14px] font-bold">{title}</div>
                  </div>
                </div>
                <p className="text-[13px] text-[#5a5a5a] leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Main card */}
        <section className="mx-auto max-w-[800px] grid grid-cols-1 sm:grid-cols-5 gap-6 mb-12">

          <div className="clay sm:col-span-3 p-6">

            {/* ── CONNECTED ── */}
            {phase === 'connected' && (
              <div>
                <div className="flex items-center gap-3 mb-5">
                  <div className="h-11 w-11 rounded-full flex items-center justify-center flex-shrink-0"
                    style={{ background: '#dcfce7', border: '2px solid #16a34a' }}>
                    <CheckCircle className="h-5 w-5 text-[#16a34a]" />
                  </div>
                  <div>
                    <div className="text-[15px] font-bold text-[#16a34a]">Fully connected</div>
                    <div className="text-[12px] text-[#5a5a5a]">{connectedEmail}</div>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3 mb-5">
                  <div className="clay p-4 text-center" style={{ background: '#f0fff6' }}>
                    <div className="text-[26px] font-bold text-[#16a34a]">{stats.emails_scanned}</div>
                    <div className="text-[11px] text-[#5a5a5a] font-bold">Emails scanned</div>
                  </div>
                  <div className="clay p-4 text-center"
                    style={{ background: stats.alerts_sent > 0 ? '#fff1f1' : '#f9fafb' }}>
                    <div className={`text-[26px] font-bold ${stats.alerts_sent > 0 ? 'text-[#dc2626]' : 'text-[#1a1a1a]'}`}>
                      {stats.alerts_sent}
                    </div>
                    <div className="text-[11px] text-[#5a5a5a] font-bold">Telegram alerts sent</div>
                  </div>
                </div>

                <div className="flex items-center gap-2 rounded-xl border-2 border-[#b3f0c8] bg-[#f0fff6] px-4 py-3 text-[13px] text-[#166534] font-bold mb-5">
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  Checking inbox every 2 minutes
                </div>

                <p className="text-[12px] text-[#5a5a5a] mb-4">
                  Alerts going to{' '}
                  <a href={`https://t.me/${TG_BOT}`} target="_blank" rel="noreferrer"
                    className="text-[#0088cc] no-underline font-bold">
                    @{TG_BOT}
                  </a>
                </p>

                <button onClick={handleDisconnect}
                  className="clay-btn px-4 py-2 text-[13px]"
                  style={{ background: '#fff1f1', color: '#dc2626', borderColor: '#dc2626' }}>
                  Disconnect
                </button>
              </div>
            )}

            {/* ── IDLE ── */}
            {phase === 'idle' && (
              <>
                <h3 className="text-[18px] font-bold mb-1">Get started — 2 steps</h3>
                <p className="text-[13px] text-[#5a5a5a] mb-6">Connect Telegram first, then Gmail. Takes 30 seconds.</p>

                {errorMsg && (
                  <div className="mb-4 rounded-xl border-2 border-[#ffb3b3] bg-[#fff1f1] px-4 py-3 text-[13px] text-[#dc2626] font-bold flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 flex-shrink-0" /> {errorMsg}
                  </div>
                )}

                <button onClick={handleConnectTelegram}
                  className="w-full flex items-center justify-center gap-3 py-3.5 rounded-xl font-bold text-[15px] mb-3 transition-all"
                  style={{ background: '#0088cc', color: '#fff', border: '2px solid #006ba1',
                    boxShadow: '3px 3px 0 #004d70', cursor: 'pointer', fontFamily: "'Space Mono', monospace" }}>
                  <TelegramIcon size={20} />
                  Step 1 — Connect Telegram
                </button>
                <p className="text-center text-[11px] text-[#5a5a5a] mb-5">
                  Opens @{TG_BOT} in Telegram. Just press Start.
                </p>

                <button disabled
                  className="w-full flex items-center justify-center gap-3 py-3.5 rounded-xl font-bold text-[14px] opacity-40 cursor-not-allowed"
                  style={{ background: '#f3f4f6', color: '#374151', border: '2px solid #d1d5db',
                    fontFamily: "'Space Mono', monospace" }}>
                  <GoogleIcon />
                  Step 2 — Connect Gmail
                </button>
                <p className="text-center text-[11px] text-[#9ca3af] mt-2">Available after Telegram is linked</p>
              </>
            )}

            {/* ── TG_PENDING: waiting for user to press /start ── */}
            {phase === 'tg_pending' && (
              <div className="text-center py-4">
                <div className="h-14 w-14 rounded-full flex items-center justify-center mx-auto mb-4"
                  style={{ background: '#e8f4fd', border: '2px solid #0088cc' }}>
                  <TelegramIcon size={28} />
                </div>
                <h3 className="text-[16px] font-bold mb-2">Waiting for Telegram...</h3>
                <p className="text-[13px] text-[#5a5a5a] mb-4">
                  Open the Telegram tab that just opened and press <strong>Start</strong>.
                </p>
                <div className="flex justify-center gap-1.5 mb-5">
                  {[0,1,2].map(i => (
                    <span key={i} className="h-2.5 w-2.5 rounded-full bg-[#0088cc]"
                      style={{ animation: `pulse 1.2s ${i * 0.2}s infinite` }} />
                  ))}
                </div>
                <a href={`https://t.me/${TG_BOT}?start=${tgToken}`} target="_blank" rel="noreferrer"
                  className="clay-btn px-4 py-2 text-[13px] inline-flex items-center gap-2 no-underline"
                  style={{ background: '#0088cc', color: '#fff', borderColor: '#006ba1' }}>
                  <TelegramIcon size={14} /> Open bot again
                </a>
                <p className="mt-4 text-[11px] text-[#9ca3af]">
                  This page will automatically advance once you press Start.
                </p>
              </div>
            )}

            {/* ── TG_LINKED: Telegram done, now connect Gmail ── */}
            {(phase === 'tg_linked' || phase === 'gmail_pending') && (
              <div>
                <div className="flex items-center gap-2 rounded-xl border-2 border-[#b3e5fc] bg-[#e8f4fd] px-4 py-3 text-[13px] text-[#0277bd] font-bold mb-5">
                  <TelegramIcon size={15} />
                  Telegram connected! Now connect Gmail.
                </div>

                {errorMsg && (
                  <div className="mb-4 rounded-xl border-2 border-[#ffb3b3] bg-[#fff1f1] px-4 py-3 text-[13px] text-[#dc2626] font-bold flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 flex-shrink-0" /> {errorMsg}
                  </div>
                )}

                <h3 className="text-[17px] font-bold mb-1">Connect Gmail</h3>
                <p className="text-[13px] text-[#5a5a5a] mb-5">
                  Sign in with Google. Read-only access — we cannot write or delete emails.
                </p>

                <button onClick={handleConnectGmail} disabled={phase === 'gmail_pending'}
                  className="w-full flex items-center justify-center gap-3 py-3.5 rounded-xl font-bold text-[14px] transition-all"
                  style={{ background: '#fff', border: '2px solid #dadce0',
                    boxShadow: '0 2px 4px rgba(0,0,0,0.15)', cursor: phase === 'gmail_pending' ? 'wait' : 'pointer',
                    color: '#3c4043', fontFamily: "'Space Mono', monospace", opacity: phase === 'gmail_pending' ? 0.75 : 1 }}>
                  {phase === 'gmail_pending' ? (
                    <><span className="w-5 h-5 border-2 border-[#dadce0] border-t-[#4285F4] rounded-full animate-spin" /> Redirecting to Google...</>
                  ) : (
                    <><GoogleIcon /> Connect with Google</>
                  )}
                </button>
                <p className="text-center text-[11px] text-[#5a5a5a] mt-2">
                  You&apos;ll sign in directly with Google. Your password never touches our servers.
                </p>
              </div>
            )}
          </div>

          {/* Right column */}
          <div className="sm:col-span-2 flex flex-col gap-4">

            {/* Sample Telegram alert */}
            <div className="clay p-5">
              <p className="text-[11px] font-bold uppercase tracking-[0.1em] text-[#5a5a5a] mb-3">Sample Telegram alert</p>
              <div className="rounded-xl p-4" style={{ background: '#e8f4fd', border: '1.5px solid #b3d9f0' }}>
                <div className="flex items-center gap-2 mb-2">
                  <div className="h-8 w-8 rounded-full bg-[#0088cc] flex items-center justify-center flex-shrink-0">
                    <TelegramIcon size={16} />
                  </div>
                  <div>
                    <div className="text-[13px] font-bold text-[#1a1a1a]">phishfilter_bot</div>
                    <div className="text-[10px] text-[#5a5a5a]">just now</div>
                  </div>
                </div>
                <div className="text-[13px] leading-[1.65] text-[#1a1a1a]" style={{ fontFamily: 'sans-serif' }}>
                  🚨 <strong>PhishFilter Pro</strong><br /><br />
                  <strong>DANGEROUS — DO NOT open</strong><br /><br />
                  📧 From: <code style={{fontSize:11}}>security@paypaI-secure.ru</code><br />
                  📌 Subject: <em>Urgent account verification</em><br /><br />
                  🔴 Risk score: <strong>82/100</strong><br /><br />
                  <em>This email pretends to be from PayPal. The sender domain uses a fake lookalike letter. Do not click any links.</em><br /><br />
                  Red flags:<br />
                  • Fake domain (paypaI ≠ paypal)<br />
                  • Asks for account credentials<br />
                  • Urgency tactic<br /><br />
                  ❌ Do NOT click any links in this email.
                </div>
              </div>
            </div>

            {/* Trust badges */}
            <div className="clay p-5">
              <p className="text-[11px] font-bold uppercase tracking-[0.1em] text-[#5a5a5a] mb-3">Privacy & security</p>
              <ul className="space-y-2.5">
                {[
                  { icon: Lock,        text: 'Read-only Gmail — cannot send or delete' },
                  { icon: Shield,      text: 'Bot only sends to you — reads nothing' },
                  { icon: Zap,         text: 'Checks inbox every 2 minutes' },
                  { icon: CheckCircle, text: 'Revoke Gmail access anytime in Google' },
                  { icon: Globe,       text: 'No passwords stored anywhere' },
                ].map(({ icon: Icon, text }) => (
                  <li key={text} className="flex items-center gap-2.5 text-[12px]">
                    <Icon className="h-3.5 w-3.5 text-[#16a34a] flex-shrink-0" />
                    {text}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </section>

        {/* FAQ */}
        <section className="mx-auto max-w-[800px] mb-12">
          <h2 className="text-[20px] font-bold mb-6 text-center">Frequently asked questions</h2>
          <div className="space-y-3">
            {faqs.map((faq, i) => (
              <div key={i} className="clay overflow-hidden">
                <button onClick={() => setFaqOpen(faqOpen === i ? null : i)}
                  className="w-full flex items-center gap-3 px-5 py-4 text-left bg-transparent border-none cursor-pointer"
                  style={{ fontFamily: "'Space Mono', monospace" }}>
                  <span className="flex-1 text-[14px] font-bold">{faq.q}</span>
                  <span className="text-[18px] text-[#5a5a5a] flex-shrink-0"
                    style={{ transform: faqOpen === i ? 'rotate(45deg)' : 'none', transition: 'transform .15s' }}>+</span>
                </button>
                {faqOpen === i && (
                  <div className="px-5 pb-4 text-[13px] text-[#5a5a5a] leading-relaxed border-t-2 border-[#1a1a1a] pt-3">
                    {faq.a}
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>

        {/* CTA */}
        <section className="mx-auto max-w-[800px] p-8 text-white text-center"
          style={{ background: '#16a34a', border: '2px solid #1a1a1a', borderRadius: '16px', boxShadow: '4px 4px 0px #1a1a1a' }}>
          <h2 className="text-[24px] font-bold mb-3">Start protecting your inbox today</h2>
          <p className="text-[14px] mb-6" style={{ color: 'rgba(255,255,255,0.85)' }}>
            Free forever. No credit card. No browser extension needed. Works with any Gmail.
          </p>
          <button onClick={() => { window.scrollTo({ top: 500, behavior: 'smooth' }); if (phase === 'idle') handleConnectTelegram(); }}
            className="clay-btn px-6 py-3 text-[14px] font-bold inline-flex items-center gap-2"
            style={{ background: '#fff', color: '#16a34a', borderColor: '#fff' }}>
            <TelegramIcon size={16} />
            Connect Telegram &amp; Gmail
            <ArrowRight className="h-4 w-4" />
          </button>
        </section>

      </main>
    </div>
  )
}

export default function SafeMailsPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-[#f5f0e8] flex items-center justify-center"
        style={{ fontFamily: "'Space Mono', monospace" }}>
        <div className="text-[14px] text-[#5a5a5a]">Loading...</div>
      </div>
    }>
      <SafeMailsContent />
    </Suspense>
  )
}
