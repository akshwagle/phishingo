'use client'
import { useEffect, useState } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import { Shield, Mail, MessageSquare, Bell, CheckCircle, AlertTriangle, ArrowRight, Zap, Lock, Globe, RefreshCw } from 'lucide-react'
import { Suspense } from 'react'

const BACKEND = process.env.NEXT_PUBLIC_BACKEND_URL || 'https://phishingo-production.up.railway.app'

// ── Google button SVG ────────────────────────────────────────────────────────
function GoogleIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 48 48" aria-hidden="true">
      <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
      <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
      <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
      <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
      <path fill="none" d="M0 0h48v48H0z"/>
    </svg>
  )
}

// ── Main page component (needs Suspense for useSearchParams) ─────────────────
function SafeMailsContent() {
  const searchParams = useSearchParams()
  const [whatsapp, setWhatsapp] = useState('')
  const [loading, setLoading] = useState(false)
  const [errorMsg, setErrorMsg] = useState('')
  const [faqOpen, setFaqOpen] = useState<number | null>(null)

  // Status from OAuth callback redirect
  const [status, setStatus] = useState<'idle' | 'connected' | 'error'>('idle')
  const [connectedEmail, setConnectedEmail] = useState('')
  const [sessionId, setSessionId] = useState('')
  const [stats, setStats] = useState({ alerts_sent: 0, emails_scanned: 0 })

  // Read query params on mount (set by OAuth callback)
  useEffect(() => {
    const s = searchParams.get('status')
    const err = searchParams.get('error')
    const sess = searchParams.get('session')
    const em = searchParams.get('email')

    if (s === 'connected' && sess) {
      setStatus('connected')
      setSessionId(sess)
      setConnectedEmail(decodeURIComponent(em || ''))
      // Restore whatsapp from localStorage
      const saved = localStorage.getItem('pfp_whatsapp')
      if (saved) setWhatsapp(saved)
    } else if (err) {
      setStatus('error')
      setErrorMsg(err === 'cancelled' ? 'Google sign-in was cancelled.' : `Authentication failed: ${err}`)
    }
  }, [searchParams])

  // Poll stats when connected
  useEffect(() => {
    if (status !== 'connected' || !sessionId) return
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${BACKEND}/api/safe-mails/status/${sessionId}`)
        if (res.ok) {
          const d = await res.json()
          setStats({ alerts_sent: d.alerts_sent, emails_scanned: d.emails_scanned })
        }
      } catch { /* ignore */ }
    }, 10000)
    return () => clearInterval(interval)
  }, [status, sessionId])

  async function handleConnectGoogle() {
    if (!whatsapp.trim()) {
      setErrorMsg('Enter your WhatsApp number first.')
      return
    }
    const wp = whatsapp.trim().replace(/\s+/g, '')
    if (!wp.startsWith('+')) {
      setErrorMsg('Include country code (e.g. +91 or +1)')
      return
    }

    setErrorMsg('')
    setLoading(true)

    // Save whatsapp so we can restore after OAuth redirect
    localStorage.setItem('pfp_whatsapp', wp)

    try {
      const res = await fetch(`${BACKEND}/api/safe-mails/auth-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ whatsapp: wp }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed to get auth URL')
      // Redirect to Google OAuth
      window.location.href = data.auth_url
    } catch (err: unknown) {
      setLoading(false)
      setErrorMsg(err instanceof Error ? err.message : 'Could not connect to backend.')
    }
  }

  async function handleDisconnect() {
    if (!sessionId) return
    try {
      await fetch(`${BACKEND}/api/safe-mails/disconnect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId }),
      })
    } catch { /* ignore */ }
    setStatus('idle')
    setSessionId('')
    setConnectedEmail('')
    setStats({ alerts_sent: 0, emails_scanned: 0 })
    localStorage.removeItem('pfp_whatsapp')
    // Clear query params
    window.history.replaceState({}, '', '/safe-mails')
  }

  const faqs = [
    { q: 'What permissions does Google grant?', a: 'Read-only access to Gmail. We request only the gmail.readonly scope — we cannot send emails, delete them, or access anything outside Gmail.' },
    { q: 'Is this secure?', a: 'Yes. We use Google OAuth 2.0 — you sign in with Google directly, your password never touches our servers. We receive a read-only access token that you can revoke anytime in your Google Account → Security → Third-party apps.' },
    { q: 'How fast are WhatsApp alerts?', a: 'We check your inbox every 2 minutes. When a suspicious email arrives, we analyze it in 5-15 seconds and immediately send a WhatsApp message.' },
    { q: 'Which emails trigger an alert?', a: 'Only emails scoring 30+ on our risk scale. Safe, legitimate emails are silently marked clean — no notification noise.' },
    { q: 'How do I revoke access?', a: 'Click Disconnect on this page, or go to myaccount.google.com → Security → Third-party apps → PhishFilter Pro → Remove access.' },
    { q: 'Does it work on mobile?', a: 'Yes. We monitor Gmail regardless of what device you use to read mail. WhatsApp alerts go to any phone.' },
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
            <span className="text-[16px] font-bold text-[#1a1a1a]">
              PhishFilter <span className="text-[#4f46e5]">Pro</span>
            </span>
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
            <span className="h-2 w-2 rounded-full bg-[#16a34a]" /> Free · Read-only access · No passwords stored
          </div>
          <h1 className="text-[34px] sm:text-[42px] font-bold leading-[1.15] mb-5">
            Never miss a phishing email.<br />
            <span className="text-[#16a34a]">Get WhatsApp alerts instantly.</span>
          </h1>
          <p className="text-[16px] text-[#5a5a5a] leading-relaxed max-w-[580px] mx-auto">
            Connect your Gmail with one click. We scan every incoming email using 10 forensic engines and 5 AI models.
            The moment something suspicious arrives, your WhatsApp gets a plain-English alert.
          </p>
        </section>

        {/* How it works */}
        <section className="mx-auto max-w-[800px] mb-12">
          <h2 className="text-[20px] font-bold mb-6 text-center">How it works</h2>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[
              { icon: Mail, color: '#4f46e5', bg: '#eff4ff', num: '1', title: 'Connect Gmail', desc: 'Click "Connect with Google" and sign in. We get read-only access. No passwords, no inbox writing.' },
              { icon: Zap, color: '#d97706', bg: '#fffbee', num: '2', title: 'We scan every email', desc: 'Every 2 minutes we check for new emails and run the full 10-engine analysis — URL forensics, homograph detection, and 5 AI models.' },
              { icon: MessageSquare, color: '#16a34a', bg: '#f0fff6', num: '3', title: 'WhatsApp alert', desc: 'Risk score 30+? Instant WhatsApp message with the verdict, score, and the top red flags in plain English.' },
            ].map(({ icon: Icon, color, bg, num, title, desc }) => (
              <div key={num} className="clay p-5">
                <div className="flex items-center gap-3 mb-3">
                  <div className="h-9 w-9 rounded-xl flex items-center justify-center flex-shrink-0"
                    style={{ background: bg, border: `2px solid ${color}` }}>
                    <Icon className="h-4 w-4" style={{ color }} />
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

        {/* Main connect section */}
        <section className="mx-auto max-w-[800px] grid grid-cols-1 sm:grid-cols-5 gap-6 mb-12">

          {/* Connect card */}
          <div className="clay sm:col-span-3 p-6">
            {status === 'connected' ? (
              /* ── Connected state ── */
              <div>
                <div className="flex items-center gap-3 mb-5">
                  <div className="h-10 w-10 rounded-full flex items-center justify-center"
                    style={{ background: '#dcfce7', border: '2px solid #16a34a' }}>
                    <CheckCircle className="h-5 w-5 text-[#16a34a]" />
                  </div>
                  <div>
                    <div className="text-[15px] font-bold text-[#16a34a]">Connected</div>
                    <div className="text-[12px] text-[#5a5a5a]">{connectedEmail}</div>
                  </div>
                </div>

                {/* Live stats */}
                <div className="grid grid-cols-2 gap-3 mb-5">
                  <div className="clay p-4 text-center" style={{ background: '#f0fff6' }}>
                    <div className="text-[24px] font-bold text-[#16a34a]">{stats.emails_scanned}</div>
                    <div className="text-[11px] text-[#5a5a5a] font-bold">Emails scanned</div>
                  </div>
                  <div className="clay p-4 text-center" style={{ background: stats.alerts_sent > 0 ? '#fff1f1' : '#f9fafb' }}>
                    <div className={`text-[24px] font-bold ${stats.alerts_sent > 0 ? 'text-[#dc2626]' : 'text-[#1a1a1a]'}`}>
                      {stats.alerts_sent}
                    </div>
                    <div className="text-[11px] text-[#5a5a5a] font-bold">WhatsApp alerts sent</div>
                  </div>
                </div>

                <div className="rounded-xl border-2 border-[#b3f0c8] bg-[#f0fff6] px-4 py-3 text-[13px] text-[#166534] font-bold flex items-center gap-2 mb-5">
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  Checking inbox every 2 minutes
                </div>

                <p className="text-[12px] text-[#5a5a5a] mb-3">
                  WhatsApp alerts going to: <strong>{whatsapp || localStorage?.getItem('pfp_whatsapp') || 'your number'}</strong>
                </p>

                <button
                  onClick={handleDisconnect}
                  className="clay-btn px-4 py-2 text-[13px]"
                  style={{ background: '#fff1f1', color: '#dc2626', borderColor: '#dc2626' }}
                >
                  Disconnect Gmail
                </button>
              </div>
            ) : (
              /* ── Connect form ── */
              <>
                <h3 className="text-[18px] font-bold mb-1">Connect your Gmail</h3>
                <p className="text-[13px] text-[#5a5a5a] mb-6">
                  Sign in with Google — takes 10 seconds. We only get read-only access.
                </p>

                {/* WhatsApp number input */}
                <div className="mb-5">
                  <label className="block text-[13px] font-bold mb-2">
                    Your WhatsApp number
                    <span className="text-[#5a5a5a] font-normal ml-2 text-[11px]">(include country code)</span>
                  </label>
                  <input
                    className="clay-input w-full h-12 px-4 text-[15px]"
                    type="tel"
                    placeholder="+91 98765 43210"
                    value={whatsapp}
                    onChange={e => setWhatsapp(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && handleConnectGoogle()}
                  />
                  <p className="mt-1.5 text-[11px] text-[#5a5a5a]">
                    Alerts sent via WhatsApp. Supports any country.
                  </p>
                </div>

                {errorMsg && (
                  <div className="mb-4 rounded-xl border-2 border-[#ffb3b3] bg-[#fff1f1] px-4 py-3 text-[13px] text-[#dc2626] font-bold flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                    {errorMsg}
                  </div>
                )}

                {/* Google Sign-In button */}
                <button
                  onClick={handleConnectGoogle}
                  disabled={loading}
                  className="w-full flex items-center justify-center gap-3 py-3.5 rounded-xl font-bold text-[14px] transition-all"
                  style={{
                    background: '#fff',
                    border: '2px solid #dadce0',
                    boxShadow: '0 2px 4px rgba(0,0,0,0.15)',
                    cursor: loading ? 'wait' : 'pointer',
                    opacity: loading ? 0.8 : 1,
                    color: '#3c4043',
                    fontFamily: "'Space Mono', monospace",
                  }}
                >
                  {loading ? (
                    <>
                      <span className="w-5 h-5 border-2 border-[#dadce0] border-t-[#4285F4] rounded-full animate-spin" />
                      Redirecting to Google...
                    </>
                  ) : (
                    <>
                      <GoogleIcon />
                      Connect with Google
                    </>
                  )}
                </button>

                <p className="mt-3 text-center text-[11px] text-[#5a5a5a]">
                  You&apos;ll be taken to Google&apos;s sign-in page. We never see your password.
                </p>
              </>
            )}
          </div>

          {/* Right column: preview + checklist */}
          <div className="sm:col-span-2 flex flex-col gap-4">
            {/* Sample WhatsApp alert */}
            <div className="clay p-5">
              <p className="text-[11px] font-bold uppercase tracking-[0.1em] text-[#5a5a5a] mb-3">Sample alert</p>
              <div className="rounded-xl p-4 text-[13px] leading-relaxed"
                style={{ background: '#e7f9e7', border: '1.5px solid #a8d5a2', fontFamily: 'sans-serif' }}>
                <div className="font-bold text-[#1a1a1a] mb-2" style={{ fontSize: 14 }}>PhishFilter Pro</div>
                <div className="text-[#1a1a1a]" style={{ fontSize: 13, lineHeight: 1.6 }}>
                  <strong>SUSPICIOUS EMAIL</strong><br /><br />
                  From: security@paypaI-secure.ru<br />
                  Subject: Urgent account verification<br /><br />
                  Risk: <strong>78/100</strong><br /><br />
                  Red flags:<br />
                  - Lookalike domain (paypaI vs paypal)<br />
                  - Credential request + urgency<br />
                  - Unknown sender domain<br /><br />
                  Do NOT click any links.
                </div>
                <div className="text-right text-[11px] text-[#5a5a5a] mt-2">Now · Delivered</div>
              </div>
            </div>

            {/* What we check */}
            <div className="clay p-5">
              <p className="text-[11px] font-bold uppercase tracking-[0.1em] text-[#5a5a5a] mb-3">What we check</p>
              <ul className="space-y-2">
                {[
                  'Sender domain reputation',
                  'Lookalike / homograph domains',
                  'Suspicious URLs in body',
                  'SPF / DKIM / DMARC headers',
                  'Urgency & credential request patterns',
                  '5 AI models in parallel',
                ].map(item => (
                  <li key={item} className="flex items-center gap-2 text-[13px]">
                    <CheckCircle className="h-3.5 w-3.5 text-[#16a34a] flex-shrink-0" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </section>

        {/* Trust badges */}
        <section className="mx-auto max-w-[800px] mb-12">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { icon: Lock,         label: 'No passwords stored',  sub: 'Google OAuth only' },
              { icon: Globe,        label: 'Read-only access',     sub: 'Cannot send or delete' },
              { icon: Zap,          label: '2-minute check',       sub: 'Near real-time alerts' },
              { icon: CheckCircle,  label: 'Revoke anytime',       sub: 'One click in Google' },
            ].map(({ icon: Icon, label, sub }) => (
              <div key={label} className="clay p-4 text-center">
                <Icon className="h-5 w-5 mx-auto mb-2 text-[#4f46e5]" />
                <div className="text-[13px] font-bold">{label}</div>
                <div className="text-[11px] text-[#5a5a5a] mt-0.5">{sub}</div>
              </div>
            ))}
          </div>
        </section>

        {/* FAQ */}
        <section className="mx-auto max-w-[800px] mb-12">
          <h2 className="text-[20px] font-bold mb-6 text-center">Frequently asked questions</h2>
          <div className="space-y-3">
            {faqs.map((faq, i) => (
              <div key={i} className="clay overflow-hidden">
                <button
                  onClick={() => setFaqOpen(faqOpen === i ? null : i)}
                  className="w-full flex items-center gap-3 px-5 py-4 text-left bg-transparent border-none cursor-pointer"
                  style={{ fontFamily: "'Space Mono', monospace" }}
                >
                  <span className="flex-1 text-[14px] font-bold text-[#1a1a1a]">{faq.q}</span>
                  <span className="text-[18px] text-[#5a5a5a] flex-shrink-0 transition-transform"
                    style={{ transform: faqOpen === i ? 'rotate(45deg)' : 'none' }}>+</span>
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

        {/* CTA footer */}
        <section
          className="mx-auto max-w-[800px] p-8 text-white text-center"
          style={{ background: '#16a34a', border: '2px solid #1a1a1a', borderRadius: '16px', boxShadow: '4px 4px 0px #1a1a1a' }}
        >
          <h2 className="text-[24px] font-bold mb-3">Start protecting your inbox today</h2>
          <p className="text-[14px] mb-6" style={{ color: 'rgba(255,255,255,0.85)' }}>
            Free forever. No credit card. Works with any Gmail account.
          </p>
          <button
            onClick={() => window.scrollTo({ top: 500, behavior: 'smooth' })}
            className="clay-btn px-6 py-3 text-[14px] font-bold"
            style={{ background: '#fff', color: '#16a34a', borderColor: '#fff' }}
          >
            Connect with Google
            <ArrowRight className="h-4 w-4 inline ml-1.5" />
          </button>
        </section>

      </main>
    </div>
  )
}

// Suspense wrapper required because useSearchParams() is used
export default function SafeMailsPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-[#f5f0e8] flex items-center justify-center" style={{ fontFamily: "'Space Mono', monospace" }}>
        <div className="text-[14px] text-[#5a5a5a]">Loading...</div>
      </div>
    }>
      <SafeMailsContent />
    </Suspense>
  )
}
