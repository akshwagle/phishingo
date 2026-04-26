'use client'
import { useState } from 'react'
import Link from 'next/link'
import { Shield, Mail, MessageSquare, Bell, CheckCircle, AlertTriangle, ArrowRight, Zap, Lock, Globe } from 'lucide-react'

const BACKEND = process.env.NEXT_PUBLIC_BACKEND_URL || 'https://phishingo-production.up.railway.app'

type Step = 'idle' | 'connecting' | 'connected' | 'error'

export default function SafeMailsPage() {
  const [email, setEmail] = useState('')
  const [appPassword, setAppPassword] = useState('')
  const [whatsapp, setWhatsapp] = useState('')
  const [step, setStep] = useState<Step>('idle')
  const [errorMsg, setErrorMsg] = useState('')
  const [sessionId, setSessionId] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [faqOpen, setFaqOpen] = useState<number | null>(null)

  async function handleConnect() {
    if (!email.trim()) return setErrorMsg('Enter your Gmail address.')
    if (!appPassword.trim()) return setErrorMsg('Enter your Gmail App Password.')
    if (!whatsapp.trim()) return setErrorMsg('Enter your WhatsApp number.')

    // Basic validation
    if (!email.includes('@')) return setErrorMsg('Enter a valid email address.')
    const wpClean = whatsapp.replace(/\s+/g, '').replace(/^0/, '+91')
    if (!wpClean.startsWith('+')) return setErrorMsg('Include country code in WhatsApp number (e.g. +91...)')

    setStep('connecting')
    setErrorMsg('')

    try {
      const res = await fetch(`${BACKEND}/api/safe-mails/connect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim(), app_password: appPassword.trim(), whatsapp: wpClean }),
      })

      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Connection failed')

      setSessionId(data.session_id || 'connected')
      setStep('connected')
    } catch (err: unknown) {
      setStep('error')
      setErrorMsg(err instanceof Error ? err.message : 'Could not connect. Check your credentials.')
    }
  }

  const faqs = [
    {
      q: 'What is a Gmail App Password?',
      a: 'An App Password is a 16-character code that allows apps to access your Gmail securely without using your main password. Enable it at myaccount.google.com → Security → 2-Step Verification → App passwords.',
    },
    {
      q: 'Is my password stored?',
      a: 'No. Your App Password is used only to connect to Gmail via IMAP. It is stored encrypted and only used to read new emails. You can revoke it anytime from your Google Account.',
    },
    {
      q: 'How fast are WhatsApp alerts?',
      a: 'We check your inbox every 2 minutes. When a new email arrives, we analyze it (takes 5-15 seconds) and immediately send you a WhatsApp alert if anything suspicious is detected.',
    },
    {
      q: 'Will I get alerts for safe emails too?',
      a: 'No. We only send alerts for emails that score above 30/100 on our risk scale. Safe, legitimate emails are silently marked clean — no notification noise.',
    },
    {
      q: 'Which WhatsApp number receives alerts?',
      a: 'The number you enter here. Make sure to include your country code (e.g. +91 for India, +1 for US). We send via the Twilio WhatsApp API.',
    },
    {
      q: 'How do I stop monitoring?',
      a: 'Click "Disconnect" on this page at any time. All stored credentials are immediately deleted and monitoring stops.',
    },
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
            <span className="h-2 w-2 rounded-full bg-[#16a34a]" /> Free · No tracking · Instant alerts
          </div>
          <h1 className="text-[34px] sm:text-[42px] font-bold leading-[1.15] mb-5">
            Never miss a phishing email.<br />
            <span className="text-[#16a34a]">Get WhatsApp alerts instantly.</span>
          </h1>
          <p className="text-[16px] text-[#5a5a5a] leading-relaxed max-w-[560px] mx-auto">
            Connect your Gmail account. We monitor every incoming email with 10 forensic engines and 5 AI models.
            When something suspicious arrives, you get a simple WhatsApp message — before you even open it.
          </p>
        </section>

        {/* How it works */}
        <section className="mx-auto max-w-[800px] mb-12">
          <h2 className="text-[20px] font-bold mb-6 text-center">How it works</h2>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[
              { icon: Mail, color: '#4f46e5', bg: '#eff4ff', num: '1', title: 'Connect Gmail', desc: 'Enter your Gmail address and an App Password. We connect via secure IMAP — no OAuth, no permissions beyond reading.' },
              { icon: Zap, color: '#d97706', bg: '#fffbee', num: '2', title: 'We scan every email', desc: 'Every 2 minutes we check for new emails. Each one runs through homograph detection, URL forensics, and 5 AI models.' },
              { icon: MessageSquare, color: '#16a34a', bg: '#f0fff6', num: '3', title: 'WhatsApp alert', desc: 'If risk score > 30, you get a WhatsApp message with the verdict, score, and top red flags — in plain English.' },
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

        {/* Connection form or success */}
        <section className="mx-auto max-w-[800px] grid grid-cols-1 sm:grid-cols-5 gap-6 mb-12">

          {/* Form */}
          <div className="clay sm:col-span-3 p-6">
            {step === 'connected' ? (
              <div className="text-center py-6">
                <div className="h-14 w-14 rounded-full flex items-center justify-center mx-auto mb-4"
                  style={{ background: '#dcfce7', border: '2px solid #16a34a' }}>
                  <CheckCircle className="h-7 w-7 text-[#16a34a]" />
                </div>
                <h3 className="text-[18px] font-bold mb-2">Connected successfully</h3>
                <p className="text-[13px] text-[#5a5a5a] mb-2">Monitoring <strong>{email}</strong></p>
                <p className="text-[13px] text-[#5a5a5a] mb-6">WhatsApp alerts will be sent to <strong>{whatsapp}</strong></p>
                <div className="clay-badge bg-[#b3f0c8] text-[#1a1a1a] px-4 py-2 text-[12px] font-bold inline-block mb-6">
                  Checking inbox every 2 minutes
                </div>
                <div>
                  <button
                    onClick={() => { setStep('idle'); setSessionId(''); }}
                    className="clay-btn px-4 py-2 text-[13px] bg-[#fff1f1] text-[#dc2626]"
                    style={{ borderColor: '#dc2626' }}
                  >
                    Disconnect
                  </button>
                </div>
              </div>
            ) : (
              <>
                <h3 className="text-[17px] font-bold mb-1">Connect your Gmail</h3>
                <p className="text-[13px] text-[#5a5a5a] mb-5">Takes 30 seconds. Revoke access anytime.</p>

                <div className="space-y-4">
                  <div>
                    <label className="block text-[12px] font-bold mb-1.5">Gmail address</label>
                    <input
                      className="clay-input w-full h-11 px-3 text-[14px]"
                      type="email"
                      placeholder="you@gmail.com"
                      value={email}
                      onChange={e => setEmail(e.target.value)}
                    />
                  </div>

                  <div>
                    <label className="block text-[12px] font-bold mb-1.5">
                      Gmail App Password
                      <a
                        href="https://myaccount.google.com/apppasswords"
                        target="_blank"
                        rel="noreferrer"
                        className="ml-2 text-[#4f46e5] font-normal text-[11px] underline"
                      >
                        Get one here
                      </a>
                    </label>
                    <div className="relative">
                      <input
                        className="clay-input w-full h-11 px-3 pr-16 text-[14px]"
                        type={showPassword ? 'text' : 'password'}
                        placeholder="xxxx xxxx xxxx xxxx"
                        value={appPassword}
                        onChange={e => setAppPassword(e.target.value)}
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(p => !p)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-[11px] text-[#5a5a5a] font-bold bg-transparent border-none cursor-pointer"
                      >
                        {showPassword ? 'Hide' : 'Show'}
                      </button>
                    </div>
                    <p className="mt-1 text-[11px] text-[#5a5a5a]">Enable 2FA in Google, then create an App Password for "Mail".</p>
                  </div>

                  <div>
                    <label className="block text-[12px] font-bold mb-1.5">Your WhatsApp number</label>
                    <input
                      className="clay-input w-full h-11 px-3 text-[14px]"
                      type="tel"
                      placeholder="+91 98765 43210"
                      value={whatsapp}
                      onChange={e => setWhatsapp(e.target.value)}
                    />
                    <p className="mt-1 text-[11px] text-[#5a5a5a]">Include country code. Alerts sent via WhatsApp.</p>
                  </div>
                </div>

                {errorMsg && (
                  <div className="mt-4 rounded-xl border-2 border-[#ffb3b3] bg-[#fff1f1] px-4 py-2.5 text-[13px] text-[#dc2626] font-bold flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                    {errorMsg}
                  </div>
                )}

                <button
                  onClick={handleConnect}
                  disabled={step === 'connecting'}
                  className="clay-btn mt-5 w-full py-3.5 bg-[#16a34a] text-white text-[14px] flex items-center justify-center gap-2"
                  style={{ borderColor: '#166534' }}
                >
                  {step === 'connecting' ? (
                    <>
                      <span className="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      Connecting...
                    </>
                  ) : (
                    <>
                      <Bell className="h-4 w-4" />
                      Start monitoring
                      <ArrowRight className="h-4 w-4" />
                    </>
                  )}
                </button>
              </>
            )}
          </div>

          {/* Sample alert preview */}
          <div className="sm:col-span-2 flex flex-col gap-4">
            <div className="clay p-5">
              <p className="text-[11px] font-bold uppercase tracking-[0.1em] text-[#5a5a5a] mb-3">Sample WhatsApp alert</p>
              <div className="rounded-xl p-4 text-[13px] leading-relaxed"
                style={{ background: '#e7f9e7', border: '1.5px solid #a8d5a2', fontFamily: 'sans-serif' }}>
                <div className="font-bold text-[#1a1a1a] mb-1">PhishFilter Pro</div>
                <div className="text-[#1a1a1a]">
                  <strong>SUSPICIOUS EMAIL DETECTED</strong><br /><br />
                  From: security@paypaI-secure.ru<br />
                  Subject: Urgent account verification<br /><br />
                  Risk score: <strong>78/100</strong><br />
                  Red flags: Lookalike domain, urgent language, credential request<br /><br />
                  <a href="#" className="text-[#0066cc]" onClick={e => e.preventDefault()}>View full report</a>
                </div>
                <div className="text-right text-[11px] text-[#5a5a5a] mt-2">Now</div>
              </div>
            </div>

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
              { icon: Lock, label: 'Encrypted credentials', sub: 'AES-256 at rest' },
              { icon: Globe, label: 'IMAP only', sub: 'Read-only access' },
              { icon: Zap, label: '2-minute polling', sub: 'Near real-time' },
              { icon: CheckCircle, label: 'Revoke anytime', sub: 'One click disconnect' },
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
                  className="w-full flex items-center justify-content-between gap-3 px-5 py-4 text-left bg-transparent border-none cursor-pointer"
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
          style={{
            background: '#16a34a',
            border: '2px solid #1a1a1a',
            borderRadius: '16px',
            boxShadow: '4px 4px 0px #1a1a1a',
          }}
        >
          <h2 className="text-[24px] font-bold mb-3">Start protecting your inbox today</h2>
          <p className="text-[14px] mb-6" style={{ color: 'rgba(255,255,255,0.85)' }}>
            Free forever. No credit card. No browser extension needed.
          </p>
          <button
            onClick={() => window.scrollTo({ top: 400, behavior: 'smooth' })}
            className="clay-btn px-6 py-3 text-[14px] font-bold"
            style={{ background: '#fff', color: '#16a34a', borderColor: '#fff' }}
          >
            Connect Gmail now
          </button>
        </section>

      </main>
    </div>
  )
}
