'use client'
import Link from 'next/link'
import { useState, useRef } from 'react'
import {
  Shield, Globe, Lock, Mail, MousePointer, Bot,
  Download, ChevronDown, ChevronUp,
} from 'lucide-react'

const FONT = "'Space Mono', 'Courier New', monospace"

// ── Shared navbar (with Extension active) ─────────────────────────────────────
function Navbar() {
  return (
    <header
      className="h-14 bg-[#fffefb] border-b-2 border-[#1a1a1a]"
      style={{ boxShadow: '0 2px 0 #1a1a1a', fontFamily: FONT }}
    >
      <div className="mx-auto max-w-5xl h-full px-4 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5 no-underline">
          <div
            className="h-8 w-8 rounded-xl border-2 border-[#1a1a1a] bg-[#4f46e5] flex items-center justify-center"
            style={{ boxShadow: '2px 2px 0 #1a1a1a' }}
          >
            <Shield className="h-4 w-4 text-white" />
          </div>
          <span className="text-[16px] font-bold text-[#1a1a1a]">
            PhishFilter <span className="text-[#4f46e5]">Pro</span>
          </span>
        </Link>

        <nav className="hidden sm:flex items-center gap-5 text-[11px] font-bold">
          <Link href="/" className="text-[#5a5a5a] hover:text-[#4f46e5] no-underline transition-colors">Scanner</Link>
          <Link href="/features" className="text-[#5a5a5a] hover:text-[#4f46e5] no-underline transition-colors">Features</Link>
          <Link href="/extension" className="text-[#4f46e5] no-underline border-b-2 border-[#4f46e5] pb-0.5">Extension</Link>
        </nav>

        <div className="flex items-center gap-2 text-[11px] text-[#5a5a5a]">
          <span className="h-2 w-2 rounded-full bg-[#16a34a]" />
          <span className="hidden sm:inline">All engines online</span>
        </div>
      </div>
    </header>
  )
}

// ── FAQ item ──────────────────────────────────────────────────────────────────
function FaqItem({ q, a }: { q: string; a: string }) {
  const [open, setOpen] = useState(false)
  return (
    <div
      className="border-2 border-[#1a1a1a] rounded-xl overflow-hidden"
      style={{ boxShadow: '3px 3px 0 #1a1a1a', background: '#fffefb' }}
    >
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-5 py-4 text-left font-bold text-[13px] bg-transparent border-none cursor-pointer"
        style={{ fontFamily: FONT }}
      >
        <span>{q}</span>
        {open ? <ChevronUp className="h-4 w-4 text-[#5a5a5a] flex-shrink-0" /> : <ChevronDown className="h-4 w-4 text-[#5a5a5a] flex-shrink-0" />}
      </button>
      {open && (
        <div className="px-5 pb-5 text-[12px] text-[#5a5a5a] leading-relaxed border-t-2 border-[#1a1a1a] pt-4">
          {a}
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function ExtensionPage() {
  const installRef = useRef<HTMLElement>(null)

  const features = [
    {
      icon: Globe,
      title: 'Live page scanning',
      desc: 'Every page you visit is checked against threat feeds. Phishing sites get blocked before they load.',
      bg: '#b3c8ff',
    },
    {
      icon: MousePointer,
      title: 'Smart link preview',
      desc: 'Hover any link for 1 second to see where it actually leads — no more clicking blind on shortened URLs.',
      bg: '#ffe9a0',
    },
    {
      icon: Lock,
      title: 'Password sentinel',
      desc: 'If you start typing your password on a suspicious site, we instantly block keystrokes and show a warning.',
      bg: '#ffb3b3',
    },
    {
      icon: Mail,
      title: 'Gmail + Outlook integration',
      desc: 'One-click forensic scan on any email — runs the full 10-engine analysis without leaving your inbox.',
      bg: '#b3f0c8',
    },
    {
      icon: MousePointer,
      title: 'Selection scanner',
      desc: 'Right-click any text or link to instantly check if it\'s a scam — works on every website.',
      bg: '#d4b3ff',
    },
    {
      icon: Bot,
      title: 'AI ensemble verdict',
      desc: '5 AI models analyze suspicious content in parallel. Get a confidence score, not a black-box yes/no.',
      bg: '#ffd0a0',
    },
  ]

  const steps = [
    {
      n: 1,
      title: 'Download the .zip file',
      desc: 'Click the download button above. Unzip the file to a folder you\'ll keep — don\'t delete it later, the extension runs from this folder.',
    },
    {
      n: 2,
      title: 'Open Chrome extensions',
      desc: 'Type chrome://extensions in your address bar and hit enter. Or: Menu → More tools → Extensions.',
    },
    {
      n: 3,
      title: 'Enable Developer mode',
      desc: 'Toggle the "Developer mode" switch in the top right corner of the extensions page.',
    },
    {
      n: 4,
      title: 'Load the extension',
      desc: 'Click "Load unpacked" (top left). Select the folder you unzipped. Done — pin the shield icon to your toolbar.',
    },
  ]

  const faqs = [
    { q: 'Is it free?', a: 'Yes, 100% free and open source. No subscriptions, no premium tiers.' },
    { q: 'Do you collect my data?', a: 'No. All scans run through our transparent API. We don\'t track your browsing, we don\'t log which sites you visit, we don\'t sell data. We only receive the URL or text you explicitly ask us to scan.' },
    { q: 'Why isn\'t it on the Chrome Web Store?', a: 'It will be soon. For now, Developer mode is the fastest way to get it in your hands — takes 30 seconds and gives you the full feature set immediately.' },
    { q: 'Will it slow down my browser?', a: 'No. Page scans are async and cached for 10 minutes. Most quick checks complete in under 300ms. Your browsing experience is unaffected.' },
    { q: 'What if it blocks a site I trust?', a: 'Add it to your whitelist in the extension popup. Takes one click. Common trusted sites (Google, GitHub, LinkedIn, etc.) are already pre-whitelisted.' },
    { q: 'Does it work on mobile?', a: 'Chrome extensions are desktop-only. We\'re building a mobile app — send us an email to join the waitlist.' },
  ]

  return (
    <div className="min-h-screen bg-[#f5f0e8] text-[#1a1a1a]" style={{ fontFamily: FONT }}>
      <Navbar />

      {/* ── Hero ──────────────────────────────────────────────── */}
      <section className="mx-auto max-w-[660px] text-center px-4 pt-16 pb-10">
        <span
          className="inline-block px-3 py-1 rounded-full text-[11px] font-bold mb-5 border-2 border-[#1a1a1a]"
          style={{ background: '#f5f0e8', boxShadow: '2px 2px 0 #1a1a1a' }}
        >
          Free · Open source · No tracking
        </span>

        <h1
          className="text-[28px] sm:text-[34px] font-bold leading-[1.25] mb-5"
          style={{ maxWidth: 600, margin: '0 auto 20px' }}
        >
          Real-time phishing protection<br className="hidden sm:block" /> in your browser
        </h1>

        <p className="text-[14px] text-[#5a5a5a] leading-relaxed mb-8 mx-auto" style={{ maxWidth: 520 }}>
          Scan emails, links, and entire web pages instantly. PhishFilter Pro blocks phishing sites
          before you can enter your password.
        </p>

        <a
          href="/phishfilter-extension.zip"
          download
          className="inline-flex items-center gap-2 px-6 py-4 rounded-xl font-bold text-[15px] text-white no-underline border-2 border-[#1a1a1a]"
          style={{ background: '#4f46e5', boxShadow: '4px 4px 0 #1a1a1a' }}
        >
          <Download className="h-5 w-5" />
          Download extension (.zip)
        </a>

        <p className="text-[11px] text-[#9ca3af] mt-3">
          Compatible with Chrome, Edge, Brave · v1.0 · ~2.4 MB
        </p>

        <button
          onClick={() => installRef.current?.scrollIntoView({ behavior: 'smooth' })}
          className="text-[12px] text-[#4f46e5] mt-3 font-bold bg-transparent border-none cursor-pointer underline"
          style={{ fontFamily: FONT }}
        >
          Or get install instructions ↓
        </button>
      </section>

      {/* ── Features grid ─────────────────────────────────────── */}
      <section className="mx-auto max-w-[960px] px-4 pb-16">
        <h2 className="text-[18px] font-bold text-center mb-8">Everything you need to stay safe</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
          {features.map((f) => (
            <div
              key={f.title}
              className="p-5 rounded-xl border-2 border-[#1a1a1a]"
              style={{ background: '#fffefb', boxShadow: '4px 4px 0 #1a1a1a' }}
            >
              <div
                className="h-10 w-10 rounded-xl border-2 border-[#1a1a1a] flex items-center justify-center mb-4"
                style={{ background: f.bg, boxShadow: '2px 2px 0 #1a1a1a' }}
              >
                <f.icon className="h-5 w-5 text-[#1a1a1a]" />
              </div>
              <h3 className="text-[13px] font-bold mb-2">{f.title}</h3>
              <p className="text-[12px] text-[#5a5a5a] leading-relaxed">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── Install steps ──────────────────────────────────────── */}
      <section
        ref={installRef}
        className="mx-auto max-w-[720px] px-4 pb-16"
        id="install"
      >
        <h2 className="text-[18px] font-bold text-center mb-2">Install in 30 seconds</h2>
        <p className="text-center text-[12px] text-[#5a5a5a] mb-8">No account required. No sign-up. Just download and load.</p>
        <div className="flex flex-col gap-5">
          {steps.map((step) => (
            <div
              key={step.n}
              className="flex flex-col sm:flex-row gap-5 p-5 rounded-xl border-2 border-[#1a1a1a]"
              style={{ background: '#fffefb', boxShadow: '4px 4px 0 #1a1a1a' }}
            >
              {/* Left: step number + text */}
              <div className="flex gap-4 sm:w-[52%] flex-shrink-0">
                <div
                  className="h-9 w-9 rounded-full border-2 border-[#1a1a1a] bg-[#4f46e5] flex items-center justify-center flex-shrink-0 text-white font-bold text-[13px]"
                  style={{ boxShadow: '2px 2px 0 #1a1a1a' }}
                >
                  {step.n}
                </div>
                <div>
                  <h3 className="text-[13px] font-bold mb-2">{step.title}</h3>
                  <p className="text-[12px] text-[#5a5a5a] leading-relaxed">{step.desc}</p>
                </div>
              </div>

              {/* Right: screenshot */}
              <div className="flex-1 flex items-center justify-center">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={`/screenshots/step${step.n}.png`}
                  alt={`Install step ${step.n}: ${step.title}`}
                  className="w-full rounded-xl border-2 border-[#1a1a1a] object-cover"
                  style={{ boxShadow: '2px 2px 0 #1a1a1a', aspectRatio: '16/9' }}
                />
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── FAQ ───────────────────────────────────────────────── */}
      <section className="mx-auto max-w-[660px] px-4 pb-16">
        <h2 className="text-[18px] font-bold text-center mb-8">Frequently asked questions</h2>
        <div className="flex flex-col gap-3">
          {faqs.map((faq) => (
            <FaqItem key={faq.q} q={faq.q} a={faq.a} />
          ))}
        </div>
      </section>

      {/* ── CTA footer ────────────────────────────────────────── */}
      <section
        className="py-16 text-center text-white"
        style={{
          background: '#4f46e5',
          borderTop: '2px solid #1a1a1a',
        }}
      >
        <h2 className="text-[22px] font-bold mb-3">Ready to never click a phish again?</h2>
        <p className="text-[13px] mb-8 opacity-80">
          Join thousands of users protected by PhishFilter Pro every day.
        </p>
        <a
          href="/phishfilter-extension.zip"
          download
          className="inline-flex items-center gap-2 px-6 py-4 rounded-xl font-bold text-[14px] text-[#4f46e5] no-underline border-2 border-[#1a1a1a]"
          style={{ background: '#fff', boxShadow: '4px 4px 0 rgba(0,0,0,0.3)' }}
        >
          <Download className="h-5 w-5" />
          Download for Chrome
        </a>
      </section>
    </div>
  )
}
