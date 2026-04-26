'use client'
import Link from 'next/link'
import { Shield, ShieldCheck, Link2, Eye, Globe, Cpu, Radar, FlaskConical, FormInput, Wifi } from 'lucide-react'

const features = [
  { icon: ShieldCheck,  title: 'Header forensics',           desc: 'SPF, DKIM, DMARC and sender mismatch checks in one plain-language view.', bg: 'clay-blue' },
  { icon: Link2,        title: 'URL forensics',              desc: 'Expands, normalizes, and validates suspicious links before anyone clicks.', bg: 'clay-purple' },
  { icon: Eye,          title: 'Homograph detection',        desc: 'Detects lookalike domains using Unicode confusable character analysis.',   bg: 'clay-red' },
  { icon: Radar,        title: 'Typosquat detection',        desc: 'Finds brand-imitating domains built to capture passwords and OTP codes.',  bg: 'clay-orange' },
  { icon: Globe,        title: 'Domain intelligence',        desc: 'Evaluates domain age, registrar patterns, and infrastructure anomalies.',  bg: 'clay-yellow' },
  { icon: Cpu,          title: '5-model AI ensemble',        desc: 'Independent model consensus explains risk in simple language.',            bg: 'clay-green' },
  { icon: Radar,        title: 'Threat intel cross-check',   desc: 'Compares indicators against known phishing and malware data sources.',     bg: 'clay-red' },
  { icon: FlaskConical, title: 'Sandboxed preview',          desc: 'Inspects risky URLs and forms in an isolated environment.',               bg: 'clay-blue' },
  { icon: FormInput,    title: 'Form sentinel (extension)',  desc: 'Warns before sensitive data is entered into suspicious login forms.',      bg: 'clay-purple' },
  { icon: Wifi,         title: 'Real-time protection',       desc: 'Live Gmail and browser protections for everyday non-technical users.',     bg: 'clay-green' },
]

export default function FeaturesPage() {
  return (
    <div className="min-h-screen bg-[#f5f0e8]" style={{ fontFamily: "'Space Mono', monospace" }}>

      {/* Navbar */}
      <header className="h-14 bg-[#fffefb] border-b-2 border-[#1a1a1a]"
        style={{ boxShadow: '0 2px 0 #1a1a1a' }}>
        <div className="mx-auto flex h-full max-w-5xl items-center justify-between px-4">
          <Link href="/" className="flex items-center gap-2.5 no-underline">
            <div className="h-8 w-8 rounded-xl border-2 border-[#1a1a1a] bg-[#4f46e5] flex items-center justify-center"
              style={{ boxShadow: '2px 2px 0 #1a1a1a' }}>
              <Shield className="h-4 w-4 text-white" />
            </div>
            <span className="text-[16px] font-bold text-[#1a1a1a]">
              PhishFilter <span className="text-[#4f46e5]">Pro</span>
            </span>
          </Link>
          <nav className="hidden sm:flex items-center gap-5 text-[11px] font-bold">
            <Link href="/" className="text-[#5a5a5a] hover:text-[#4f46e5] no-underline transition-colors">Scanner</Link>
            <Link href="/features" className="text-[#4f46e5] border-b-2 border-[#4f46e5] pb-0.5 no-underline">Features</Link>
            <Link href="/extension" className="text-[#5a5a5a] hover:text-[#4f46e5] no-underline transition-colors">Extension</Link>
          </nav>
          <Link href="/" className="clay-btn bg-[#b3c8ff] text-[#1a1a1a] px-3 py-2 text-[11px] hidden sm:inline-flex">
            Back to scanner
          </Link>
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-4 py-10">
        <div className="mx-auto max-w-2xl">
          <h1 className="text-[26px] sm:text-[30px] font-bold leading-[1.25] text-[#1a1a1a]">
            Professional phishing defense,<br className="hidden sm:block" /> designed for clarity
          </h1>
          <p className="mt-3 text-[13px] text-[#5a5a5a] leading-relaxed">
            Every scan combines deterministic forensic checks with AI interpretation so teams and individuals can make fast, confident decisions.
          </p>
        </div>

        <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((feature) => {
            const Icon = feature.icon
            return (
              <div key={feature.title} className={`clay ${feature.bg} p-5`}>
                <div className="h-9 w-9 rounded-xl border-2 border-[#1a1a1a] bg-[#fffefb] flex items-center justify-center"
                  style={{ boxShadow: '2px 2px 0 #1a1a1a' }}>
                  <Icon className="h-4 w-4 text-[#4f46e5]" />
                </div>
                <h3 className="mt-3 text-[14px] font-bold text-[#1a1a1a]">{feature.title}</h3>
                <p className="mt-1.5 text-[12px] leading-relaxed text-[#5a5a5a]">{feature.desc}</p>
              </div>
            )
          })}
        </div>
      </main>
    </div>
  )
}
