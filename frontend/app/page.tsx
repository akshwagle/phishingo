'use client'
import { useEffect, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { Check, Shield, Upload, Zap, Lock, Activity, Clock, Download } from 'lucide-react'
import { DashboardResponse, LLM_MODELS, analyzeContent, getDashboard } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'

type Tab = 'email' | 'url' | 'text'

const samples = [
  { label: 'PayPal phish', kind: 'danger', tab: 'email', content: 'From: PayPal Security <security@paypaI-secure.ru>\nSubject: Urgent account review\n\nVerify now: http://paypaI-secure.ru/login' },
  { label: 'Homograph attack', kind: 'danger', tab: 'url', content: 'https://\u0430\u0440\u0440\u04a3\u0435id-login.com' },
  { label: 'Apple ID scam', kind: 'danger', tab: 'text', content: 'Your Apple ID was locked. Verify immediately to avoid account deletion.' },
  { label: 'Suspicious link', kind: 'warning', tab: 'url', content: 'https://billing-update-secure.top/verify' },
  { label: 'Legit GitHub email', kind: 'success', tab: 'email', content: 'From: notifications@github.com\nSubject: [GitHub] Pull request merged\n\nThis is a security notification for your repository.' },
] as const

const fallbackDashboard: DashboardResponse = {
  stats: { emails_scanned: 0, phishes_caught: 0, accuracy: 0, avg_scan_time_seconds: 0 },
  recent_scans: [],
}

const tabLabels: Record<Tab, string> = {
  email: 'Email',
  url:   'URL',
  text:  'Text / SMS',
}

const chipVariant = { danger: 'danger', warning: 'warning', success: 'success' } as const

export default function HomePage() {
  const router = useRouter()
  const [tab, setTab]           = useState<Tab>('email')
  const [content, setContent]   = useState('')
  const [urlInput, setUrlInput] = useState('')
  const [file, setFile]         = useState<File | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')
  const [dashboard, setDashboard] = useState<DashboardResponse>(fallbackDashboard)
  const [dashboardError, setDashboardError] = useState('')

  async function loadDashboard() {
    try {
      setDashboard(await getDashboard())
      setDashboardError('')
    } catch {
      setDashboardError('Live metrics unavailable — backend not running.')
    }
  }
  useEffect(() => { loadDashboard() }, [])

  async function runAnalysis() {
    setError('')
    let inputType: 'email' | 'url' | 'text' = 'text'
    let submitContent = ''

    if (tab === 'email') {
      // Email tab: prefer pasted content; otherwise use the uploaded .eml
      if (file && !content.trim()) {
        inputType = 'email'; submitContent = await file.text()
      } else if (content.trim()) {
        inputType = 'email'; submitContent = content.trim()
      } else {
        return setError('Paste an email or upload a .eml file first.')
      }
    } else if (tab === 'url') {
      if (!urlInput.trim()) return setError('Enter a URL before running analysis.')
      inputType = 'url'; submitContent = urlInput.trim()
    } else {
      if (!content.trim()) return setError('Paste suspicious text before running analysis.')
      inputType = 'text'; submitContent = content.trim()
    }

    setLoading(true)
    try {
      const report = await analyzeContent({ input_type: inputType, content: submitContent })
      sessionStorage.setItem(`pfp-report-${report.job_id}`, JSON.stringify(report))
      router.push(`/analyze/${report.job_id}`)
    } catch (e: unknown) {
      setError(`Could not analyze: ${e instanceof Error ? e.message : String(e)}`)
      setLoading(false)
    }
  }

  async function useSample(sample: (typeof samples)[number]) {
    setTab(sample.tab); setError(''); setFile(null)
    if (sample.tab === 'url') { setUrlInput(sample.content); setContent('') }
    else { setContent(sample.content); setUrlInput('') }

    // Call the API directly — avoids stale closure on `tab` state
    const inputType: 'email' | 'url' | 'text' =
      sample.tab === 'url' ? 'url' : sample.tab === 'email' ? 'email' : 'text'
    setLoading(true)
    try {
      const report = await analyzeContent({ input_type: inputType, content: sample.content })
      sessionStorage.setItem(`pfp-report-${report.job_id}`, JSON.stringify(report))
      router.push(`/analyze/${report.job_id}`)
    } catch (e: unknown) {
      setError(`Could not analyze: ${e instanceof Error ? e.message : String(e)}`)
      setLoading(false)
    }
  }

  const statCards = [
    { icon: Activity, label: 'Emails scanned', value: dashboard.stats.emails_scanned.toLocaleString(), color: 'text-[#4f46e5]', bg: 'clay-blue' },
    { icon: Zap,      label: 'Phishes caught', value: dashboard.stats.phishes_caught.toLocaleString(), color: 'text-[#dc2626]', bg: 'clay-red' },
    { icon: Check,    label: 'Accuracy',        value: `${dashboard.stats.accuracy.toFixed(1)}%`,     color: 'text-[#16a34a]', bg: 'clay-green' },
    { icon: Clock,    label: 'Avg scan time',   value: `${dashboard.stats.avg_scan_time_seconds.toFixed(1)}s`, color: 'text-[#d97706]', bg: 'clay-yellow' },
  ]

  return (
    <div className="min-h-screen bg-[#f5f0e8] text-[#1a1a1a]" style={{ fontFamily: "'Space Mono', monospace" }}>

      {/* ── Navbar ─────────────────────────────────────────── */}
      <header className="h-16 bg-[#fffefb] border-b-2 border-[#1a1a1a]"
        style={{ boxShadow: '0 2px 0 #1a1a1a' }}>
        <div className="mx-auto max-w-6xl h-full px-6 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3 no-underline">
            <div className="h-9 w-9 rounded-xl border-2 border-[#1a1a1a] bg-[#4f46e5] flex items-center justify-center"
              style={{ boxShadow: '2px 2px 0 #1a1a1a' }}>
              <Shield className="h-5 w-5 text-white" />
            </div>
            <span className="text-[18px] font-bold text-[#1a1a1a]">
              PhishFilter <span className="text-[#4f46e5]">Pro</span>
            </span>
          </Link>
          <nav className="hidden sm:flex items-center gap-6 text-[14px] font-bold">
            <Link href="/" className="text-[#4f46e5] border-b-2 border-[#4f46e5] pb-0.5 no-underline">Scanner</Link>
            <Link href="/features" className="text-[#3a3a3a] hover:text-[#4f46e5] no-underline transition-colors">Features</Link>
            <Link href="/extension" className="text-[#3a3a3a] hover:text-[#4f46e5] no-underline transition-colors">Extension</Link>
            <Link href="/safe-mails" className="text-[#3a3a3a] hover:text-[#4f46e5] no-underline transition-colors">Safe Mails</Link>
          </nav>
          <div className="flex items-center gap-2 text-[13px] text-[#3a3a3a]">
            <span className="h-2 w-2 rounded-full bg-[#16a34a]" />
            <span className="hidden sm:inline font-bold">All engines online</span>
            <span className="hidden md:inline-flex clay-badge bg-[#b3f0c8] text-[#1a1a1a] px-2.5 py-1 text-[11px] font-bold">
              5 AI models
            </span>
          </div>
        </div>
      </header>

      <main className="px-6 py-12">

        {/* ── Hero ───────────────────────────────────────────── */}
        <section className="mx-auto max-w-3xl text-center">
          <h1 className="text-[34px] sm:text-[42px] font-bold leading-[1.15]">
            Is this email trying to scam you?<br className="hidden sm:block" /> Find out in seconds.
          </h1>
          <p className="mx-auto mt-6 max-w-[640px] text-[17px] text-[#3a3a3a] leading-relaxed">
            Paste any email, URL, or suspicious text. 10 forensic engines and 5 AI models give you a definitive verdict with full evidence.
          </p>
          <div className="mt-7 flex flex-wrap items-center justify-center gap-x-5 gap-y-2.5 text-[14px] text-[#3a3a3a] font-bold">
            {['10 forensic engines', '5-model AI ensemble', 'Homograph detection', 'URL unshortening', 'Real-time threat intel'].map((t) => (
              <span key={t} className="flex items-center gap-1.5">
                <Check className="h-4 w-4 text-[#16a34a]" />{t}
              </span>
            ))}
          </div>
        </section>

        {/* ── Scanner card ───────────────────────────────────── */}
        <div className="clay mx-auto mt-10 max-w-[800px]">
          <div className="p-6">

            {/* Tabs */}
            <div className="grid grid-cols-3 gap-2">
              {(Object.keys(tabLabels) as Tab[]).map((t) => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={`clay-btn text-[15px] py-3 px-3 ${
                    tab === t
                      ? 'bg-[#4f46e5] text-white'
                      : 'bg-[#fffefb] text-[#3a3a3a]'
                  }`}
                >
                  {tabLabels[t]}
                </button>
              ))}
            </div>

            {/* Input area */}
            <div className="mt-5">
              {tab === 'email' && (
                <div
                  onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
                  onDragLeave={() => setDragOver(false)}
                  onDrop={async (e) => {
                    e.preventDefault(); setDragOver(false)
                    const f = e.dataTransfer.files[0]
                    if (!f) return
                    setFile(f)
                    setContent(await f.text())
                  }}
                  className={`relative ${dragOver ? 'ring-4 ring-[#4f46e5] ring-offset-2 rounded-2xl' : ''}`}
                >
                  <textarea
                    className="clay-input w-full min-h-[220px] px-4 py-3 pb-12 text-[15px] text-[#1a1a1a] placeholder:text-[#7a7a7a] resize-none"
                    placeholder="Paste full email including headers, or drop a .eml file anywhere in this box..."
                    value={content}
                    onChange={(e) => setContent(e.target.value)}
                  />
                  <div className="absolute bottom-3 left-3 right-3 flex items-center justify-between gap-2">
                    <label className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[13px] font-bold text-[#4f46e5] hover:bg-[#eff4ff] transition-colors"
                      style={{ background: '#fffefb', border: '1.5px solid #4f46e5' }}>
                      <Upload className="h-3.5 w-3.5" />
                      {file ? file.name.slice(0, 24) : 'Upload .eml file'}
                      <input
                        type="file"
                        className="hidden"
                        accept=".eml,.txt,message/rfc822"
                        onChange={async (e) => {
                          const f = e.target.files?.[0]
                          if (!f) return
                          setFile(f)
                          setContent(await f.text())
                        }}
                      />
                    </label>
                    {file && (
                      <button
                        onClick={() => { setFile(null); setContent('') }}
                        className="text-[12px] text-[#dc2626] font-bold hover:underline">
                        Clear
                      </button>
                    )}
                  </div>
                </div>
              )}
              {tab === 'text' && (
                <textarea
                  className="clay-input w-full min-h-[180px] px-4 py-3 text-[15px] text-[#1a1a1a] placeholder:text-[#7a7a7a] resize-none"
                  placeholder="SMS, WhatsApp, DM, any suspicious text..."
                  value={content}
                  onChange={(e) => setContent(e.target.value)}
                />
              )}
              {tab === 'url' && (
                <input
                  className="clay-input w-full h-14 px-4 text-[15px] text-[#1a1a1a] placeholder:text-[#7a7a7a]"
                  placeholder="https://example.com/login"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                />
              )}
            </div>

            {error && (
              <div className="mt-4 rounded-xl border-2 border-[#ffb3b3] bg-[#fff1f1] px-4 py-3 text-[14px] text-[#dc2626] font-bold">
                {error}
              </div>
            )}

            <button
              disabled={loading}
              onClick={runAnalysis}
              className="clay-btn mt-5 w-full py-4 bg-[#4f46e5] text-white text-[15px] flex items-center justify-center gap-2"
            >
              <Shield className="h-5 w-5" />
              {loading ? 'Analyzing...' : 'Analyze now'}
            </button>

            <p className="mt-4 text-center text-[13px] text-[#3a3a3a] font-bold">
              {LLM_MODELS.map((m) => m.short).join(' · ')}
            </p>
          </div>
        </div>

        {/* ── Demo samples ───────────────────────────────────── */}
        <section className="mx-auto mt-7 max-w-[800px]">
          <p className="text-[13px] font-bold uppercase tracking-[0.14em] text-[#3a3a3a]">Try a sample</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {samples.map((s) => (
              <button
                key={s.label}
                onClick={() => useSample(s)}
                className={`clay-badge px-4 py-2.5 text-[14px] font-bold cursor-pointer ${
                  s.kind === 'danger'  ? 'bg-[#ffb3b3]' :
                  s.kind === 'warning' ? 'bg-[#ffe9a0]' :
                                         'bg-[#b3f0c8]'
                } text-[#1a1a1a]`}
              >
                {s.label}
              </button>
            ))}
          </div>
        </section>

        {/* ── Stats row ──────────────────────────────────────── */}
        <section className="mx-auto mt-10 max-w-[800px]">
          {dashboardError && (
            <div className="mb-3 rounded-xl border-2 border-[#ffe9a0] bg-[#fffbee] px-4 py-3 text-[14px] text-[#92400e] font-bold">
              {dashboardError}
            </div>
          )}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {statCards.map(({ icon: Icon, label, value, color, bg }) => (
              <div key={label} className={`clay ${bg} p-5`}>
                <Icon className={`h-6 w-6 mb-2 ${color}`} />
                <p className={`text-[26px] font-bold ${color}`}>{value}</p>
                <p className="text-[13px] text-[#3a3a3a] font-bold mt-1">{label}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ── Extension + Safe Mails CTA row ─────────────────── */}
        <section className="mx-auto mt-10 max-w-[800px] grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div
            className="p-6 text-white"
            style={{
              background: '#4f46e5',
              border: '2px solid #1a1a1a',
              borderRadius: '16px',
              boxShadow: '4px 4px 0px #1a1a1a',
            }}
          >
            <div className="h-10 w-10 rounded-xl flex items-center justify-center mb-4"
              style={{ border: '2px solid rgba(255,255,255,0.6)', background: 'rgba(255,255,255,0.15)' }}>
              <Lock className="h-5 w-5 text-white" />
            </div>
            <h2 className="text-[20px] font-bold text-white">Real-time browser protection</h2>
            <p className="mt-2 text-[14px] leading-relaxed" style={{ color: 'rgba(255,255,255,0.92)' }}>
              Chrome extension that blocks phishing sites, warns on suspicious links, and guards your passwords.
            </p>
            <Link
              href="/extension"
              className="clay-btn mt-4 px-4 py-2.5 text-[14px] font-bold inline-flex items-center gap-1.5 no-underline"
              style={{ background: '#ffffff', color: '#4f46e5', borderColor: '#ffffff' }}
            >
              <Download className="h-4 w-4" />
              Get the extension
            </Link>
          </div>

          <div
            className="p-6 text-white"
            style={{
              background: '#16a34a',
              border: '2px solid #1a1a1a',
              borderRadius: '16px',
              boxShadow: '4px 4px 0px #1a1a1a',
            }}
          >
            <div className="h-10 w-10 rounded-xl flex items-center justify-center mb-4"
              style={{ border: '2px solid rgba(255,255,255,0.6)', background: 'rgba(255,255,255,0.15)' }}>
              <Activity className="h-5 w-5 text-white" />
            </div>
            <h2 className="text-[20px] font-bold text-white">Gmail + Telegram alerts</h2>
            <p className="mt-2 text-[14px] leading-relaxed" style={{ color: 'rgba(255,255,255,0.92)' }}>
              Connect your Gmail. Get instant Telegram alerts whenever a suspicious email arrives in your inbox.
            </p>
            <Link
              href="/safe-mails"
              className="clay-btn mt-4 px-4 py-2.5 text-[14px] font-bold inline-flex items-center gap-1.5 no-underline"
              style={{ background: '#ffffff', color: '#16a34a', borderColor: '#ffffff' }}
            >
              <Zap className="h-4 w-4" />
              Set up alerts
            </Link>
          </div>
        </section>

        {/* ── Recent scans ───────────────────────────────────── */}
        <section className="clay mx-auto mt-10 max-w-[800px] overflow-hidden">
          <div className="px-6 pt-5 pb-2">
            <p className="text-[13px] font-bold uppercase tracking-[0.14em] text-[#3a3a3a]">Recent scans</p>
          </div>
          <div className="divide-y-2 divide-[#1a1a1a]">
            {dashboard.recent_scans.length === 0 && (
              <div className="px-6 py-5 text-[15px] text-[#3a3a3a]">No completed scans yet.</div>
            )}
            {dashboard.recent_scans.map((item) => (
              <div
                key={`${item.job_id ?? item.description}-${item.time_ago}`}
                className="flex items-center gap-3 px-6 py-4"
              >
                <Badge variant={item.verdict === 'SAFE' ? 'success' : item.verdict === 'DANGEROUS' ? 'danger' : 'warning'}>
                  {item.verdict === 'SAFE' ? 'Safe' : item.verdict === 'DANGEROUS' ? 'Dangerous' : 'Suspicious'}
                </Badge>
                <span className="flex-1 truncate text-[14px] font-bold">{item.description}</span>
                <span className="text-[13px] text-[#3a3a3a] font-bold">{item.score}</span>
                <span className="text-[13px] text-[#3a3a3a] hidden sm:block">{item.time_ago}</span>
              </div>
            ))}
          </div>
        </section>

        <div className="mx-auto mt-8 max-w-[800px] text-center text-[14px] text-[#3a3a3a]">
          Learn how detection works in{' '}
          <Link href="/features" className="text-[#4f46e5] underline underline-offset-2 font-bold">Features</Link>.
        </div>
      </main>
    </div>
  )
}
