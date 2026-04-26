'use client'
import { useEffect, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { Check, Shield, Upload, Zap, Lock, Activity, Clock } from 'lucide-react'
import { DashboardResponse, LLM_MODELS, analyzeContent, getDashboard } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'

type Tab = 'email' | 'eml' | 'url' | 'text'

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
  email: 'Paste email',
  eml:   'Upload .eml',
  url:   'Check URL',
  text:  'Analyze text',
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
      if (!content.trim()) return setError('Paste a full email before running analysis.')
      inputType = 'email'; submitContent = content.trim()
    } else if (tab === 'eml') {
      if (!file) return setError('Upload a .eml file first.')
      inputType = 'email'; submitContent = await file.text()
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
      <header className="h-14 bg-[#fffefb] border-b-2 border-[#1a1a1a]"
        style={{ boxShadow: '0 2px 0 #1a1a1a' }}>
        <div className="mx-auto max-w-5xl h-full px-4 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="h-8 w-8 rounded-xl border-2 border-[#1a1a1a] bg-[#4f46e5] flex items-center justify-center"
              style={{ boxShadow: '2px 2px 0 #1a1a1a' }}>
              <Shield className="h-4 w-4 text-white" />
            </div>
            <span className="text-[16px] font-bold">
              PhishFilter <span className="text-[#4f46e5]">Pro</span>
            </span>
          </div>
          <div className="flex items-center gap-2 text-[11px] text-[#5a5a5a]">
            <span className="h-2 w-2 rounded-full bg-[#16a34a]" />
            <span className="hidden sm:inline">All engines online</span>
            <span className="clay-badge bg-[#b3f0c8] text-[#1a1a1a] px-2 py-0.5 text-[10px] font-bold">
              5 AI models active
            </span>
          </div>
        </div>
      </header>

      <main className="px-4 py-10">

        {/* ── Hero ───────────────────────────────────────────── */}
        <section className="mx-auto max-w-2xl text-center">
          <h1 className="text-[26px] sm:text-[30px] font-bold leading-[1.25]">
            Is this email trying to scam you?<br className="hidden sm:block" /> Find out in seconds.
          </h1>
          <p className="mx-auto mt-4 max-w-[480px] text-[14px] text-[#5a5a5a] leading-relaxed">
            Paste any email, URL, or suspicious text. 10 forensic engines and 5 AI models give you a definitive verdict with full evidence.
          </p>
          <div className="mt-5 flex flex-wrap items-center justify-center gap-x-3 gap-y-1.5 text-[11px] text-[#5a5a5a]">
            {['10 forensic engines', '5-model AI ensemble', 'Homograph detection', 'URL unshortening', 'Real-time threat intel'].map((t) => (
              <span key={t} className="flex items-center gap-1">
                <Check className="h-3 w-3 text-[#16a34a]" />{t}
              </span>
            ))}
          </div>
        </section>

        {/* ── Scanner card ───────────────────────────────────── */}
        <div className="clay mx-auto mt-8 max-w-[660px]">
          <div className="p-5">

            {/* Tabs */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {(Object.keys(tabLabels) as Tab[]).map((t) => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={`clay-btn text-[11px] py-2 px-3 ${
                    tab === t
                      ? 'bg-[#4f46e5] text-white'
                      : 'bg-[#fffefb] text-[#5a5a5a]'
                  }`}
                >
                  {tabLabels[t]}
                </button>
              ))}
            </div>

            {/* Input area */}
            <div className="mt-4">
              {(tab === 'email' || tab === 'text') && (
                <textarea
                  className="clay-input w-full min-h-[180px] px-3 py-2.5 text-[13px] text-[#1a1a1a] placeholder:text-[#9a9a9a] resize-none"
                  placeholder={tab === 'email' ? 'Paste full email including headers...' : 'SMS, WhatsApp, DM, any suspicious text...'}
                  value={content}
                  onChange={(e) => setContent(e.target.value)}
                />
              )}
              {tab === 'url' && (
                <input
                  className="clay-input w-full h-11 px-3 text-[13px] text-[#1a1a1a] placeholder:text-[#9a9a9a]"
                  placeholder="https://example.com/login"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                />
              )}
              {tab === 'eml' && (
                <label
                  onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
                  onDragLeave={() => setDragOver(false)}
                  onDrop={(e) => { e.preventDefault(); setDragOver(false); setFile(e.dataTransfer.files[0] ?? null) }}
                  className={`block rounded-2xl border-2 border-dashed border-[#1a1a1a] px-4 py-10 text-center cursor-pointer transition ${
                    dragOver ? 'bg-[#eff4ff]' : 'bg-[#fffefb]'
                  }`}
                >
                  <Upload className="mx-auto h-7 w-7 text-[#5a5a5a]" />
                  <p className="mt-2 text-[12px] text-[#1a1a1a] font-bold">{file ? file.name : 'Drag and drop your .eml file here'}</p>
                  <p className="text-[11px] text-[#5a5a5a]">.eml files supported, max 10MB</p>
                  <input type="file" className="hidden" accept=".eml,.txt,message/rfc822" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
                </label>
              )}
            </div>

            {error && (
              <div className="mt-3 rounded-xl border-2 border-[#ffb3b3] bg-[#fff1f1] px-3 py-2 text-[11px] text-[#dc2626] font-bold">
                {error}
              </div>
            )}

            <button
              disabled={loading}
              onClick={runAnalysis}
              className="clay-btn mt-4 w-full py-3 bg-[#4f46e5] text-white text-[13px] flex items-center justify-center gap-2"
            >
              <Shield className="h-4 w-4" />
              {loading ? 'Analyzing...' : 'Analyze now'}
            </button>

            <p className="mt-3 text-center text-[10px] text-[#5a5a5a]">
              {LLM_MODELS.map((m) => m.short).join(' · ')}
            </p>
          </div>
        </div>

        {/* ── Demo samples ───────────────────────────────────── */}
        <section className="mx-auto mt-6 max-w-[660px]">
          <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#5a5a5a]">Try a sample</p>
          <div className="mt-2 flex flex-wrap gap-2">
            {samples.map((s) => (
              <button
                key={s.label}
                onClick={() => useSample(s)}
                className={`clay-badge px-3 py-1.5 text-[11px] cursor-pointer ${
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
        <section className="mx-auto mt-8 max-w-[660px]">
          {dashboardError && (
            <div className="mb-3 rounded-xl border-2 border-[#ffe9a0] bg-[#fffbee] px-3 py-2 text-[11px] text-[#92400e] font-bold">
              {dashboardError}
            </div>
          )}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {statCards.map(({ icon: Icon, label, value, color, bg }) => (
              <div key={label} className={`clay ${bg} p-4`}>
                <Icon className={`h-4 w-4 mb-1 ${color}`} />
                <p className={`text-[22px] font-bold ${color}`}>{value}</p>
                <p className="text-[10px] text-[#5a5a5a] font-bold mt-0.5">{label}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ── Extension CTA ──────────────────────────────────── */}
        <section
          className="mx-auto mt-10 max-w-[660px] p-6 text-white"
          style={{
            background: '#4f46e5',
            border: '2px solid #1a1a1a',
            borderRadius: '16px',
            boxShadow: '4px 4px 0px #1a1a1a, inset 0 1px 0 rgba(255,255,255,0.15)',
          }}
        >
          <div className="flex items-start gap-3">
            <div className="h-10 w-10 rounded-xl flex-shrink-0 flex items-center justify-center"
              style={{ border: '2px solid rgba(255,255,255,0.6)', background: 'rgba(255,255,255,0.15)' }}>
              <Lock className="h-5 w-5 text-white" />
            </div>
            <div className="flex-1 min-w-0">
              <h2 className="text-[18px] font-bold text-white">Protect yourself in real-time</h2>
              <p className="mt-1.5 text-[12px] leading-relaxed" style={{ color: 'rgba(255,255,255,0.75)' }}>
                Install the Chrome extension for live Gmail scanning, link hover preview, and automatic blocking when entering credentials on phish sites.
              </p>
              <button
                className="clay-btn mt-4 px-4 py-2 text-[12px] font-bold"
                style={{ background: '#ffffff', color: '#4f46e5', borderColor: '#ffffff' }}
              >
                Coming soon
              </button>
            </div>
          </div>
        </section>

        {/* ── Recent scans ───────────────────────────────────── */}
        <section className="clay mx-auto mt-8 max-w-[660px] overflow-hidden">
          <div className="px-5 pt-5 pb-2">
            <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#5a5a5a]">Recent scans</p>
          </div>
          <div className="divide-y-2 divide-[#1a1a1a]">
            {dashboard.recent_scans.length === 0 && (
              <div className="px-5 py-4 text-[12px] text-[#5a5a5a]">No completed scans yet.</div>
            )}
            {dashboard.recent_scans.map((item) => (
              <div
                key={`${item.job_id ?? item.description}-${item.time_ago}`}
                className="flex items-center gap-3 px-5 py-3"
              >
                <Badge variant={item.verdict === 'SAFE' ? 'success' : item.verdict === 'DANGEROUS' ? 'danger' : 'warning'}>
                  {item.verdict === 'SAFE' ? 'Safe' : item.verdict === 'DANGEROUS' ? 'Dangerous' : 'Suspicious'}
                </Badge>
                <span className="flex-1 truncate text-[12px]">{item.description}</span>
                <span className="text-[11px] text-[#5a5a5a]">{item.score}</span>
                <span className="text-[11px] text-[#5a5a5a] hidden sm:block">{item.time_ago}</span>
              </div>
            ))}
          </div>
        </section>

        <div className="mx-auto mt-8 max-w-[660px] text-center text-[11px] text-[#5a5a5a]">
          Learn how detection works in{' '}
          <Link href="/features" className="text-[#4f46e5] underline underline-offset-2">Features</Link>.
        </div>
      </main>
    </div>
  )
}
