'use client'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import dynamic from 'next/dynamic'
import { ArrowLeft, Copy, FileDown, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { AnalyzeReport, WSMessage, connectWS } from '@/lib/api'
import { Badge } from '@/components/ui/badge'

const PDFExportButton = dynamic(() => import('@/components/PDFExportButton'), {
  ssr: false,
  loading: () => (
    <button className="clay-btn bg-[#fffefb] text-[#5a5a5a] px-3 py-2 text-[11px]">Loading PDF...</button>
  ),
})

const AUTHORITY_LINKS = [
  { label: 'Report to APWG', url: 'https://apwg.org/report-phishing/' },
  { label: 'Report to FTC',  url: 'https://reportfraud.ftc.gov/' },
  { label: 'Report to IC3',  url: 'https://www.ic3.gov/' },
]

const ENGINE_ORDER = ['headers','urls','homograph','typosquat','domain_intel','llm','threat_intel','sandbox','aggregator']

type EngineStatus = 'idle' | 'running' | 'done' | 'error'

export default function AnalyzePage() {
  const { id } = useParams<{ id: string }>()
  const router = useRouter()
  const [report,     setReport]     = useState<AnalyzeReport | null>(null)
  const [showReport, setShowReport] = useState(false)
  const [wsStatus,   setWsStatus]   = useState<'connecting'|'streaming'|'done'|'error'>('connecting')
  const [engines,    setEngines]    = useState<Record<string, { status: EngineStatus; summary: string }>>(() =>
    Object.fromEntries(ENGINE_ORDER.map((e) => [e, { status: 'idle', summary: '' }]))
  )
  const [copyDone, setCopyDone] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!id) return
    const stored = sessionStorage.getItem(`pfp-report-${id}`)
    if (stored) {
      try { setReport(JSON.parse(stored) as AnalyzeReport) } catch { /* ignore */ }
    }
  }, [id])

  useEffect(() => {
    if (!id) return
    setWsStatus('connecting')
    const ws = connectWS(
      id,
      (msg: WSMessage) => {
        setWsStatus('streaming')
        const key = msg.engine.toLowerCase().replace(/ /g, '_')
        setEngines((prev) => ({
          ...prev,
          [key]: {
            status:  msg.status === 'running' ? 'running' : (msg.result?.error ? 'error' : 'done'),
            summary: msg.status === 'running' ? 'Analyzing...' : summarizeEngine(key, msg.result),
          },
        }))
      },
      () => { setWsStatus('done'); setTimeout(() => setShowReport(true), 350) },
      () => setWsStatus('error'),
    )
    wsRef.current = ws
    return () => ws.close()
  }, [id])

  const verdict    = report?.score.verdict ?? 'SUSPICIOUS'
  const scoreColor = useMemo(() => {
    if (verdict === 'SAFE')      return '#16a34a'
    if (verdict === 'DANGEROUS') return '#dc2626'
    return '#d97706'
  }, [verdict])

  const scoreCardBg = verdict === 'SAFE' ? 'clay-green' : verdict === 'DANGEROUS' ? 'clay-red' : 'clay-yellow'

  function copyLink() {
    navigator.clipboard.writeText(window.location.href).then(() => {
      setCopyDone(true)
      setTimeout(() => setCopyDone(false), 1500)
    })
  }

  return (
    <div className="min-h-screen bg-[#f5f0e8] pb-12" style={{ fontFamily: "'Space Mono', monospace" }}>

      {/* Navbar */}
      <header className="h-14 bg-[#fffefb] border-b-2 border-[#1a1a1a]"
        style={{ boxShadow: '0 2px 0 #1a1a1a' }}>
        <div className="mx-auto h-full max-w-[720px] px-4 flex items-center justify-between">
          <button
            onClick={() => router.push('/')}
            className="clay-btn bg-[#b3c8ff] text-[#1a1a1a] px-3 py-2 text-[11px] flex items-center gap-1.5"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Scan another
          </button>
          <div className="text-[11px] text-[#5a5a5a] hidden sm:block">
            ID: {id?.slice(0, 12)}...
          </div>
        </div>
      </header>

      <main className="mx-auto mt-6 max-w-[660px] px-4 space-y-4">

        {/* Live progress */}
        {(wsStatus === 'connecting' || wsStatus === 'streaming') && (
          <div className="clay overflow-hidden">
            <div className="h-1.5 w-full bg-[#e5e7eb]">
              <div className="h-full bg-[#4f46e5] transition-all duration-500 animate-pulse" style={{ width: '60%' }} />
            </div>
            <div className="p-4">
              <p className="text-[12px] font-bold text-[#5a5a5a]">Live analysis in progress...</p>
              <div className="mt-3 grid grid-cols-2 sm:grid-cols-3 gap-2">
                {ENGINE_ORDER.map((engine) => {
                  const data = engines[engine]
                  const tone =
                    data?.status === 'done'    ? 'clay-green'  :
                    data?.status === 'running' ? 'clay-yellow' :
                    data?.status === 'error'   ? 'clay-red'    :
                    ''
                  return (
                    <div key={engine} className={`clay ${tone} p-2.5`}>
                      <p className="text-[10px] font-bold">{prettyName(engine)}</p>
                      <p className="mt-0.5 text-[10px] text-[#5a5a5a]">{data?.summary || 'Waiting...'}</p>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        )}

        {report && (showReport || wsStatus === 'done') && (
          <>
            {/* Verdict card */}
            <section className={`clay ${scoreCardBg} p-5`}>
              <div className="flex items-start justify-between gap-3">
                <Badge variant={verdict === 'SAFE' ? 'success' : verdict === 'DANGEROUS' ? 'danger' : 'warning'}
                  className="text-[12px] px-3 py-1 flex items-center gap-1.5">
                  {verdict === 'SAFE'      ? <ShieldCheck    className="h-3.5 w-3.5" /> :
                   verdict === 'DANGEROUS' ? <ShieldAlert    className="h-3.5 w-3.5" /> :
                                             <ShieldQuestion className="h-3.5 w-3.5" />}
                  {verdict === 'DANGEROUS' ? 'Dangerous' : verdict === 'SAFE' ? 'Safe' : 'Suspicious'}
                </Badge>
                <div
                  className="h-[52px] w-[52px] rounded-full border-[3px] bg-[#fffefb] flex items-center justify-center flex-shrink-0"
                  style={{ borderColor: scoreColor, color: scoreColor, boxShadow: `3px 3px 0 ${scoreColor}` }}
                >
                  <span className="text-[18px] font-bold">{report.score.score}</span>
                </div>
              </div>

              <p className="mt-3 text-[13px] text-[#1a1a1a] leading-relaxed">
                {report.engines.llm?.summary ||
                  'This message shows multiple signals commonly found in phishing attempts. Verify sender identity and destination URLs before taking action.'}
              </p>

              {/* Auth badges */}
              <div className="mt-4 grid grid-cols-2 sm:grid-cols-5 gap-2">
                <AuthSmall label="SPF"        value={report.engines.headers?.spf  ?? 'unknown'} />
                <AuthSmall label="DKIM"       value={report.engines.headers?.dkim ?? 'unknown'} />
                <AuthSmall label="DMARC"      value={report.engines.headers?.dmarc ?? 'unknown'} />
                <AuthSmall label="Domain Age" value={findDomainAge(report)} />
                <AuthSmall label="VirusTotal" value={threatIntelStatus(report)} />
              </div>
            </section>

            {/* URL Redirect chain */}
            <section className="clay p-5">
              <h3 className="text-[12px] font-bold text-[#1a1a1a]">URL Redirect Chain</h3>
              <pre className="mono-evidence mt-3 rounded-xl border-2 border-[#1a1a1a] bg-[#fffefb] p-3 text-[11px] text-[#1a1a1a] whitespace-pre-wrap break-all overflow-x-auto"
                style={{ boxShadow: 'inset 0 2px 4px rgba(0,0,0,0.05)' }}>
                {renderChain(report)}
              </pre>
            </section>

            {/* AI Ensemble */}
            <section className="clay p-5">
              <h3 className="text-[12px] font-bold text-[#1a1a1a]">AI Ensemble</h3>
              <div className="mt-3 grid grid-cols-2 sm:grid-cols-3 gap-2">
                {Object.entries(report.engines.llm?.models_used ?? {}).slice(0, 5).map(([model, status]) => (
                  <div key={model} className={`clay p-3 ${status === 'ok' ? 'clay-green' : 'clay-yellow'}`}>
                    <p className="text-[10px] font-bold truncate">{model.split('/')[1] ?? model}</p>
                    <p className={`mt-1 text-[11px] font-bold ${status === 'ok' ? 'text-[#16a34a]' : 'text-[#d97706]'}`}>
                      {status === 'ok' ? 'Responded' : status}
                    </p>
                    <p className="text-[10px] text-[#5a5a5a]">score {report.engines.llm?.risk_score ?? 'n/a'}</p>
                  </div>
                ))}
              </div>
            </section>

            {/* Red flags */}
            {(report.engines.llm?.red_flags?.length ?? 0) > 0 && (
              <section className="clay p-5">
                <h3 className="text-[12px] font-bold text-[#1a1a1a]">Red Flags</h3>
                <div className="mt-3 space-y-2">
                  {(report.engines.llm?.red_flags ?? []).slice(0, 6).map((flag, idx) => (
                    <div key={`${flag.category}-${idx}`} className={`clay p-3 ${flag.severity === 'critical' || flag.severity === 'high' ? 'clay-red' : 'clay-yellow'}`}>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="clay-badge px-2 py-0.5 text-[10px] font-bold bg-[#1a1a1a] text-white">
                          {flag.severity}
                        </span>
                        <span className="text-[11px] font-bold">{flag.explanation}</span>
                      </div>
                      <p className="mono-evidence mt-2 text-[11px] text-[#5a5a5a] italic">
                        &ldquo;{flag.evidence}&rdquo;
                      </p>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* Action row */}
            <section className="clay p-4">
              <div className="flex flex-wrap gap-2">
                <div className="inline-flex items-center gap-1.5 clay-btn bg-[#fffefb] text-[#1a1a1a] px-3 py-2 text-[11px]">
                  <FileDown className="h-3.5 w-3.5" />
                  <PDFExportButton report={report} jobId={id ?? ''} />
                </div>
                <button
                  onClick={copyLink}
                  className="clay-btn bg-[#b3c8ff] text-[#1a1a1a] px-3 py-2 text-[11px] flex items-center gap-1.5"
                >
                  <Copy className="h-3.5 w-3.5" />
                  {copyDone ? 'Copied!' : 'Copy link'}
                </button>
                {AUTHORITY_LINKS.map((item) => (
                  <a key={item.url} href={item.url} target="_blank" rel="noreferrer">
                    <button className="clay-btn bg-[#ffb3b3] text-[#1a1a1a] px-3 py-2 text-[11px]">
                      {item.label}
                    </button>
                  </a>
                ))}
                <button
                  onClick={() => router.push('/')}
                  className="clay-btn bg-[#fffefb] text-[#1a1a1a] px-3 py-2 text-[11px] flex items-center gap-1.5"
                >
                  <ArrowLeft className="h-3.5 w-3.5" />
                  Scan another
                </button>
              </div>
            </section>
          </>
        )}
      </main>
    </div>
  )
}

/* ── helpers ───────────────────────────────────────────────── */

function prettyName(key: string) {
  return key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

function summarizeEngine(key: string, result: Record<string, unknown>) {
  if (key === 'headers')     return 'Header authentication checked'
  if (key === 'urls')        return `${Array.isArray(result.urls) ? result.urls.length : 0} URL(s) inspected`
  if (key === 'homograph')   return `${Array.isArray(result.homographs) ? result.homographs.length : 0} homograph signal(s)`
  if (key === 'threat_intel') return 'Threat feeds cross-checked'
  if (key === 'domain_intel') return 'Domain registration analyzed'
  if (key === 'llm')         return 'AI ensemble verdict generated'
  return 'Completed'
}

function AuthSmall({ label, value }: { label: string; value: string }) {
  const lower = value.toLowerCase()
  const tone  =
    lower.includes('pass') || lower.includes('clean') || lower.includes('safe') ? 'text-[#16a34a]' :
    lower.includes('fail') || lower.includes('hit')   || lower.includes('danger') ? 'text-[#dc2626]' :
    'text-[#d97706]'
  return (
    <div className="clay p-2.5">
      <p className="text-[9px] font-bold text-[#5a5a5a]">{label}</p>
      <p className={`mt-1 text-[11px] font-bold ${tone}`}>{value}</p>
    </div>
  )
}

function renderChain(report: AnalyzeReport) {
  const urlsEngine = report.engines.urls as unknown as {
    results?: Record<string, { redirect_chain?: string[]; final_url?: string; is_suspicious?: boolean }>
    urls?: Array<{
      original?: string
      redirect_chain?: Array<{ url?: string }>
      final_destination?: string
      suspicious_patterns?: string[]
    }>
  } | undefined

  if (Array.isArray(urlsEngine?.urls) && urlsEngine.urls.length > 0) {
    const first = urlsEngine.urls[0]
    const hops: string[] = []
    if (first.original) hops.push(first.original)
    if (Array.isArray(first.redirect_chain)) {
      for (const hop of first.redirect_chain) {
        if (hop?.url && !hops.includes(hop.url)) hops.push(hop.url)
      }
    }
    if (first.final_destination && !hops.includes(first.final_destination)) hops.push(first.final_destination)
    if (hops.length === 0) return 'No URLs detected in this submission.'
    const suspicious = (first.suspicious_patterns?.length ?? 0) > 0
    return hops.map((url, i) => `${i + 1}. ${url}${i < hops.length - 1 ? '  ->' : suspicious ? '  [SUSPICIOUS]' : ''}`).join('\n')
  }

  const urlResult = urlsEngine?.results
  if (!urlResult || Object.keys(urlResult).length === 0) return 'No URLs detected in this submission.'
  const first = Object.values(urlResult)[0]
  const chain = [...(first.redirect_chain || []), first.final_url].filter(Boolean) as string[]
  if (chain.length === 0) return 'No URLs detected in this submission.'
  return chain.map((url, i) => `${i + 1}. ${url}${i < chain.length - 1 ? '  ->' : first.is_suspicious ? '  [SUSPICIOUS]' : ''}`).join('\n')
}

function findDomainAge(report: AnalyzeReport) {
  const first = Object.values(report.engines.domain_intel ?? {})[0]
  if (!first || first.age_days === null) return 'unknown'
  return `${first.age_days}d`
}

function threatIntelStatus(report: AnalyzeReport) {
  const results = report.engines.threat_intel?.results
  if (!results) return 'unknown'
  return Object.values(results).some((r) => r.matched) ? 'hit' : 'clean'
}
