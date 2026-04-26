// ─── Types ──────────────────────────────────────────────────────────────────

export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS'
export type AuthStatus = 'pass' | 'fail' | 'softfail' | 'none' | 'neutral' | string

export interface AnalyzeRequest {
  input_type: 'email' | 'url' | 'text'
  content: string
}

export interface RedFlag {
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  evidence: string
  explanation: string
}

export interface HeadersResult {
  spf: AuthStatus
  dkim: AuthStatus
  dmarc: AuthStatus
  from_domain: string
  return_path_domain: string
  reply_to_domain: string
  mismatches: string[]
  display_name_spoof: boolean
  received_chain: string[]
  red_flags: string[]
  error?: string
}

export interface HomographResult {
  homographs: Array<{
    url: string
    attack_type: string
    brand_imitated: string
    confusable_chars?: string[]
    original_domain?: string
    attacked_domain?: string
  }>
  error?: string
}

export interface TyposquatResult {
  typosquats: Array<{
    url: string
    technique: string
    closest_brand: string
    distance?: number
  }>
  error?: string
}

export interface URLResult {
  urls: string[]
  flagged: number
  results?: Record<string, {
    is_redirect: boolean
    redirect_chain: string[]
    final_url: string
    status_code?: number
    is_suspicious: boolean
    flags: string[]
  }>
  error?: string
}

export interface DomainInfo {
  age_days: number | null
  suspicious_tld: boolean
  registrar?: string
  country?: string
  nameservers?: string[]
  error?: string
}

export interface DomainIntelResult {
  [domain: string]: DomainInfo
}

export interface ThreatIntelResult {
  results: Record<string, {
    matched: boolean
    sources: string[]
  }>
  error?: string
}

export interface SandboxResult {
  [url: string]: {
    has_login_form: boolean
    brand_logos_detected: string[]
    screenshot_b64?: string
    page_title?: string
    error?: string
  }
}

export interface LLMResult {
  risk_score: number
  verdict: Verdict
  red_flags: RedFlag[]
  social_engineering_tactics: string[]
  brand_impersonated: string | null
  target_demographic: string
  sophistication_level: string
  summary: string
  confidence: number
  model_count: number
  models_used: Record<string, string>
  individual_verdicts: string[]
  error?: string
}

export interface ScoreBreakdown {
  signal: string
  weight: number
  contribution: number
  reasoning: string
}

export interface ScoreResult {
  score: number
  verdict: Verdict
  confidence: number
  breakdown: ScoreBreakdown[]
  engines_succeeded: number
  engines_total: number
}

export interface AnalyzeReport {
  job_id: string
  timestamp: number
  input_type: string
  parsed: {
    headers: Record<string, string>
    body: string
    urls: string[]
    attachments: string[]
    attachment_hashes: string[]
    parse_error?: string
  }
  engines: {
    headers?:      HeadersResult
    urls?:         URLResult
    homograph?:    HomographResult
    typosquat?:    TyposquatResult
    domain_intel?: DomainIntelResult
    llm?:          LLMResult
    threat_intel?: ThreatIntelResult
    sandbox?:      SandboxResult
  }
  score: ScoreResult
  ws_url?: string
}

export interface WSMessage {
  engine: string
  status: 'running' | 'done'
  result: Record<string, unknown>
  error?: string
}

export interface DashboardStats {
  emails_scanned: number
  phishes_caught: number
  accuracy: number
  avg_scan_time_seconds: number
}

export interface RecentScan {
  job_id?: string
  verdict: Verdict | string
  description: string
  score: number
  time_ago: string
}

export interface DashboardResponse {
  stats: DashboardStats
  recent_scans: RecentScan[]
}

// ─── Model constants ─────────────────────────────────────────────────────────

export const LLM_MODELS = [
  { id: 'qwen/qwen3-32b',              short: 'Qwen3-32B',    weight: 1.0 },
  { id: 'moonshotai/kimi-k2-thinking', short: 'Kimi-K2',      weight: 1.5 },
  { id: 'deepseek/deepseek-r1-0528',   short: 'DeepSeek-R1',  weight: 1.0 },
  { id: 'google/gemini-2.5-flash',     short: 'Gemini-Flash', weight: 1.0 },
  { id: 'openai/gpt-oss-120b',         short: 'GPT-OSS-120B', weight: 1.5 },
] as const

export const ENGINE_NAMES: Record<string, string> = {
  headers:      'HEADER FORENSICS',
  urls:         'URL FORENSICS',
  homograph:    'HOMOGRAPH DETECT',
  typosquat:    'TYPOSQUAT DETECT',
  domain_intel: 'DOMAIN INTEL',
  llm:          'LLM ENSEMBLE',
  threat_intel: 'THREAT INTEL',
  sandbox:      'SANDBOX ANALYSIS',
  aggregator:   'SCORE AGGREGATOR',
}

// ─── API functions ───────────────────────────────────────────────────────────

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

export async function analyzeContent(req: AnalyzeRequest): Promise<AnalyzeReport> {
  let resp: Response
  try {
    resp = await fetch(`${API_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    })
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e)
    throw new Error(`Cannot reach backend at ${API_URL}. ${msg}`)
  }
  if (!resp.ok) {
    const text = await resp.text().catch(() => '')
    throw new Error(`HTTP ${resp.status}: ${text.slice(0, 200)}`)
  }
  return resp.json() as Promise<AnalyzeReport>
}

export async function getReport(jobId: string): Promise<AnalyzeReport> {
  const resp = await fetch(`${API_URL}/api/report/${jobId}`)
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
  return resp.json() as Promise<AnalyzeReport>
}

export async function getDashboard(): Promise<DashboardResponse> {
  const resp = await fetch(`${API_URL}/api/dashboard`)
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
  return resp.json() as Promise<DashboardResponse>
}

export function connectWS(
  jobId: string,
  onMessage: (msg: WSMessage) => void,
  onClose: () => void,
  onError?: (e: Event) => void,
): WebSocket {
  const wsBase = API_URL.replace(/^https?/, (p) => (p === 'https' ? 'wss' : 'ws'))
  const ws = new WebSocket(`${wsBase}/ws/analyze/${jobId}`)
  ws.onmessage = (e) => {
    try { onMessage(JSON.parse(e.data as string)) } catch { /* ignore bad frames */ }
  }
  ws.onclose = onClose
  ws.onerror = onError ?? (() => { /* noop */ })
  return ws
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

export function verdictColor(verdict: Verdict | string | undefined): string {
  if (verdict === 'SAFE')      return '#00FF41'
  if (verdict === 'DANGEROUS') return '#FF0044'
  if (verdict === 'SUSPICIOUS') return '#FFB800'
  return '#5A5A5A'
}

export function severityColor(sev: string): string {
  if (sev === 'critical') return '#FF0044'
  if (sev === 'high')     return '#FF4444'
  if (sev === 'medium')   return '#FFB800'
  return '#5A5A5A'
}

export function severityTag(sev: string): string {
  if (sev === 'critical') return 'CRIT'
  if (sev === 'high')     return 'HIGH'
  if (sev === 'medium')   return 'WARN'
  return 'INFO'
}

export function authColor(status: AuthStatus): string {
  if (status === 'pass')   return '#00FF41'
  if (status === 'fail' || status === 'softfail') return '#FF0044'
  return '#FFB800'
}

/** Parse per-model verdicts from LLM result */
export function parseModelVerdicts(llm: LLMResult): Record<string, Verdict | null> {
  const out: Record<string, Verdict | null> = {}
  let idx = 0
  for (const m of LLM_MODELS) {
    if (llm.models_used[m.id] === 'ok') {
      out[m.id] = (llm.individual_verdicts[idx] as Verdict) ?? null
      idx++
    } else {
      out[m.id] = null
    }
  }
  return out
}

/** Format epoch timestamp as local time string */
export function fmtTimestamp(epoch: number): string {
  return new Date(epoch * 1000).toLocaleString()
}
