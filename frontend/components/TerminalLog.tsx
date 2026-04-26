'use client'
import { useEffect, useRef } from 'react'

export interface LogLine {
  ts: string
  engine: string
  text: string
  status: 'running' | 'done' | 'error' | 'info'
}

interface Props {
  lines: LogLine[]
  height?: string
}

function lineColor(status: LogLine['status']): string {
  if (status === 'done')    return '#00FF41'
  if (status === 'running') return '#FFB800'
  if (status === 'error')   return '#FF0044'
  return '#5A5A5A'
}

export default function TerminalLog({ lines, height = '100%' }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lines.length])

  return (
    <div
      className="terminal-log p-3"
      style={{ height, overflowY: 'auto', fontFamily: 'inherit' }}
    >
      <div className="text-brutal-gray text-xs mb-2">
        ┌─ PHISH-FILTER-PRO FORENSIC LOG ──────────────────────────────────────┐
      </div>

      {lines.length === 0 && (
        <div className="text-brutal-gray text-xs">
          [ WAITING FOR ENGINE OUTPUT... ]
        </div>
      )}

      {lines.map((line, i) => (
        <div
          key={i}
          className="text-xs leading-5 whitespace-pre-wrap"
          style={{ color: lineColor(line.status) }}
        >
          <span className="text-brutal-gray select-none">[{line.ts}] </span>
          <span className="text-brutal-gray">[</span>
          <span style={{ color: lineColor(line.status) }}>
            {line.engine.padEnd(18)}
          </span>
          <span className="text-brutal-gray">] </span>
          {line.text}
        </div>
      ))}

      <div ref={bottomRef} className="flex items-center gap-1 mt-1">
        <span className="text-brutal-green text-xs">
          root@phishfilter:~$
        </span>
        <span className="blink text-brutal-green text-xs">█</span>
      </div>
    </div>
  )
}

export function formatLogLine(msg: {
  engine: string
  status: 'running' | 'done'
  result: Record<string, unknown>
  error?: string
}): LogLine {
  const ts = new Date().toISOString().slice(11, 23)
  const engineLabel = msg.engine.toUpperCase().replace(/_/g, ' ')

  if (msg.error) {
    return { ts, engine: engineLabel, text: `ERROR — ${msg.error}`, status: 'error' }
  }

  if (msg.status === 'running') {
    return { ts, engine: engineLabel, text: 'running...', status: 'running' }
  }

  // Format done message with key findings
  const r = msg.result as Record<string, unknown>
  let summary = 'DONE'

  if (msg.engine === 'headers') {
    const parts: string[] = []
    if (r.spf)   parts.push(`SPF: ${String(r.spf).toUpperCase()}`)
    if (r.dkim)  parts.push(`DKIM: ${String(r.dkim).toUpperCase()}`)
    if (r.dmarc) parts.push(`DMARC: ${String(r.dmarc).toUpperCase()}`)
    if (r.display_name_spoof) parts.push('DISPLAY-NAME SPOOF DETECTED')
    const mm = r.mismatches as string[] | undefined
    if (mm?.length) parts.push(`${mm.length} DOMAIN MISMATCH(ES)`)
    summary = parts.length ? `DONE — ${parts.join(', ')}` : 'DONE — NO AUTH HEADERS'
  }

  else if (msg.engine === 'urls') {
    const flagged = r.flagged as number | undefined
    const urls = r.urls as unknown[] | undefined
    summary = `DONE — ${urls?.length ?? 0} URL(S) ANALYZED, ${flagged ?? 0} FLAGGED`
  }

  else if (msg.engine === 'homograph') {
    const h = r.homographs as unknown[] | undefined
    summary = `DONE — ${h?.length ?? 0} HOMOGRAPH ATTACK(S) DETECTED`
  }

  else if (msg.engine === 'typosquat') {
    const t = r.typosquats as unknown[] | undefined
    summary = `DONE — ${t?.length ?? 0} TYPOSQUAT(S) DETECTED`
  }

  else if (msg.engine === 'domain_intel') {
    const domains = Object.keys(r)
    summary = `DONE — ${domains.length} DOMAIN(S) ANALYZED`
  }

  else if (msg.engine === 'llm') {
    const verdict = r.verdict as string | undefined
    const score   = r.risk_score as number | undefined
    const models  = r.model_count as number | undefined
    summary = `DONE — VERDICT: ${verdict ?? '?'} | RISK: ${score ?? '?'}/100 | ${models ?? '?'} MODELS`
  }

  else if (msg.engine === 'threat_intel') {
    const results = r.results as Record<string, { matched: boolean }> | undefined
    const hits = Object.values(results ?? {}).filter((v) => v?.matched).length
    summary = `DONE — ${hits} THREAT FEED HIT(S)`
  }

  else if (msg.engine === 'sandbox') {
    const urls = Object.keys(r)
    const forms = Object.values(r as Record<string, { has_login_form?: boolean }>)
      .filter((v) => v?.has_login_form).length
    summary = `DONE — ${urls.length} URL(S) SCREENSHOTTED, ${forms} LOGIN FORM(S) FOUND`
  }

  else if (msg.engine === 'aggregator') {
    const verdict = r.verdict as string | undefined
    const score   = r.score as number | undefined
    const conf    = r.confidence as number | undefined
    summary = `FINAL VERDICT: ${verdict} | SCORE: ${score}/100 | CONFIDENCE: ${conf}%`
  }

  return { ts, engine: engineLabel, text: summary, status: 'done' }
}
