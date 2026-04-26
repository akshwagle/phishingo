'use client'
import { useState } from 'react'
import { ENGINE_NAMES } from '@/lib/api'

export type EngineStatus = 'idle' | 'running' | 'done' | 'error'

export interface EngineState {
  name: string
  status: EngineStatus
  summary: string
  result: Record<string, unknown>
}

interface Props {
  engines: Record<string, EngineState>
}

const STATUS_LABEL: Record<EngineStatus, string> = {
  idle:    '○ IDLE',
  running: '◉ RUNNING',
  done:    '✓ DONE',
  error:   '✗ ERROR',
}

const STATUS_COLOR: Record<EngineStatus, string> = {
  idle:    '#5A5A5A',
  running: '#FFB800',
  done:    '#00FF41',
  error:   '#FF0044',
}

const ENGINE_ICONS: Record<string, string> = {
  headers:      '▤',
  urls:         '↗',
  homograph:    '⚠',
  typosquat:    '≈',
  domain_intel: '◎',
  llm:          '⬡',
  threat_intel: '☠',
  sandbox:      '⊞',
}

function EngineCard({ engine, state }: { engine: string; state: EngineState }) {
  const [expanded, setExpanded] = useState(false)
  const color = STATUS_COLOR[state.status]
  const icon  = ENGINE_ICONS[engine] ?? '■'

  return (
    <div
      className={`engine-card border-2 p-3 ${state.status}`}
      style={{ borderColor: color }}
    >
      <div className="flex items-center gap-2 mb-2">
        <span className="status-dot" style={{
          background: color,
          borderRadius: '50%',
          width: 8, height: 8, flexShrink: 0, display: 'inline-block',
          ...(state.status === 'running' ? { animation: 'pulseDot 1s ease-in-out infinite' } : {}),
        }} />
        <span className="text-xs font-bold tracking-wider" style={{ color }}>
          {icon} {ENGINE_NAMES[engine] ?? engine.toUpperCase()}
        </span>
      </div>

      <div className="text-brutal-gray text-xs mb-1">
        {STATUS_LABEL[state.status]}
      </div>

      {state.summary && (
        <div className="text-brutal-white text-xs leading-4 mb-2" style={{ color }}>
          {state.summary}
        </div>
      )}

      {state.status === 'done' && Object.keys(state.result).length > 0 && (
        <button
          onClick={() => setExpanded((x) => !x)}
          className="text-brutal-gray text-xs border border-brutal-gray px-2 py-0.5 hover:border-brutal-white hover:text-brutal-white transition-colors"
        >
          {expanded ? '[COLLAPSE]' : '[EXPAND]'}
        </button>
      )}

      {expanded && (
        <div className="json-dump mt-2 text-brutal-gray text-xs">
          {JSON.stringify(state.result, null, 2)}
        </div>
      )}
    </div>
  )
}

const ENGINE_ORDER = [
  'headers', 'urls', 'homograph',
  'typosquat', 'domain_intel', 'llm',
  'threat_intel', 'sandbox',
]

export default function EngineGrid({ engines }: Props) {
  return (
    <div>
      <div className="text-brutal-gray text-xs mb-2 tracking-widest">
        ── ENGINE STATUS GRID ────────────────────────────────────────────
      </div>
      <div
        className="grid gap-2"
        style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}
      >
        {ENGINE_ORDER.map((key) => {
          const state = engines[key] ?? {
            name: key, status: 'idle' as EngineStatus, summary: '', result: {},
          }
          return <EngineCard key={key} engine={key} state={state} />
        })}
      </div>
    </div>
  )
}

export function initEngines(): Record<string, EngineState> {
  const out: Record<string, EngineState> = {}
  for (const key of ENGINE_ORDER) {
    out[key] = { name: key, status: 'idle', summary: '', result: {} }
  }
  return out
}
