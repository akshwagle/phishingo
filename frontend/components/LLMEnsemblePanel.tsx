'use client'
import { LLMResult, LLM_MODELS, Verdict, verdictColor, parseModelVerdicts } from '@/lib/api'

interface Props {
  llm: LLMResult
}

function ModelCard({
  shortName,
  modelId,
  status,
  verdict,
  weight,
}: {
  shortName: string
  modelId: string
  status: string
  verdict: Verdict | null
  weight: number
}) {
  const ok         = status === 'ok'
  const vColor     = verdict ? verdictColor(verdict) : '#5A5A5A'
  const borderColor = ok && verdict ? `${vColor}66` : '#333333'

  return (
    <div
      className="model-card flex flex-col gap-1"
      style={{ borderColor }}
    >
      {/* model name */}
      <div className="text-brutal-white text-xs font-bold tracking-wide truncate">
        {shortName}
      </div>

      {/* weight badge */}
      {weight > 1 && (
        <div className="text-brutal-amber text-xs">
          {weight}x WEIGHT
        </div>
      )}

      {/* verdict */}
      {ok && verdict ? (
        <div
          className="text-xs font-bold px-1 py-0.5 self-start"
          style={{ background: vColor, color: '#0A0A0A' }}
        >
          {verdict}
        </div>
      ) : (
        <div className="text-brutal-gray text-xs">—</div>
      )}

      {/* status */}
      <div className="text-xs mt-auto" style={{ color: ok ? '#00FF41' : '#FF0044' }}>
        {ok ? '✓ RESPONDED' : `✗ ${status.toUpperCase().slice(0, 12)}`}
      </div>

      {/* model id hint */}
      <div className="text-brutal-gray" style={{ fontSize: 9 }}>
        {modelId.split('/')[1]?.slice(0, 20) ?? modelId.slice(0, 20)}
      </div>
    </div>
  )
}

export default function LLMEnsemblePanel({ llm }: Props) {
  if (!llm || llm.error) {
    return (
      <div className="border-2 border-brutal-gray p-4">
        <div className="text-brutal-gray text-xs">LLM ENSEMBLE UNAVAILABLE — {llm?.error}</div>
      </div>
    )
  }

  const modelVerdicts = parseModelVerdicts(llm)
  const successCount  = Object.values(llm.models_used).filter((s) => s === 'ok').length

  return (
    <div className="border-2 border-brutal-gray">
      {/* header */}
      <div className="px-4 py-2 border-b-2 border-brutal-gray bg-brutal-panel flex items-center gap-3">
        <span className="text-brutal-white text-sm font-bold tracking-widest">⬡ LLM ENSEMBLE</span>
        <span className="text-brutal-gray text-xs">5-MODEL WEIGHTED VOTE</span>
        <span className="text-brutal-gray text-xs ml-auto">
          {successCount}/5 MODELS RESPONDED
        </span>
      </div>

      {/* model cards */}
      <div className="flex gap-2 p-3">
        {LLM_MODELS.map((m) => (
          <ModelCard
            key={m.id}
            shortName={m.short}
            modelId={m.id}
            status={llm.models_used[m.id] ?? 'unknown'}
            verdict={modelVerdicts[m.id] ?? null}
            weight={m.weight}
          />
        ))}
      </div>

      {/* ensemble verdict summary */}
      <div
        className="px-4 py-3 border-t-2 border-brutal-gray flex flex-wrap items-center gap-3"
        style={{ background: '#0d0d0d' }}
      >
        <span className="text-brutal-gray text-xs">ENSEMBLE VERDICT:</span>
        <span
          className="text-sm font-bold px-2 py-1"
          style={{ background: verdictColor(llm.verdict), color: '#0A0A0A' }}
        >
          {llm.verdict}
        </span>
        <span className="text-brutal-gray text-xs">
          ({successCount}/5 models agree · {llm.confidence}% confidence)
        </span>

        {llm.brand_impersonated && (
          <span className="text-brutal-amber text-xs ml-auto">
            TARGET BRAND: {llm.brand_impersonated.toUpperCase()}
          </span>
        )}
        {llm.sophistication_level && (
          <span className="text-brutal-gray text-xs">
            SOPHISTICATION: {llm.sophistication_level.replace(/_/g, ' ').toUpperCase()}
          </span>
        )}
      </div>

      {/* summary */}
      {llm.summary && (
        <div className="px-4 py-2 border-t border-brutal-gray">
          <span className="text-brutal-gray text-xs">LLM SUMMARY: </span>
          <span className="text-brutal-white text-xs italic">&ldquo;{llm.summary}&rdquo;</span>
        </div>
      )}

      {/* social engineering tactics */}
      {llm.social_engineering_tactics?.length > 0 && (
        <div className="px-4 py-2 border-t border-brutal-gray">
          <span className="text-brutal-gray text-xs">TACTICS: </span>
          {llm.social_engineering_tactics.map((t, i) => (
            <span key={i} className="text-brutal-amber text-xs mr-2">
              [{t.toUpperCase()}]
            </span>
          ))}
        </div>
      )}
    </div>
  )
}
