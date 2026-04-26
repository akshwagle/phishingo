'use client'
import { RedFlag, severityColor, severityTag } from '@/lib/api'

const CATEGORY_LABELS: Record<string, string> = {
  urgency:        'URGENCY',
  authority:      'AUTHORITY',
  credentials:    'CREDENTIAL THEFT',
  grammar:        'GRAMMAR ANOMALY',
  spoofing:       'SPOOFING',
  threat:         'THREAT',
  prize:          'PRIZE / LOTTERY',
  impersonation:  'IMPERSONATION',
}

const CATEGORY_TOOLTIPS: Record<string, string> = {
  urgency:       'Creates artificial time pressure to bypass rational thinking ("Your account will be suspended in 24 hours").',
  authority:     'Impersonates a trusted figure or institution (CEO, bank, government) to increase compliance.',
  credentials:   'Attempts to harvest passwords, PINs, or account numbers.',
  grammar:       'Grammatical or spelling errors typical of non-native-English phishing kits.',
  spoofing:      'Forges sender identity — email address, domain, or display name is fake.',
  threat:        'Uses fear or legal threats to compel action ("You will be arrested if...").',
  prize:         'Fake lottery wins or rewards to elicit personal information.',
  impersonation: 'Directly impersonates a real brand, person, or service.',
}

interface Props {
  flags: RedFlag[]
  headerFlags?: string[]
}

export default function RedFlagsList({ flags, headerFlags = [] }: Props) {
  const allFlags: Array<{ severity: string; category: string; evidence: string; explanation: string }> = [
    ...flags,
    ...headerFlags.map((f) => ({
      severity: 'high',
      category: 'spoofing',
      evidence: f,
      explanation: 'Email header anomaly detected during forensic header analysis.',
    })),
  ]

  if (allFlags.length === 0) {
    return (
      <div>
        <div className="text-brutal-gray text-xs mb-2 tracking-widest">
          ── RED FLAGS ─────────────────────────────────────────────────────
        </div>
        <div className="text-brutal-green text-sm p-3 border border-brutal-gray">
          ✓ NO RED FLAGS DETECTED
        </div>
      </div>
    )
  }

  return (
    <div>
      <div className="text-brutal-gray text-xs mb-2 tracking-widest">
        ── RED FLAGS ({allFlags.length} detected) ──────────────────────────────
      </div>
      <div className="border-2 border-brutal-gray overflow-hidden">
        {/* header row */}
        <div className="grid text-brutal-gray text-xs p-2 border-b border-brutal-gray"
          style={{ gridTemplateColumns: '60px 160px 1fr' }}
        >
          <span>SEV</span>
          <span>CATEGORY</span>
          <span>EVIDENCE & EXPLANATION</span>
        </div>

        {allFlags.map((flag, i) => {
          const color = severityColor(flag.severity)
          const tag   = severityTag(flag.severity)
          const cat   = CATEGORY_LABELS[flag.category] ?? flag.category.toUpperCase()
          const tip   = CATEGORY_TOOLTIPS[flag.category] ?? ''

          return (
            <div
              key={i}
              className="red-flag-row grid text-xs p-2 border-b"
              style={{
                gridTemplateColumns: '60px 160px 1fr',
                borderColor: '#1a1a1a',
              }}
            >
              {/* severity tag */}
              <span>
                <span
                  className="flag-tag px-1 py-0.5 text-brutal-bg text-xs font-bold"
                  style={{ background: color }}
                >
                  [{tag}]
                </span>
              </span>

              {/* category */}
              <span className="tt-wrap">
                <span style={{ color }} className="font-bold">{cat}</span>
                {tip && <span className="tt">{tip}</span>}
              </span>

              {/* evidence + explanation */}
              <span>
                {flag.evidence && (
                  <span className="text-brutal-white">
                    &ldquo;<em>{flag.evidence.slice(0, 120)}{flag.evidence.length > 120 ? '...' : ''}</em>&rdquo;
                  </span>
                )}
                {flag.evidence && flag.explanation && (
                  <span className="text-brutal-gray"> — </span>
                )}
                {flag.explanation && (
                  <span className="text-brutal-gray">{flag.explanation.slice(0, 200)}</span>
                )}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
