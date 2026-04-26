'use client'
import { useEffect, useRef } from 'react'
import { ScoreResult, Verdict, verdictColor } from '@/lib/api'

const ASCII_SKULL = `
  ░░░░░░░░░░░░░░░░░
  ░░░▓▓▓▓▓▓▓▓▓░░░░
  ░░▓▒░░░░░░░▒▓░░░
  ░░▓▒██░░██░▒▓░░░
  ░░▓▒░░░░░░░▒▓░░░
  ░░▓▒░░▓▓░░░▒▓░░░
  ░░░▓▓▓░░░▓▓▓░░░░
  ░░░░░▓▓▓▓░░░░░░░
  ░░░░░░░░░░░░░░░░░`

const ASCII_CHECK = `
  ░░░░░░░░░░░░░░░░░
  ░░░░░░░░░░▓░░░░░
  ░░░░░░░░░▓▓░░░░░
  ░░░▓░░░░▓▓░░░░░░
  ░░░▓▓░░▓▓░░░░░░░
  ░░░░▓▓▓▓░░░░░░░░
  ░░░░░▓▓░░░░░░░░░
  ░░░░░░░░░░░░░░░░░`

interface Props {
  score: ScoreResult
}

function ScoreBar({ value, color }: { value: number; color: string }) {
  return (
    <div className="score-bar-track w-full">
      <div
        className="score-bar-fill"
        style={{ width: `${value}%`, background: color }}
      />
    </div>
  )
}

function DangerousTicker() {
  return (
    <div
      className="ticker-wrap py-2 border-y-2 mt-2"
      style={{ borderColor: '#FF0044', background: 'rgba(255,0,68,0.08)' }}
    >
      <div className="ticker-inner text-xs font-bold tracking-widest" style={{ color: '#FF0044' }}>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        ⚠ DANGEROUS — DO NOT INTERACT ⚠ &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        ⚠ DANGEROUS — DO NOT INTERACT ⚠ &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        ⚠ DANGEROUS — DO NOT INTERACT ⚠ &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        ⚠ PHISHING ATTEMPT CONFIRMED ⚠ &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        ⚠ DO NOT CLICK ANY LINKS ⚠ &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        ⚠ DO NOT ENTER CREDENTIALS ⚠
      </div>
    </div>
  )
}

export default function VerdictCard({ score }: Props) {
  const verdict = score.verdict as Verdict
  const color   = verdictColor(verdict)
  const isDangerous  = verdict === 'DANGEROUS'
  const isSuspicious = verdict === 'SUSPICIOUS'
  const isSafe       = verdict === 'SAFE'

  return (
    <div
      className={`border-3 p-6 slide-in ${isDangerous ? 'alarm-border' : ''}`}
      style={{
        borderWidth: 3,
        borderStyle: 'solid',
        borderColor: color,
        background: `${color}08`,
        fontFamily: 'inherit',
      }}
    >
      {/* top bar */}
      <div className="flex items-center justify-between mb-4">
        <div className="text-brutal-gray text-xs tracking-widest">
          ── FORENSIC VERDICT ────────────────────────────────────────────
        </div>
        <div className="text-brutal-gray text-xs">
          ENGINE COVERAGE: {score.engines_succeeded}/{score.engines_total}
        </div>
      </div>

      {isDangerous && <DangerousTicker />}

      {/* main verdict row */}
      <div className="flex items-start gap-6 my-4">
        {/* ASCII art */}
        <pre
          className="text-xs leading-tight hidden md:block shrink-0"
          style={{ color, fontFamily: 'inherit', fontSize: 10 }}
        >
          {isDangerous ? ASCII_SKULL : ASCII_CHECK}
        </pre>

        {/* score + verdict */}
        <div className="flex-1">
          {/* score number */}
          <div
            className={`score-display font-bold leading-none ${isDangerous ? 'glitch-text' : ''}`}
            data-text={score.score}
            style={{ color, fontFamily: 'inherit' }}
          >
            {score.score}
            <span className="text-2xl" style={{ color: '#5A5A5A' }}>/100</span>
          </div>

          {/* verdict label */}
          <div
            className="text-3xl font-bold tracking-widest mt-1"
            style={{ color, fontFamily: 'inherit' }}
          >
            {isSafe       ? '✓ VERIFIED CLEAN'     : ''}
            {isSuspicious ? '⚠ HANDLE WITH CAUTION' : ''}
            {isDangerous  ? '☠ DO NOT INTERACT'     : ''}
          </div>

          {/* confidence */}
          <div className="text-brutal-gray text-sm mt-1">
            {score.confidence}% CONFIDENCE
          </div>

          {/* score bar */}
          <div className="mt-3">
            <ScoreBar value={score.score} color={color} />
            <div className="flex justify-between text-brutal-gray text-xs mt-1">
              <span>SAFE</span>
              <span>SUSPICIOUS</span>
              <span>DANGEROUS</span>
            </div>
          </div>
        </div>
      </div>

      {/* score breakdown */}
      {score.breakdown.length > 0 && (
        <div className="mt-4 border-t border-brutal-gray pt-3">
          <div className="text-brutal-gray text-xs mb-2 tracking-widest">SCORE BREAKDOWN:</div>
          <div className="flex flex-col gap-1">
            {score.breakdown.map((item, i) => (
              <div key={i} className="flex items-start gap-3 text-xs">
                <span className="text-brutal-white shrink-0 w-8 text-right font-bold" style={{ color }}>
                  +{item.contribution}
                </span>
                <span className="text-brutal-white font-bold shrink-0 min-w-[180px]">
                  {item.signal}
                </span>
                <span className="text-brutal-gray">{item.reasoning.slice(0, 120)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
