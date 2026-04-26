'use client'
import { useCallback, useEffect, useRef, useState } from 'react'

export function useSoundEffects() {
  const ctxRef  = useRef<AudioContext | null>(null)
  const [muted, setMuted] = useState(true)  // muted by default

  // Load mute state from localStorage
  useEffect(() => {
    if (typeof window === 'undefined') return
    const stored = localStorage.getItem('pfp-muted')
    setMuted(stored !== 'false')
  }, [])

  function getCtx(): AudioContext | null {
    if (typeof window === 'undefined') return null
    if (!ctxRef.current) {
      ctxRef.current = new (window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext)()
    }
    return ctxRef.current
  }

  function beep(freq: number, duration: number, vol = 0.08, type: OscillatorType = 'square') {
    if (muted) return
    const ctx = getCtx()
    if (!ctx) return
    const osc  = ctx.createOscillator()
    const gain = ctx.createGain()
    osc.connect(gain)
    gain.connect(ctx.destination)
    osc.type = type
    osc.frequency.setValueAtTime(freq, ctx.currentTime)
    gain.gain.setValueAtTime(vol, ctx.currentTime)
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + duration)
    osc.start(ctx.currentTime)
    osc.stop(ctx.currentTime + duration)
  }

  const keyClick = useCallback(() => beep(1200, 0.04, 0.04, 'square'), [muted])

  const engineDone = useCallback(() => {
    beep(440, 0.08, 0.06, 'sine')
    setTimeout(() => beep(880, 0.05, 0.04, 'sine'), 80)
  }, [muted])

  const dangerAlarm = useCallback(() => {
    for (let i = 0; i < 4; i++) {
      setTimeout(() => {
        beep(880, 0.15, 0.12, 'sawtooth')
        setTimeout(() => beep(440, 0.15, 0.10, 'sawtooth'), 160)
      }, i * 400)
    }
  }, [muted])

  const toggleMute = useCallback(() => {
    setMuted((m) => {
      const next = !m
      localStorage.setItem('pfp-muted', String(!next))
      return next
    })
  }, [])

  return { keyClick, engineDone, dangerAlarm, toggleMute, muted }
}
