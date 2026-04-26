'use client'
import { useEffect, useRef } from 'react'

const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*(){}[]<>?!01アイウエオカキクケコ'

export default function MatrixRain({ opacity = 0.04 }: { opacity?: number }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let W = window.innerWidth
    let H = window.innerHeight
    canvas.width = W
    canvas.height = H

    const fontSize = 14
    const cols = Math.floor(W / fontSize)
    const drops = Array.from({ length: cols }, () => Math.random() * -50)

    function draw() {
      if (!ctx || !canvas) return
      ctx.fillStyle = 'rgba(10,10,10,0.05)'
      ctx.fillRect(0, 0, W, H)
      ctx.fillStyle = '#00FF41'
      ctx.font = `${fontSize}px "JetBrains Mono", monospace`

      for (let i = 0; i < drops.length; i++) {
        const char = CHARS[Math.floor(Math.random() * CHARS.length)]
        ctx.fillText(char, i * fontSize, drops[i] * fontSize)
        if (drops[i] * fontSize > H && Math.random() > 0.975) {
          drops[i] = 0
        }
        drops[i]++
      }
    }

    const timer = setInterval(draw, 60)

    function onResize() {
      W = window.innerWidth
      H = window.innerHeight
      if (canvas) { canvas.width = W; canvas.height = H }
    }
    window.addEventListener('resize', onResize)

    return () => {
      clearInterval(timer)
      window.removeEventListener('resize', onResize)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      className="matrix-canvas"
      style={{ opacity, zIndex: 0 }}
    />
  )
}
