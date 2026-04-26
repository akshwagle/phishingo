import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'PhishFilter Pro',
  description: 'Trusted phishing detection with forensic evidence and AI consensus',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" style={{ fontFamily: "'Space Mono', 'Courier New', monospace" }}>
      <body style={{ fontFamily: "'Space Mono', 'Courier New', monospace" }}>{children}</body>
    </html>
  )
}
