'use client'
import { AuthStatus, authColor } from '@/lib/api'

const TOOLTIPS: Record<string, string> = {
  SPF:   'Sender Policy Framework — verifies that the sending mail server is authorized to send email for the domain. FAIL means the server is NOT on the allowed list.',
  DKIM:  'DomainKeys Identified Mail — a cryptographic signature that proves the email content was not tampered with in transit. FAIL means the signature is invalid.',
  DMARC: 'Domain-based Message Authentication, Reporting, and Conformance — tells receiving servers what to do when SPF/DKIM fail. NONE means no policy is set.',
}

interface Props {
  spf:   AuthStatus
  dkim:  AuthStatus
  dmarc: AuthStatus
}

function Badge({ label, status }: { label: string; status: AuthStatus }) {
  const displayStatus = status.toUpperCase()
  const color = authColor(status)

  return (
    <div className="tt-wrap flex-1">
      <div className="auth-badge" style={{ borderColor: color, color }}>
        <div className="text-brutal-gray text-xs mb-1">{label}</div>
        <div className="text-lg font-bold tracking-widest">{displayStatus}</div>
        <div className="text-xs mt-1" style={{ color }}>
          {status === 'pass'     ? '● VERIFIED'
          : status === 'fail'    ? '✗ FAILED'
          : status === 'softfail'? '~ SOFT FAIL'
          : '? NOT SET'}
        </div>
      </div>
      <div className="tt">{TOOLTIPS[label]}</div>
    </div>
  )
}

export default function AuthBadges({ spf, dkim, dmarc }: Props) {
  return (
    <div>
      <div className="text-brutal-gray text-xs mb-2 tracking-widest">
        ── EMAIL AUTHENTICATION ──────────────────────────────────────────
      </div>
      <div className="flex gap-2">
        <Badge label="SPF"   status={spf}   />
        <Badge label="DKIM"  status={dkim}  />
        <Badge label="DMARC" status={dmarc} />
      </div>
      <div className="text-brutal-gray text-xs mt-2">
        Hover each badge for explanation.
      </div>
    </div>
  )
}
