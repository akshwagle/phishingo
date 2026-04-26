'use client'

interface Hop {
  url: string
  status_code?: number
  is_suspicious?: boolean
  is_flagged?: boolean
  homograph_note?: string
}

interface Props {
  urlResults?: Record<string, {
    is_redirect: boolean
    redirect_chain: string[]
    final_url: string
    status_code?: number
    is_suspicious: boolean
    flags: string[]
  }>
  homographs?: Array<{
    url: string
    attack_type: string
    brand_imitated: string
    attacked_domain?: string
  }>
  urls?: string[]
}

function isSuspiciousDomain(url: string): boolean {
  try {
    const domain = new URL(url).hostname
    return (
      /[а-яёА-ЯЁ]/.test(domain) ||         // Cyrillic
      /xn--/.test(domain) ||                // punycode
      /[^\x00-\x7F]/.test(domain) ||        // non-ASCII
      /-secure\.|verify\.|account\.|login\./.test(domain) ||
      /\.(ru|tk|ml|ga|cf|pw|top|xyz|click)$/i.test(domain)
    )
  } catch { return false }
}

function truncateUrl(url: string, maxLen = 55): string {
  if (url.length <= maxLen) return url
  const half = Math.floor(maxLen / 2)
  return url.slice(0, half) + '…' + url.slice(-half)
}

function ChainEntry({ hop, isLast }: { hop: Hop; isLast: boolean }) {
  const suspicious = hop.is_flagged || hop.is_suspicious
  const color = suspicious ? '#FF0044' : '#E8E8E8'
  const borderColor = suspicious ? '#FF0044' : '#5A5A5A'

  return (
    <div>
      <div
        className="chain-link p-2 my-1 text-xs"
        style={{ borderColor }}
      >
        <div className="flex items-start gap-2">
          <span style={{ color, fontFamily: 'inherit' }} className="font-bold break-all">
            {truncateUrl(hop.url)}
          </span>
          {hop.status_code && (
            <span className="text-brutal-gray shrink-0">[{hop.status_code}]</span>
          )}
          {isLast && suspicious && (
            <span
              className="text-xs px-1 shrink-0"
              style={{ background: '#FF0044', color: '#0A0A0A' }}
            >
              ⚠ FINAL DEST
            </span>
          )}
        </div>
        {hop.homograph_note && (
          <div className="mt-1" style={{ color: '#FF0044' }}>
            ↳ {hop.homograph_note}
          </div>
        )}
      </div>
      {!isLast && (
        <div className="chain-arrow text-sm pl-3">↓ {hop.status_code ?? '3XX'}</div>
      )}
    </div>
  )
}

export default function RedirectChain({ urlResults, homographs, urls }: Props) {
  const entries: Hop[] = []

  const homographDomains = new Set(
    (homographs ?? []).map((h) => {
      try { return new URL(h.url).hostname } catch { return '' }
    }),
  )

  if (urlResults && Object.keys(urlResults).length > 0) {
    for (const [url, info] of Object.entries(urlResults)) {
      const chain: string[] = [url, ...(info.redirect_chain ?? []), info.final_url]
      const unique: string[] = []
      const seen = new Set<string>()
      for (const u of chain) {
        if (u && !seen.has(u)) { seen.add(u); unique.push(u) }
      }

      for (let i = 0; i < unique.length; i++) {
        const u = unique[i]
        let hostname = ''
        try { hostname = new URL(u).hostname } catch { /* */ }
        const isHg = homographDomains.has(hostname)
        const hg   = isHg ? homographs?.find((h) => {
          try { return new URL(h.url).hostname === hostname } catch { return false }
        }) : undefined

        entries.push({
          url: u,
          status_code: i === 0 ? undefined : 301,
          is_suspicious: isSuspiciousDomain(u) || info.is_suspicious,
          is_flagged: i === unique.length - 1 && (info.is_suspicious || isHg),
          homograph_note: hg
            ? `HOMOGRAPH DETECTED — "${hg.brand_imitated}" imitation (${hg.attack_type})`
            : undefined,
        })
      }
    }
  } else if (urls?.length) {
    for (const u of urls) {
      let hostname = ''
      try { hostname = new URL(u).hostname } catch { /* */ }
      const isHg = homographDomains.has(hostname)
      const hg   = isHg ? homographs?.find((h) => {
        try { return new URL(h.url).hostname === hostname } catch { return false }
      }) : undefined

      entries.push({
        url: u,
        is_suspicious: isSuspiciousDomain(u) || isHg,
        is_flagged: isHg,
        homograph_note: hg
          ? `HOMOGRAPH DETECTED — "${hg.brand_imitated}" imitation (${hg.attack_type})`
          : undefined,
      })
    }
  }

  if (entries.length === 0) {
    return (
      <div>
        <div className="text-brutal-gray text-xs mb-2 tracking-widest">
          ── URL REDIRECT CHAINS ────────────────────────────────────────────
        </div>
        <div className="text-brutal-gray text-xs p-3 border border-brutal-gray">
          NO URLS DETECTED IN CONTENT
        </div>
      </div>
    )
  }

  return (
    <div>
      <div className="text-brutal-gray text-xs mb-2 tracking-widest">
        ── URL REDIRECT CHAINS ({entries.length} hop(s)) ──────────────────────────
      </div>
      <div className="border-2 border-brutal-gray p-3">
        {entries.map((hop, i) => (
          <ChainEntry key={i} hop={hop} isLast={i === entries.length - 1} />
        ))}
      </div>
      <div className="text-brutal-gray text-xs mt-1">
        <span className="tt-wrap">
          <span className="underline cursor-help">HOMOGRAPH</span>
          <span className="tt">
            A homograph attack uses visually identical characters from different Unicode scripts (e.g. Cyrillic 'а' vs Latin 'a') to disguise a malicious domain as legitimate.
          </span>
        </span>
        {' '} | {' '}
        <span className="tt-wrap">
          <span className="underline cursor-help">PUNYCODE</span>
          <span className="tt">
            Punycode (xn--) is how non-ASCII domain names are encoded in DNS. Phishers use it to represent homograph characters in domain names.
          </span>
        </span>
      </div>
    </div>
  )
}
