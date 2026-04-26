export const C = {
  SAFE:       'SAFE',
  SUSPICIOUS: 'SUSPICIOUS',
  DANGEROUS:  'DANGEROUS',

  COLOR_DANGER:    '#dc2626',
  COLOR_WARNING:   '#d97706',
  COLOR_SAFE:      '#16a34a',
  COLOR_PRIMARY:   '#4f46e5',
  COLOR_BG_DANGER: '#fff1f1',
  COLOR_BG_WARN:   '#fffbee',
  COLOR_BG_SAFE:   '#f0fff6',
  COLOR_BORDER:    '#1a1a1a',

  MSG: {
    BLOCK_TITLE:      'Phishing site detected',
    BLOCK_SUBTITLE:   (b) => `This site impersonates ${b || 'a trusted brand'}. Do not enter any information.`,
    SENTINEL_TITLE:   'Stop — this site is suspicious',
    SENTINEL_BODY:    (b) => `This site may be impersonating ${b || 'a trusted brand'}. Entering your password could expose your real account.`,
    BANNER_TEXT:      (s) => `This site looks suspicious — risk score ${s}/100.`,
    CLIPBOARD_TITLE:  'Suspicious URL copied',
    CLIPBOARD_BODY:   (d, s) => `The link you copied is flagged: ${d} — ${s}/100`,
  },

  PRODUCTION_APP:     'https://phishingo-zk3c.vercel.app',
  DEFAULT_BACKEND:    'https://phishingo-production.up.railway.app',
  LOG_PREFIX:         '[PhishFilter]',
  LINK_HOVER_DELAY:   800,
};
