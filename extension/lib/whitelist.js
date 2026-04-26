const DEFAULTS = new Set([
  'gmail.com','google.com','github.com','anthropic.com','hackclub.com',
  'vercel.com','linkedin.com','microsoft.com','apple.com','amazon.com',
  'paypal.com','wikipedia.org','stackoverflow.com','youtube.com','reddit.com',
  'twitter.com','x.com','facebook.com','instagram.com','cloudflare.com',
  'stripe.com','notion.so','slack.com','zoom.us','dropbox.com',
  'spotify.com','netflix.com','twitch.tv','discord.com',
]);

export function extractDomain(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); }
  catch { return url; }
}

export async function isWhitelisted(urlOrDomain) {
  const domain = urlOrDomain.includes('://') ? extractDomain(urlOrDomain) : urlOrDomain;
  if (DEFAULTS.has(domain)) return true;
  // check parent domains too (e.g. mail.google.com → google.com)
  const parts = domain.split('.');
  for (let i = 1; i < parts.length - 1; i++) {
    if (DEFAULTS.has(parts.slice(i).join('.'))) return true;
  }
  try {
    const { whitelist = [] } = await chrome.storage.local.get('whitelist');
    return whitelist.some(d => domain === d || domain.endsWith(`.${d}`));
  } catch { return false; }
}
