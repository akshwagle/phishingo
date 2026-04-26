const STAT_KEYS = ['sitesBlocked', 'linksScanned', 'passwordsProtected', 'phishesCaught'];

export async function getStats() {
  const data = await chrome.storage.local.get(STAT_KEYS);
  return {
    sitesBlocked:       data.sitesBlocked       || 0,
    linksScanned:       data.linksScanned       || 0,
    passwordsProtected: data.passwordsProtected || 0,
    phishesCaught:      data.phishesCaught      || 0,
  };
}

export async function incrementStat(name) {
  const d = await chrome.storage.local.get(name);
  await chrome.storage.local.set({ [name]: (d[name] || 0) + 1 });
}

export async function getWhitelist() {
  const { whitelist } = await chrome.storage.local.get('whitelist');
  return whitelist || [];
}

export async function addToWhitelist(domain) {
  const list = await getWhitelist();
  if (!list.includes(domain)) {
    list.push(domain);
    await chrome.storage.local.set({ whitelist: list });
  }
}

export async function removeFromWhitelist(domain) {
  const list = await getWhitelist();
  await chrome.storage.local.set({ whitelist: list.filter(d => d !== domain) });
}

export async function getSettings() {
  const defaults = {
    sensitivity: 'medium',
    soundAlerts:  false,
    autoBlock:    true,
    backendUrl:   '',
  };
  const data = await chrome.storage.local.get(Object.keys(defaults));
  return { ...defaults, ...data };
}

export async function saveSettings(patch) {
  await chrome.storage.local.set(patch);
}
