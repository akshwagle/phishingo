export const QUICK_TTL = 5  * 60 * 1000;  // 5 min
export const URL_TTL   = 10 * 60 * 1000;  // 10 min

export const cache = {
  async get(key) {
    try {
      const data = await chrome.storage.session.get(key);
      const entry = data[key];
      if (!entry) return null;
      if (entry.expiresAt < Date.now()) {
        chrome.storage.session.remove(key);
        return null;
      }
      return entry.value;
    } catch { return null; }
  },

  async set(key, value, ttlMs) {
    try {
      await chrome.storage.session.set({ [key]: { value, expiresAt: Date.now() + ttlMs } });
    } catch { /* session storage full — ignore */ }
  },

  async remove(key) {
    try { await chrome.storage.session.remove(key); } catch { /* ignore */ }
  },
};
