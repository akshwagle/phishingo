import { C } from './constants.js';

const log = (...a) => console.log(C.LOG_PREFIX, ...a);

export async function getBackendUrl() {
  try {
    const { backendUrl } = await chrome.storage.local.get('backendUrl');
    return (backendUrl || C.DEFAULT_BACKEND).replace(/\/$/, '');
  } catch { return C.DEFAULT_BACKEND; }
}

async function fetchWithTimeout(url, opts = {}, timeoutMs = 5000) {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { ...opts, signal: ctrl.signal });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return await resp.json();
  } finally {
    clearTimeout(id);
  }
}

export async function checkUrlQuick(url) {
  const base = await getBackendUrl();
  return fetchWithTimeout(`${base}/api/url-quick`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ url }),
  }, 5000);
}

export async function analyzeFull(content, inputType = 'text') {
  const base = await getBackendUrl();
  return fetchWithTimeout(`${base}/api/analyze`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ input_type: inputType, content }),
  }, 90000);
}

export async function analyzePage(pageData) {
  const base = await getBackendUrl();
  return fetchWithTimeout(`${base}/api/page-scan`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(pageData),
  }, 60000);
}

export async function getHealth() {
  try {
    const base = await getBackendUrl();
    return await fetchWithTimeout(`${base}/api/health`, {}, 5000);
  } catch { return null; }
}
