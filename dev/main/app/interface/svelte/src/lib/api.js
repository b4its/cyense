// Cyense API client — talks to the FastAPI backend (/api/v1/*).
const BASE = '/api/v1'

async function req(path, opts = {}) {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  })
  if (!res.ok) {
    let detail = res.statusText
    try { const j = await res.json(); detail = j.detail || JSON.stringify(j) } catch { /* noop */ }
    throw new Error(`${res.status}: ${detail}`)
  }
  if (res.status === 204) return null
  return res.json()
}

export const api = {
  health: () => req('/health'),
  rules: () => req('/rules'),
  listScans: () => req('/scans'),
  websites: () => req('/websites'),
  getScan: (id) => req(`/scans/${id}`),
  getReport: (id) => req(`/scans/${id}/report`),
  submitScan: (payload) => req('/scans', { method: 'POST', body: JSON.stringify(payload) }),
  getCoverage: (id) => req(`/scans/${id}/coverage`),
  proposeFixes: (id) => req(`/scans/${id}/fixes`, { method: 'POST', body: JSON.stringify({}) }),
  getFixes: (session) => req(`/fixes/${session}`),
  getFixDiff: async (session) => {
    const res = await fetch(`${BASE}/fixes/${session}/diff`)
    if (!res.ok) throw new Error(res.statusText)
    return res.text()
  },
}

// Severity ordering + badge mapping used across views.
export const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

export function sevRank(s) { return SEV_ORDER[s?.toLowerCase()] ?? 5 }

export function fmtDuration(ms) {
  if (!ms) return '—'
  if (ms < 1000) return `${ms} ms`
  return `${(ms / 1000).toFixed(2)} s`
}

export function fmtTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return isNaN(d) ? iso : d.toLocaleString('id-ID', { dateStyle: 'medium', timeStyle: 'short' })
}
