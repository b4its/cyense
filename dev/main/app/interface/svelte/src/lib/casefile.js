// Case File — light evidence bundle, OSINT Radar style: tools saved while
// investigating, copied/exported later. Persisted in localStorage only
// (client-side; survives reloads, lost with cache — see disclaimer in UI).

import { writable, derived } from 'svelte/store'

const KEY = 'cyense.casefile.v1'

function load() {
  try {
    const raw = localStorage.getItem(KEY)
    const arr = raw ? JSON.parse(raw) : []
    return Array.isArray(arr) ? arr : []
  } catch {
    return []
  }
}

function persist(items) {
  try { localStorage.setItem(KEY, JSON.stringify(items)) } catch { /* private mode */ }
}

const initial = typeof localStorage !== 'undefined' ? load() : []
export const caseFile = writable(initial)

// Mirror writes to storage on every change.
caseFile.subscribe(persist)

export const caseCount = derived(caseFile, (v) => v.length)

export function isInCaseFile(items, name) {
  return items.some((it) => it.name === name)
}

export function addToCaseFile(items, tool) {
  if (isInCaseFile(items, tool.name)) return items
  return [...items, {
    name: tool.name,
    category: tool.category || '',
    url: tool.url || '',
    description: (tool.description || '').slice(0, 300),
    pricing: tool.pricing || '',
    source: tool.source_page || '',
    addedAt: new Date().toISOString(),
    note: '',
  }]
}

export function removeFromCaseFile(items, name) {
  return items.filter((it) => it.name !== name)
}

export function setNote(items, name, note) {
  return items.map((it) => (it.name === name ? { ...it, note } : it))
}

// ── exports ────────────────────────────────────────────────────────────────
// Markdown bundle follows the Reporting Checkpoints discipline: every entry
// carries source + collection time + note, and the bundle gets an integrity
// hash (SHA-256 over the exact Markdown body) when crypto.subtle is
// available — the "hashable export" the analysis recommends over plain
// localStorage copies.

export async function buildCaseMarkdown(items) {
  const stamp = new Date().toISOString()
  const head = `# Cyense — Case File\n\nDiekspor: ${stamp} · ${items.length} entri · penyimpanan lokal (browser)`
  const sections = items.map((it, i) => {
    const src = it.source ? `\n- Entri asal: ${it.source}` : ''
    const note = it.note ? `\n- Catatan (observed result): ${it.note.replace(/\n+/g, ' ')}` : ''
    return [
      `## ${i + 1}. ${it.name}`,
      `- Kategori: ${it.category}${it.pricing ? ` · ${it.pricing}` : ''}`,
      `- Target value: ${it.url || '—'}`,
      `- Koleksi (source and time): ${it.addedAt}${src}${note}`,
    ].join('\n')
  })
  const body = [head, ...sections].join('\n\n') + '\n'
  const hash = await sha256Text(body)
  const tail = hash
    ? `\n---\nIntegritas bundel — SHA-256 dari seluruh isi berkas ini (tanpa baris hash): \`${hash}\`\n`
    : `\n---\nHash integritas tidak tersedia (crypto.subtle tidak ada di konteks ini).\n`
  return { body, hash, text: body + tail }
}

async function sha256Text(text) {
  if (!globalThis.crypto?.subtle) return null
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, '0')).join('')
}

export function download(filename, text) {
  const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = filename
  a.click()
  URL.revokeObjectURL(a.href)
}
