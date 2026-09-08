// WARC integrity checker (ISO 28500 subset) — parse records client-side and
// verify declared WARC record/payload digests. §4.2 Toolbench extension:
// chain-of-custody verification of archived evidence ("WARC needing replay
// tools" limitation in §B2 answered locally). Gzip'd .warc.gz must be
// decompressed first — reported honestly instead of mis-parsed.

const CRLF = [13, 10]

export function isWarcGzip(view) {
  return view[0] === 0x1f && view[1] === 0x8b
}

/**
 * Parse + verify a WARC ArrayBuffer. Returns {records, errors} where each
 * record = {offset, warcType, recordId, date, contentType, contentLength,
 *   declared:{algo, value}, computedSha1?, computedSha256?, status:
 *   'ok'|'mismatch'|'no-digest'|'algo-unavailable'}.
 */
export async function checkWarc(buf) {
  const d = new DataView(buf)
  const u = new Uint8Array(buf)
  const dec = new TextDecoder('latin1')
  const records = []
  const errors = []
  if (isWarcGzip(u)) {
    return { records, errors: ['warc.gz terdeteksi — dekompresi dulu (gzip -d / gunzip) lalu periksa berkas .warc.'] }
  }
  let o = 0
  let n = 0
  while (true) {
    // skip inter-record padding (CRLFs/spaces)
    while (o < u.length && (u[o] === 0x0d || u[o] === 0x0a || u[o] === 0x20)) o++
    if (o >= u.length) break
    const lineEnd = indexOfLine(u, o)
    const line = dec.decode(u.subarray(o, lineEnd))
    if (!line.startsWith('WARC/')) {
      errors.push(`offset ${o}: bukan baris versi WARC: ${JSON.stringify(line.slice(0, 40))}`)
      break
    }
    o = lineEnd + 2 // consume CRLF
    // headers up to blank line
    const headers = {}
    while (o < u.length) {
      const e = indexOfLine(u, o)
      const h = dec.decode(u.subarray(o, e))
      o = e + 2
      if (h === '' || h === '\r') break
      const i = h.indexOf(':')
      if (i > 0) headers[h.slice(0, i).trim().toLowerCase()] = h.slice(i + 1).trim()
    }
    const cl = parseInt(headers['content-length'] || '-1', 10)
    if (!(cl >= 0)) { errors.push(`offset ${o}: Content-Length hilang/tidak valid`); break }
    if (o + cl > u.length) { errors.push(`offset ${o}: blok melewati akhir berkas (truncated)`); break }
    const block = u.subarray(o, o + cl)
    o += cl
    n += 1
    const rec = {
      index: n,
      offset: o - cl,
      version: line.trim(),
      warcType: headers['warc-type'] || '',
      recordId: headers['warc-record-id'] || '',
      date: headers['warc-date'] || '',
      contentType: headers['content-type'] || '',
      contentLength: cl,
      declared: null,
      computed: {},
      status: 'no-digest',
    }
    if (headers['digest']) {
      rec.declared = parseDigest(headers['digest'])
    }
    // verify only the whole record block after version-line is standard for
    // WARC-Record-ID digests — WARC spec: digest of the entire record block.
    const algos = new Set([rec.declared?.algo || '', 'sha256'])
    for (const a of ['sha1', 'sha256']) {
      if (!algos.has(a)) continue
      try {
        rec.computed[a] = await shaHex(block, a)
      } catch {
        if (rec.declared?.algo === a) rec.status = 'algo-unavailable'
      }
    }
    if (rec.declared && rec.computed[rec.declared.algo] !== undefined) {
      let decl = rec.declared.value
      if (rec.declared.enc === 'base64') decl = b64hex(decl)
      else if (rec.declared.enc === 'base32') decl = b32hex(decl)
      rec.status = decl && decl.toLowerCase() === rec.computed[rec.declared.algo] ? 'ok' : 'mismatch'
    }
    records.push(rec)
  }
  return { records, errors }
}

function indexOfLine(u, start) {
  for (let i = start; i < u.length - 1; i++) {
    if (u[i] === CRLF[0] && u[i + 1] === CRLF[1]) return i
  }
  return u.length
}

function parseDigest(raw) {
  // forms: "sha1:HEX", "sha256:HEX", "urn:sha1:BASE32", "sha-256-BASE64"
  let m = raw.match(/^(sha-?1|sha-?256)[:\-]([A-Za-z0-9+/=]+)$/i)
  if (m) {
    const algo = /1$/.test(m[1].toLowerCase().replace('-', '')) ? 'sha1' : 'sha256'
    const v = m[2]
    let enc = 'hex'
    if (/^[0-9a-fA-F]+$/.test(v) && v.length === (algo === 'sha1' ? 40 : 64)) enc = 'hex'
    else if (/^[A-Za-z2-7]+=*$/.test(v)) enc = 'base32'
    else enc = 'base64'
    return { algo, value: v, enc }
  }
  m = raw.match(/^urn:(sha-?1|sha-?256)[:\-]([A-Za-z0-9+/=]+)$/i)
  if (m) {
    const algo = /1/.test(m[1].toLowerCase()) ? 'sha1' : 'sha256'
    return { algo, value: m[2], enc: 'base32' }
  }
  m = raw.match(/^(sha-?1|sha-?256)-([0-9a-fA-F]+)$/i)
  if (m) return { algo: m[1].toLowerCase().includes('256') ? 'sha256' : 'sha1', value: m[2], enc: 'hex' }
  m = raw.match(/^(sha-?1|sha-?256)-([A-Za-z0-9+/=]+)$/i)
  if (m) return { algo: m[1].toLowerCase().includes('256') ? 'sha256' : 'sha1', value: m[2], enc: 'base64' }
  return { algo: 'unknown', value: raw, enc: 'raw' }
}

async function shaHex(bytes, algo) {
  const name = algo === 'sha1' ? 'SHA-1' : 'SHA-256'
  const h = await crypto.subtle.digest(name, bytes)
  return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, '0')).join('')
}

function b64hex(v) {
  try {
    const bin = atob(v)
    return [...bin].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
  } catch { return null }
}
// RFC 4648 base32 (upper alphabet used by urn:sha1:) → hex
function b32hex(v) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const c of v.toUpperCase()) {
    const i = A.indexOf(c)
    if (i < 0) return null
    bits += i.toString(2).padStart(5, '0')
  }
  let hex = ''
  for (let i = 0; i + 4 <= bits.length; i += 4) hex += parseInt(bits.slice(i, i + 4), 2).toString(16)
  return hex
}
