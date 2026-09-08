// Minimal, dependency-free RFC 5322 header analyzer — runs fully client-side.
// Unfolds continuation lines, walks the Received: chain (top = newest hop is
// appended last in RFC order, so oldest = closest to origin = end of chain),
// and reads SPF/DKIM/DMARC verdicts out of Authentication-Results (plain as
// well as [1]indexed style).

const IPV4_RE = /\[?(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])\]?/
const IPV6_RE = /\[((?:[0-9a-fA-F:]+))\]/
// Received by:  from <host> (<host> [ip])?  by <host>; with <proto>

export function analyze_headers(raw) {
  const block = raw.split(/\r?\n\s*\r?\n/)[0]
  const lines = unfold(block)

  const headers = {}
  for (const line of lines) {
    const idx = line.indexOf(':')
    if (idx < 0) continue
    const name = line.slice(0, idx).trim()
    const value = line.slice(idx + 1).trim()
    ;(headers[name.toLowerCase()] ||= []).push(value)
  }

  const envelope = {
    from: (headers['from'] || [null])[0],
    returnPath: (headers['return-path'] || [null])[0],
    replyTo: (headers['reply-to'] || [null])[0],
    to: (headers['to'] || [null])[0],
    subject: (headers['subject'] || [null])[0],
    messageId: (headers['message-id'] || [null])[0],
    date: (headers['date'] || [null])[0],
    xMailer: (headers['x-mailer'] || [null])[0],
  }

  // ── Received chain (chronological: origin first) ─────
  const hops = []
  for (const r of [...(headers['received'] || [])].reverse()) {
    hops.push(parse_received(r))
  }

  const originIp = (() => {
    // The deepest client IP — last hop whose IP is not the receiving MX itself.
    for (const h of hops) {
      if (h.ip && !isPrivate(h.ip)) return h.ip
    }
    for (const h of hops) if (h.ip) return h.ip
    return null
  })()

  // ── Authentication-Results / SPF / DKIM / DMARC ──────
  const auth = []

  const allAuth = [...(headers['authentication-results'] || []),
    ...(headers['received-spf'] || []), ...(headers['dkim-signature'] || []),
    ...(headers['dmarc-signature'] || [])]
  // received-spf / dkim-signature are different formats — handle separately.
  for (const a of headers['authentication-results'] || []) {
    // "spf=pass smtp.mailfrom=…; dkim=pass header.d=…; dmarc=pass header.from=…"
    // one mech per ';'-separated segment (a trailing comment in parentheses
    // after a verdict may itself contain ';' — the mech=verdict anchor is
    // segment-leading so those never produce false hits).
    for (const seg of a.split(';')) {
      const m = seg.match(/\b(spf|dkim|dmarc|arc)=(pass|fail|neutral|softfail|permerror|temperror|none)(.*)$/i)
      if (!m) continue
      const [, mech, verdict, rest] = m
      const detail = rest.trim().slice(0, 120)
      auth.push({ mech: mech.toLowerCase(), verdict, detail })
    }
  }
  for (const r of headers['received-spf'] || []) {
    const m = r.match(/spf-(\w+)/i)
    auth.push({ mech: 'spf', verdict: m ? m[1].toLowerCase() : '', detail: r.slice(0, 140) })
  }

  return { envelope, hops, originIp, auth }
}

function unfold(headerBlock) {
  // Join continuation lines (CRLF + WSP) into single logical lines.
  const parts = []
  let cur = ''
  for (const line of headerBlock.replace(/\r\n/g, '\n').split('\n')) {
    if (/^[ \t]/.test(line)) { cur += ' ' + line.trim(); continue }
    if (cur) parts.push(cur)
    cur = line
  }
  if (cur) parts.push(cur)
  return parts
}

function parse_received(value) {
  const hop = { raw: value, date: null, from: null, by: null, with: null,
    ip: null, rdns: null, isPrivate: false }
  // date after the last ';'
  const dm = value.match(/;\s*(.+)$/s)
  if (dm) {
    hop.date = dm[1].trim()
    hop.rawCore = value.slice(0, value.lastIndexOf(';')).trim()
  }
  const core = value // simpler regex on whole string, stopping at ';' date:
  const from = core.match(/\bfrom\s+([^\s(;]+)(?:\s*\(([^)]*)\))?/)
  hop.from = from ? from[1] : null
  const by = core.match(/\bby\s+([^\s(;]+)/)
  hop.by = by ? by[1] : null
  const withp = core.match(/\bwith\s+([A-Z][A-Z0-9]*)/i)
  hop.with = withp ? withp[1].toUpperCase() : null

  // IPs — the bracketed client addr is conventionally the connecting host:
  const bracket = core.match(/\[((?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:.]+)\]/)
  if (bracket && looksLikeIp(bracket[1])) { hop.ip = bracket[1] }
  else {
    const alt = core.match(IPV4_RE) || core.match(IPV6_RE)
    if (alt) hop.ip = alt[1]
  }
  const rdm = core.match(/\(\s*([A-Za-z0-9._-]+)\s+\[(?:\d{1,3}\.){3}\d{1,3}\)/)
  if (rdm) hop.rdns = rdm[1]
  if (hop.ip) hop.isPrivate = isPrivate(hop.ip)
  return hop
}

function looksLikeIp(s) {
  return /\./.test(s) || /:/.test(s)
}

function isPrivate(ip) {
  const t = ip.toLowerCase()
  if (/^127\./.test(t) || /^10\./.test(t) || /^192\.168\./.test(t) || /^172\.(1[6-9]|2\d|3[01])\./.test(t)) return true
  if (/^169\.254\./.test(t) || /^0\./.test(t)) return true
  if (/^(fe80|fd|::1)/.test(t)) return true
  const m = t.match(/^100\.(6[45-9]|[7-9]\d|1[01]\d|12[0-7])\./)
  if (m) return true
  return false
}
