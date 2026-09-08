<script>
  // Hash identifier — length + charset + prefix-pattern matching against a
  // curated algorithm table, entirely client-side. Same heuristics as the
  // classic hashID/hashcat families: identical shapes stay ambiguous by design.
  let input = ''

  const RULES = [
    { name: 'CRC32 / Adler32 (checksum non-kriptografis)', re: /^[0-9a-fA-F]{8}$/ },
    { name: 'MD5 / MD4 / NTLM / RIPEMD-128 / Domain Cached Credentials (32 hex — bentuk sama)', re: /^[0-9a-fA-F]{32}$/ },
    { name: 'Windows NT hash (32 hex, seluruhnya uppercase)', re: /^[0-9A-F]{32}$/ },
    { name: 'LM hash (32 hex uppercase, sepasang 16 per 7 karakter input)', re: /^[0-9A-F]{32}$/ },
    { name: 'MySQL PASSWORD() pra-4.1 (16 hex)', re: /^[0-9a-fA-F]{16}$/ },
    { name: 'SHA-1 / RIPEMD-160 / HAS-160 / SHA-1(dgit) (40 hex — bentuk sama)', re: /^[0-9a-fA-F]{40}$/ },
    { name: 'MySQL 4.1+ / SHA-1 dengan prefiks *', re: /^\*[0-9A-Fa-f]{40}$/ },
    { name: 'SHA-224 (56 hex)', re: /^[0-9a-fA-F]{56}$/ },
    { name: 'SHA-256 · SHA3-256 · keccak-256 · GOST R 34.11-94 (64 hex — ambigu)', re: /^[0-9a-fA-F]{64}$/ },
    { name: 'Hakim-style / hex dengan prefiks 0x (64)', re: /^0x[0-9a-fA-F]{64}$/ },
    { name: 'SHA-384 · SHA3-384 · shake-variants (96 hex)', re: /^[0-9a-fA-F]{96}$/ },
    { name: 'SHA-512 · SHA3-512 (128 hex)', re: /^[0-9a-fA-F]{128}$/ },
    { name: 'bcrypt / bcrypta ($2a$–$2y$, cost 04–31)', re: /^\$2[ab y]?\$[0-9]{2}\$[./A-Za-z0-9]{53}$/ },
    { name: 'argon2 (PHC)', re: /^\$argon2(?:id|m|i)\$v=\d+\$/ },
    { name: 'scrypt (PHC)', re: /^\$scrypt\$/ },
    { name: 'crypt MD5 ($1$, BSD/Dynamic)', re: /^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$/ },
    { name: "crypt BSDi ($2$cost$… 8-digit cost)", re: /^\$2\$\d{8}\$[./A-Za-z0-9]+$/ },
    { name: 'sha256crypt ($5$, round opsional)', re: /^\$5\$(rounds=\$)?([A-Za-z0-9.$/-]{1,16}\$)?[./A-Za-z0-9]{43}$/ },
    { name: 'sha512crypt ($6$, round opsional)', re: /^\$6\$(rounds=\$)?([A-Za-z0-9.$/-]{1,16}\$)?[./A-Za-z0-9]{86}$/ },
    { name: 'APR1 (Apache $apr1$)', re: /^\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$/ },
    { name: 'PHPASS / WordPress ($P$ / $H$)', re: /^\$[PH]\$[./A-Za-z0-9]{31}$/ },
    { name: 'Django PBKDF2 (algo$iter$salt$hash base64)', re: /^pbkdf2(_[a-z0-9]+)?\$\d+\$[A-Za-z0-9._-]{127}$/ },
    { name: 'JWT eyJ… (tiga segmen)', re: /^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\./ },
    { name: 'Bitcoin address (base58 legacy)', re: /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/ },
    { name: 'Base64 murni (panjang %4==0, kemungkinan binary/hashed encoded)', re: /^(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw04]=|[A-Za-z0-9+/]{3}[AEIMQUYcgkosw04]=)?$/ },
  ]

  // Dedupe: identical regexes collapse to one shape label
  function findMatches(v) {
    const seen = new Set()
    return RULES.filter((r) => {
      const k = String(r.re)
      if (seen.has(k)) return false
      seen.add(k)
      try { return r.re.test(v) } catch { return false }
    })
  }

  $: trimmed = input.trim()
  $: matches = trimmed ? findMatches(trimmed) : []
  $: shape = trimmed && /^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0
    ? `${trimmed.length / 2} byte, hex` : trimmed && (trimmed.length % 4 === 0 ? 'kemungkinan base64/binary' : 'opaque')

  let copied = false
  async function copy() {
    await navigator.clipboard.writeText(trimmed)
    copied = true
    setTimeout(() => (copied = false), 1500)
  }
</script>

<div class="tb-panel">
  <p class="tool-modal-desc">Identifikasi kandidat algoritme dari panjang + charset +
    prefiks modular-crypt. Bentuk identik (MD5 vs NTLM vs MD4 → 32 hex) tetap ambigu —
    konteks kolom database asal yang memisahkan.</p>
  <div class="field"><label for="tb-hash">String hash</label>
    <input id="tb-hash" type="text" placeholder="$2b$10$… · 5f4dcc3b… · 2a2f50…" bind:value={input} /></div>

  {#if trimmed}
    <div class="tb-output">
      <div class="field-label">Bentuk: {shape}</div>
      {#if matches.length}
        <ul class="tool-modal-list">
          {#each matches as m}<li>{m.name}</li>{/each}
        </ul>
        {#if matches.length === 1 && matches[0].re.source.length > 40}
          <p class="tool-src">Pola cukup unik — keyakinan bentuk naik, tetap verifikasi
            terhadap sumber aslinya.</p>
        {/if}
      {:else}
        <p class="tb-err">Tidak ada pola tabel yang cocok. Kemungkinan hash binary,
          token acak, atau format proprietary.</p>
      {/if}
      <div class="usage-row">
        <code class="tb-code">{trimmed.length} karakter · {matches.length} kandidat</code>
        <button class="btn sm" onclick={copy}>{copied ? '✓ disalin' : 'salin'}</button>
      </div>
      <p class="tool-src">Catatan etika: identifikasi bukan izin cracking. Crack kredensial
        pihak lain tanpa otorisasi = akses tidak sah.</p>
    </div>
  {/if}
</div>
