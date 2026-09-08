<script>
  // Timestamp decoder — pure arithmetic in the browser (Unix s/ms, Windows
  // FILETIME, ISO-8601/RFC strings). No network, no logging.
  let input = ''

  const FILETIME_EPOCH_MS = 11644473600000n // 1601-01-01 → 1970-01-01 (ms)

  function fmt(d) {
    if (isNaN(d.getTime())) return null
    return {
      iso_utc: d.toISOString(),
      iso_local: d.toLocaleString(undefined, { dateStyle: 'full', timeStyle: 'medium' }),
    }
  }

  function decode(raw) {
    const v = raw.trim()
    if (!v) return { kind: null }
    // Windows FILETIME: 18-digit ticks since 1601
    if (/^\d{17,19}$/.test(v)) {
      const ms = Number((BigInt(v) - FILETIME_EPOCH_MS * 10000n) / 10000n)
      const d = new Date(ms)
      return { kind: 'Windows FILETIME (100 ns sejak 1601-01-01)', date: fmt(d), epoch_s: Math.floor(ms / 1000) }
    }
    if (/^\d{13}$/.test(v)) {
      const d = new Date(Number(v))
      return { kind: 'Unix epoch (milidetik)', date: fmt(d), epoch_s: Math.floor(Number(v) / 1000) }
    }
    if (/^\d{10}$/.test(v)) {
      const d = new Date(Number(v) * 1000)
      return { kind: 'Unix epoch (detik)', date: fmt(d), epoch_s: Number(v) }
    }
    const parsed = Date.parse(v)
    if (!isNaN(parsed)) {
      const d = new Date(parsed)
      return { kind: 'String tanggal (ISO-8601 / RFC)', date: fmt(d), epoch_s: Math.floor(parsed / 1000) }
    }
    return { kind: null, invalid: true }
  }

  $: out = decode(input)
  $: filetime = out.epoch_s !== undefined
    ? String(BigInt(out.epoch_s) * 10000000n + FILETIME_EPOCH_MS * 10000n)
    : null
</script>

<div class="tb-panel">
  <p class="tool-modal-desc">Konversi waktu deterministik di sisi klien. Format dikenali
    otomatis: Unix detik/milidetik, Windows FILETIME, ISO-8601.</p>
  <div class="field"><label for="tb-ts">Nilai timestamp</label>
    <input id="tb-ts" type="text" placeholder="1725760000 · 134196480000000000 · 2026-09-08T04:26:40Z"
           bind:value={input} /></div>

  {#if out.invalid}
    <p class="tb-err">Tidak dikenali sebagai timestamp yang valid.</p>
  {:else if out.kind}
    <dl class="tb-kv">
      <dt>Format terdeteksi</dt><dd>{out.kind}</dd>
      <dt>UTC (ISO-8601)</dt><dd>{out.date.iso_utc}</dd>
      <dt>Zona lokal perangkat</dt><dd>{out.date.iso_local}</dd>
      <dt>Unix detik</dt><dd>{out.epoch_s}</dd>
      <dt>Unix milidetik</dt><dd>{out.epoch_s * 1000}</dd>
      {#if filetime}<dt>Windows FILETIME</dt><dd>{filetime}</dd>{/if}
    </dl>
    <p class="tool-src">Untuk bukti: catat sumber &amp; offset zona asli terpisah dari
      nilai terkonversi — rekonstruksi chronolocation butuh konteks itu.</p>
  {/if}
</div>
