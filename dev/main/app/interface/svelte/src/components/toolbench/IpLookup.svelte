<script>
  // IP lookup — satu-satunya tool Toolbench yang inheren butuh jaringan
  // (geolokasi + ASN tidak dapat dihitung lokal). Memakai penyedia publik
  // tanpa akun; tidak ada data yang disimpan Cyense.
  let input = ''
  let result = null
  let error = ''
  let loading = false

  function isIp(v) {
    const t = v.trim()
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) return t.split('.').every((o) => +o <= 255)
    if (/^[0-9a-fA-F:]+$/.test(t) && t.includes(':')) return true
    return false
  }

  async function lookup() {
    error = ''; result = null
    const v = input.trim()
    if (!v) { error = 'Isi alamat IP.'; return }
    if (!isIp(v)) { error = 'Bukan format IPv4/IPv6.'; return }
    loading = true
    try {
      const r = await fetch(`https://ipwho.is/${encodeURIComponent(v)}?lang=id`)
      const j = await r.json()
      if (j.success === false) throw new Error(j.message || 'lookup gagal')
      result = j
    } catch (e) {
      error = String(e.message || e) + ' — penyedia mungkin rate-limited; coba lagi atau pakai RDAP/RIR untuk attribution.'
    } finally {
      loading = false
    }
  }

  $: can = input && isIp(input) && !loading
</script>

<div class="tb-panel">
  <p class="tool-modal-desc">Geolokasi + ASN/ISP kasar dari penyedia publik. Ingat
    keterbatasan (OSINT Radar §B10): kota bisa salah puluhan–ratusan km; IP
    mengidentifikasi koneksi, bukan orang.</p>
  <div class="field"><label for="tb-ip">Alamat IP (IPv4/IPv6)</label>
    <input id="tb-ip" type="text" bind:value={input} placeholder="8.8.8.8" onkeydown={(e) => e.key === 'Enter' && lookup()} /></div>
  <button class="btn primary sm" onclick={lookup} disabled={!can}>{loading ? 'mencari…' : 'Lookup'}</button>

  {#if error}<p class="tb-err">{error}</p>{/if}
  {#if result}
    <div class="tb-output">
      <dl class="tb-kv">
        <dt>Lokasi</dt><dd>{[result.city, result.region, result.country].filter(Boolean).join(', ') || '—'} ({result.country_code || '?'})</dd>
        <dt>Latitude / Longitude</dt><dd>{result.latitude}, {result.longitude}</dd>
        <dt>ISP</dt><dd>{result.connection?.isp} · {result.connection?.org || result.connection?.domain || ''}</dd>
        <dt>ASN</dt><dd>{result.connection?.asn ?? '—'}</dd>
        <dt>Timezone</dt><dd>{result.timezone?.id || '—'} (UTC{result.timezone?.utc || ''})</dd>
        <dt>Tipe koneksi</dt><dd>{result.connection?.type || '—'} · mobile={String(result.connection?.mobile ?? '—')}</dd>
      </dl>
      <div class="usage-row">
        <span class="tool-src">Verifikasi silang: <a href="https://rdap.org/ip/{encodeURIComponent(input.trim())}" target="_blank" rel="noopener noreferrer">RDAP</a>
          · <a href="https://search.censys.io/search?resource=hosts&q={encodeURIComponent(input.trim())}" target="_blank" rel="noopener noreferrer">Censys</a></span>
        <button class="btn sm" onclick={() => navigator.clipboard.writeText(JSON.stringify(result, null, 2))}>salin JSON</button>
      </div>
    </div>
  {/if}
</div>
