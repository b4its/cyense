<script>
  // Coordinate converter — DMS ⇄ decimal ⇄ UTM (WGS84), pure client-side math.
  // §4.2 recommends this as the first Toolbench extension (strengthens the
  // differential advantage without adding any data responsibilities).
  import { parseInput, latlonToUtm, utmToLatlon, fmtDms } from '../../lib/coords.js'

  let input = ''

  function compute(raw) {
    const v = (raw || '').trim()
    if (!v) return null
    const spec = parseInput(v)
    if (!spec) return { error: 'Format tidak dikenali. Coba: `40.785, -73.968` · `40°47′6.3″N 73°58′5.5″W` · `18T 587057 4515412`.' }
    if (spec.kind === 'utm') {
      const ll = utmToLatlon(spec.zone, spec.band, spec.easting, spec.northing)
      return {
        input: `${spec.zone}${spec.band} ${spec.easting} ${spec.northing}`,
        kind: 'UTM', lat: ll.lat, lon: ll.lon,
      }
    }
    const { lat, lon } = spec
    const u = latlonToUtm(lat, lon)
    return {
      input: v, kind: 'pair', lat, lon,
      utm: `${u.zone}${u.band} ${u.easting.toFixed(1)} ${u.northing.toFixed(1)}`,
    }
  }

  $: result = compute(input)

  let copied = false
  async function copy() {
    const text = result?.utm ||
      `${result?.lat?.toFixed(6)}, ${result?.lon?.toFixed(6)}`
    await navigator.clipboard.writeText(text)
    copied = true
    setTimeout(() => (copied = false), 1500)
  }
</script>

<div class="tb-panel">
  <p class="tool-modal-desc">Konversi DMS ⇄ desimal ⇄ UTM (WGS84) — matematika murni di
    browser (Snyder/USGS), round-trip diverifikasi &lt;1e-13°. Berguna saat membandingkan
    koordinat dari sumber yang memakai proyeksi berbeda.</p>
  <div class="field"><label for="tb-cc">Koordinat</label>
    <input id="tb-cc" type="text" bind:value={input}
           placeholder="40.785, -73.968  ·  40°47′6.3″N 73°58′5.5″W  ·  18T 587057 4515412" /></div>

  {#if result?.error}
    <p class="tb-err">{result.error}</p>
  {:else if result}
    <div class="tb-output">
      <dl class="tb-kv">
        <dt>Tipe input</dt><dd>{result.kind}</dd>
        <dt>Desimal</dt><dd class="tb-mono">{result.lat.toFixed(6)}, {result.lon.toFixed(6)}</dd>
        <dt>DMS</dt><dd>{fmtDms(result.lat, 'lat')} {fmtDms(result.lon, 'lon')}</dd>
        {#if result.utm}<dt>UTM</dt><dd class="tb-mono">{result.utm}</dd>{/if}
      </dl>
      <div class="usage-row">
        <span class="tool-src">Lihat di peta (eksternal):
          <a href="https://www.google.com/maps?q={result.lat},{result.lon}" target="_blank" rel="noopener noreferrer">Google Maps</a>
          · <a href="https://www.openstreetmap.org/?mlat={result.lat}&mlon={result.lon}#map=15/{result.lat}/{result.lon}" target="_blank" rel="noopener noreferrer">OSM</a></span>
        <button class="btn sm" onclick={copy}>{copied ? '✓ disalin' : 'salin'}</button>
      </div>
    </div>
  {/if}
</div>
