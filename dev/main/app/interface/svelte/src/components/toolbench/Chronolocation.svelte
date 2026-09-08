<script>
  // Chronolocation — §B9's "Sun Calculator" as a local tool: forward (date+time
  // → azimuth & elevation & shadow length/metre) and reverse (observed shadow
  // bearing/length → UTC times on a date). §4.2 Toolbench extension — honest
  // about its error bars: a probable/lead signal, never proof.
  import { sunPosition, findTimesForElevation, shadowPerMetre, elevationFromShadow } from '../../lib/solar.js'

  let lat = '51.5074'
  let lon = '-0.1278'
  let iso = '2026-06-21T11:52'
  let hgt = ''
  let shd = ''
  let elevTarget = ''

  $: latN = parseFloat(lat)
  $: lonN = parseFloat(lon)
  $: valid = isFinite(latN) && isFinite(lonN) && Math.abs(latN) <= 90 && Math.abs(lonN) <= 180
  $: t = iso ? new Date(iso + (iso.length === 16 ? ':00Z' : (/[+Z]/.test(iso) ? '' : 'Z'))) : null
  $: fwd = valid && t && !isNaN(t.getTime()) ? sunPosition(latN, lonN, t) : null
  $: shadowM = fwd && fwd.elevation > 0.05 ? shadowPerMetre(fwd.elevation) : null
  $: reverseElev = elevationFromShadow(parseFloat(hgt), parseFloat(shd))
  // NOTE null-safe: elevationFromShadow returns null for empty inputs, and
  // isFinite(null) is TRUE — guard by type, not by finiteness alone.
  $: reverseElevOk = typeof reverseElev === 'number' && reverseElev > 0
  $: reverseTimes = valid && reverseElevOk && iso
    ? findTimesForElevation(latN, lonN, new Date((iso.slice(0, 10)) + 'T00:00:00Z'), reverseElev)
    : []
  $: manual = valid && elevTarget !== '' ? findTimesForElevation(latN, lonN, new Date((iso.slice(0, 10)) + 'T00:00:00Z'), parseFloat(elevTarget)) : []
</script>

<div class="tb-panel">
  <p class="tool-modal-desc">Chronolocation dari matahari — maju (waktu → azimuth
    matahari &amp; panjang bayangan) dan mundur (bayangan terukur di foto →
    kandidat jam UTC). Deterministik, tanpa jaringan, ±~0.1° (1990–2050).
    <b>Ini lead, bukan konfirmasi.</b></p>

  <div class="tb-form">
    <div class="field"><label for="cl-lat">Latitude</label>
      <input id="cl-lat" type="text" bind:value={lat} /></div>
    <div class="field"><label for="cl-lon">Longitude</label>
      <input id="cl-lon" type="text" bind:value={lon} /></div>
    <div class="field"><label for="cl-iso">Tanggal &amp; waktu (lokal, tanpa offset = UTC)</label>
      <input id="cl-iso" type="text" bind:value={iso} placeholder="YYYY-MM-DDTHH:MM" /></div>
  </div>

  {#if !valid}
    <p class="tb-err">Lat/lon tidak valid.</p>
  {/if}

  {#if fwd && valid}
    <div class="tb-output">
      <h3 class="tool-modal-h" style="margin-top:0">Posisi matahari pada {t.toISOString().replace('.000','')}</h3>
      <dl class="tb-kv">
        <dt>Azimuth (dari utara, searah jarum jam)</dt><dd class="tb-mono">{fwd.azimuth.toFixed(2)}°</dd>
        <dt>Elevasi</dt><dd class="tb-mono">{fwd.elevation.toFixed(2)}°</dd>
        {#if fwd.elevation > 0.05}
          <dt>Bayangan per meter objek tegak</dt><dd class="tb-mono">{shadowM.toFixed(3)} m</dd>
          <dt>Arah bayangan</dt><dd class="tb-mono">{((fwd.azimuth + 180) % 360).toFixed(2)}° (matahari {fwd.azimuth < 180 ? 'timur' : 'barat'})</dd>
        {:else}
          <dt>Matahari</dt><dd>di bawah horizon — tidak ada bayangan langsung</dd>
        {/if}
        <dt>Deklinasi matahari</dt><dd class="tb-mono">{fwd.declination.toFixed(3)}°</dd>
      </dl>
    </div>
  {/if}

  <div style="margin-top:14px">
    <h3 class="tool-modal-h" style="margin:0 0 6px">Mundur — ukur dari foto</h3>
    <div class="tb-form">
      <div class="field"><label for="cl-h">Tinggi objek tegak (m)</label>
        <input id="cl-h" type="text" bind:value={hgt} placeholder="2" /></div>
      <div class="field"><label for="cl-s">Panjang bayangan (m)</label>
        <input id="cl-s" type="text" bind:value={shd} placeholder="2.4" /></div>
      <div class="field"><label for="cl-e">…atau elevasi langsung (°)</label>
        <input id="cl-e" type="text" bind:value={elevTarget} placeholder="45" /></div>
    </div>
    {#if reverseElevOk}
      <p class="tool-src">Elevasi dari rasio tinggi/bayangan: <b>{reverseElev.toFixed(2)}°</b> — kandidat waktu pada tanggal {iso.slice(0,10)}:</p>
      {#if reverseTimes.length}
        <ul class="tool-modal-list">
          {#each reverseTimes as d}<li>{d.toISOString()}</li>{/each}
        </ul>
      {:else}<p class="muted">Tidak ada waktu pada tanggal itu dengan elevasi ini (mis. matahari tinggi maksimum &lt; target).</p>{/if}
    {/if}
    {#if manual.length && !reverseElevOk}
      <p class="tool-src">Elevasi {elevTarget}° tercapai pada {manual.length}× — UTC:</p>
      <ul class="tool-modal-list">
        {#each manual as d}<li>{d.toISOString()}</li>{/each}
      </ul>
    {/if}
    {#if reverseElevOk || (elevTarget !== "" && manual.length)}
      <p class="cat-note" style="margin-top:8px">Kaidah pelaporan (OSINT Radar workflow <code>verify-an-image</code>):
        korelasikan dengan arah bayangan (kompas) &amp; zona waktu klaim; tandai
        <b>probable</b> bila satu-satunya sumber, jangan <b>confirmed</b> tanpa korroborasi
        (metafile, cuaca, konteks arsip).</p>
    {/if}
  </div>
</div>
