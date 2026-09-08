<script>
  // Image metadata / EXIF — file is read via FileReader in the browser; the
  // bytes never leave the machine except the SHA-256 digest computed locally.
  import { readExif } from '../../lib/exif.js'

  let result = null
  let busy = false
  let error = ''

  async function handleFile(e) {
    const f = e.target.files?.[0]
    error = ''; result = null
    if (!f) return
    if (f.size > 40 * 1024 * 1024) { error = 'Berkas > 40 MB — periksa lokal dengan exiftool.'; return }
    busy = true
    try {
      result = await readExif(f)
    } catch (err) {
      error = String(err?.message || err)
    } finally {
      busy = false
    }
  }

  $: meta = [
    ['Ukuran', `${((result?.size || 0) / 1024).toFixed(1)} KiB`],
    ['Tipe', result?.type || '?'],
    ['Format', result?.format || '?'],
  ]
</script>

<div class="tb-panel">
  <p class="tool-modal-desc">Baca EXIF/XMP dasar (kamera, timestamp, GPS bila ada) +
    hash SHA-256 berkas untuk chain-of-custody. 100% lokal via <code class="wf-conf">FileReader</code>.</p>
  <div class="field"><label for="tb-img">Berkas gambar (JPEG/PNG)</label>
    <input id="tb-img" type="file" accept="image/*" onchange={handleFile} /></div>
  {#if busy}<p class="tool-src">memproses…</p>{/if}
  {#if error}<p class="tb-err">{error}</p>{/if}

  {#if result}
    <div class="tb-output">
      <dl class="tb-kv">
        {#each meta as [k, v]}<dt>{k}</dt><dd>{v}</dd>{/each}
        {#if result.sha256}
          <dt>SHA-256</dt><dd class="tb-mono tb-break" title={result.sha256}>{result.sha256.slice(0, 32)}…</dd>
        {:else}
          <dt>SHA-256</dt><dd class="tb-err">crypto.subtle tidak tersedia (sajikan via https/localhost untuk hash)</dd>
        {/if}
        {#each Object.entries(result.exif) as [k, v]}
          <dt>{k}</dt><dd>{v}</dd>
        {/each}
        {#each Object.entries(result.gps) as [k, v]}
          <dt>GPS·{k}</dt><dd>{v}</dd>
        {/each}
      </dl>
      {#if result.gps.Coordinates}
        <p class="tool-src">GPS terdeteksi — perlakukan sebagai data sensitif: jangan
          simpan bila bukan tujuan investigasi (prinsip minimisasi), dan jangan dishare
          tanpa kebutuhan proporsional.</p>
      {/if}
      {#each result.warnings || [] as w}
        <p class="tb-err">{w}</p>
      {/each}
    </div>
  {/if}
</div>
