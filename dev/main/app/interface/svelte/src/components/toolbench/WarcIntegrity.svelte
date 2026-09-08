<script>
  // WARC integrity checker — §4.2 Toolbench extension. Recomputes each
  // record-block digest in the browser (SHA-1/SHA-256; hex, base64, or
  // urn:base32 forms) and compares against the declared Digest. Answers
  // §B2's "WARC perlu replay tool untuk verifikasi": quick integrity triage
  // is available with zero uploads.
  import { checkWarc } from '../../lib/warc.js'

  let running = false
  let result = null
  let error = ''
  let filename = ''

  const STATUS_META = {
    ok: ['badge info', '✓ digest cocok'],
    mismatch: ['badge high', '✗ integritas rusak/dipalsukan'],
    'no-digest': ['badge', 'tanpa Digest (tidak dapat diverifikasi)'],
    'algo-unavailable': ['badge', 'algoritme tidak tersedia di browser ini'],
  }

  async function handle(e) {
    const f = e.target.files?.[0]
    result = null; error = ''
    if (!f) return
    if (f.size > 80 * 1024 * 1024) { error = 'Berkas > 80 MB — jalankan warcvalidasi di terminal/servis lokal (batasan browser).'; return }
    filename = f.name
    running = true
    try {
      const buf = await f.arrayBuffer()
      result = await checkWarc(buf)
    } catch (err) {
      error = String(err?.message || err)
    } finally {
      running = false
    }
  }

  $: okCount = (result?.records || []).filter((r) => r.status === 'ok').length
  $: badCount = (result?.records || []).filter((r) => r.status === 'mismatch').length
</script>

<div class="tb-panel">
  <p class="tool-modal-desc">Pilih berkas <code class="wf-conf">.warc</code> (WARC/1.0 raw;
    bila <code class="wf-conf">.warc.gz</code> dekompresi dulu) — record di-scan,
    digest dihitung ulang, dan kecocokannya dilaporkan per record. Semua lokal.</p>
  <div class="field"><label for="warc-file">Berkas WARC</label>
    <input id="warc-file" type="file" accept=".warc" onchange={handle} /></div>
  {#if running}<p class="tool-src">memeriksa…</p>{/if}
  {#if error}<p class="tb-err">{error}</p>{/if}

  {#if result}
    <div class="tb-output">
      <h3 class="tool-modal-h" style="margin-top:0">{filename} — {result.records.length} record</h3>
      <div class="usage-row" style="margin:0 0 8px">
        <span class="badge info">✓ {okCount} cocok</span>
        {#if badCount}<span class="badge high">✗ {badCount} rusak</span>{/if}
        {#each result.errors as e}<p class="tb-err">{e}</p>{/each}
      </div>
      {#each result.records as r}
        {@const m = STATUS_META[r.status] || STATUS_META['no-digest']}
        <div class="case-row" style="padding:8px 10px;margin-bottom:6px">
          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
            <span class="badge" title="offset byte">#{r.index}</span>
            <span class="tb-mono" style="font-size:12px">{r.warcType || '?'} · {r.contentLength}B · {r.date || ''}</span>
            <span class="{m[0]}" style="margin-left:auto">{m[1]}</span>
          </div>
          {#if r.declared}
            <div class="tb-mono" style="font-size:11.5px;color:var(--ink-mute,#8a93a6);margin-top:4px;word-break:break-all">
              declared: {r.declared.algo}/{r.declared.enc} {String(r.declared.value).slice(0, 48)}…
              {#if r.computed[r.declared.algo]}
                <br/>computed: {r.computed[r.declared.algo]}
              {/if}
            </div>
          {/if}
        </div>
      {/each}
      {#if !result.records.length && !result.errors.length}
        <p class="muted">Tidak ada record terparse — pastikan berkas WARC (bukan .warc.gz yang belum didekompresi atau artefak lain).</p>
      {/if}
      <p class="cat-note" style="margin-top:10px">Catatan forensik: digest mencerminkan record-block
        seperti saat penulisan arsip — hasil <b>ok</b> mendukung integritas; <b>mismatch</b>
        wajib ditinjau ulang dengan warc tools (mungkin hanya transliteration). Tanpa Digest
        berarti tak ada klaim integritas untuk diverifikasi.</p>
    </div>
  {/if}
</div>
