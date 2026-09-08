<script>
  import { caseFile, removeFromCaseFile, setNote, buildCaseMarkdown, download } from '../lib/casefile.js'

  let msg = ''
  let busy = false

  async function copyMd() {
    busy = true; msg = ''
    const { text } = await buildCaseMarkdown($caseFile)
    try {
      await navigator.clipboard.writeText(text)
      msg = '✓ Markdown case file disalin ke clipboard.'
    } catch {
      msg = 'Clipboard ditolak browser — gunakan tombol ekspor.'
    }
    busy = false
    setTimeout(() => (msg = ''), 4000)
  }

  async function exportMd() {
    busy = true; msg = ''
    const { text } = await buildCaseMarkdown($caseFile)
    download(`cyense-case-${new Date().toISOString().slice(0, 10)}.md`, text)
    busy = false
  }

  function exportJson() {
    download(`cyense-case-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify($caseFile, null, 2))
  }
</script>

<section class="block">
  <div class="wrap">
    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px">
      <h2 style="margin:0">🗂 Case File <span class="muted">({$caseFile.length} tool tersimpan)</span></h2>
      <div style="margin-left:auto;display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn sm" onclick={copyMd} disabled={!$caseFile.length || busy}>salin Markdown</button>
        <button class="btn sm" onclick={exportMd} disabled={!$caseFile.length || busy}>ekspor .md</button>
        <button class="btn sm" onclick={exportJson} disabled={!$caseFile.length}>ekspor .json</button>
      </div>
    </div>

    <p class="tb-privacy" style="margin-bottom:12px">
      Persistensi: <b>localStorage browser ini saja</b> — hilang saat cache dibersihkan,
      tidak sinkron antar perangkat. Ekspor menyertakan SHA-256 bundel + timestamp
      koleksi per entri (disiplin Reporting Checkpoints) agar dapat diverifikasi ulang.
    </p>

    {#if msg}<p class="tool-src">{msg}</p>{/if}

    {#if !$caseFile.length}
      <p class="muted">Kosong. Klik tombol <b>＋ case</b> pada kartu tool / drawer detail untuk
        mengumpulkan bukti sambil menyelidiki.</p>
    {:else}
      {#each $caseFile as it, i (it.name + it.addedAt)}
        <div class="case-row">
          <div class="case-head">
            <span class="case-num">{i + 1}</span>
            <b>{it.name}</b>
            <span class="muted">· {it.category}{it.pricing ? ` · ${it.pricing}` : ''}</span>
            <a class="case-src" href="{it.url}" target="_blank" rel="noopener noreferrer">{it.url}</a>
            {#if it.source}
              <a class="case-src" href={it.source} target="_blank" rel="noopener noreferrer">osintradar ↗</a>
            {/if}
            <button class="case-del" onclick={() => caseFile.set(removeFromCaseFile($caseFile, it.name))}
                    aria-label="Hapus dari case file">✕</button>
          </div>
          {#if it.description}<p class="muted" style="margin:4px 0">{it.description}</p>{/if}
          <input class="case-note" placeholder="catatan observed result (kutip sebelum menafsirkan)…"
                 value={it.note}
                 oninput={(e) => caseFile.set(setNote($caseFile, it.name, e.target.value))} />
        </div>
      {/each}
    {/if}
  </div>
</section>
