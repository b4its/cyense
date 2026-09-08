<script>
  // Safety / Privacy / Anti-abuse layer — mirrors app.program.osintradar_safety
  // (§3.4 + §3.3.6). This is reference content surfaced next to the data it
  // governs, not a policy enforcement mechanism; Cyense does not execute
  // tools/connectors.
  export let safety = {}

  $: motto = safety?.motto
  $: aw = safety?.aggregation_warning
  $: dp = safety?.data_principles || []
  $: regs = safety?.regulations || []
  $: ac = safety?.abuse_controls || []
  $: hr = safety?.hard_refusals || []
  $: wf = safety?.workflow_contract || {}
  $: jur = safety?.jurisdiction_rule || ''

  let copiedYaml = false

  async function copyYaml() {
    await navigator.clipboard.writeText(wf.yaml || '')
    copiedYaml = true
    setTimeout(() => (copiedYaml = false), 1200)
  }

  const RISK_ICON = {
    subject_is_minor: '🧒',
    no_case_reference: '📁',
    purpose_not_declared: '🎯',
    unauthorized_target_asset: '🔓',
  }
</script>

{#if Object.keys(safety).length}
  <section class="block safety-panel">
    <h2>⚖ Keamanan, Privasi &amp; Anti-Penyalahgunaan <span class="muted">(sumber: dokumen analisis §3.4 &amp; §3.3.6)</span></h2>
    {#if motto}<p class="safety-motto">{motto}</p>{/if}
    {#if aw}<p class="cat-note safety-warn">{aw}</p>{/if}

    {#if dp.length}
      <h3>📦 Prinsip Data</h3>
      <div class="grid tools-grid">
        {#each dp as it}
          <div class="tool-card" role="article">
            <div class="tool-name" style="font-size:15px">📌 {it.title}</div>
            <p class="tool-desc">{it.body}</p>
          </div>
        {/each}
      </div>
    {/if}

    {#if regs.length}
      <h3>🌐 Regulasi</h3>
      <div class="safe-reg-wrap">
        <table class="safe-reg-table">
          <thead><tr><th>Kode</th><th>Wilayah / Instrumen</th><th>Kewajiban praktis inti</th></tr></thead>
          <tbody>
            {#each regs as rg}
              <tr>
                <td class="safe-code">{rg.code}</td>
                <td>{rg.name}</td>
                <td class="safe-body">{rg.duties}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if jur}<p class="cat-note">{jur}</p>{/if}
    {/if}

    {#if ac.length}
      <h3>🛡 Kontrol Organisasional</h3>
      <div class="grid tools-grid">
        {#each ac as c}
          <div class="tool-card" role="article">
            <div class="tool-name" style="font-size:15px">🏛 {c.title}</div>
            <p class="tool-desc">{c.body}</p>
          </div>
        {/each}
      </div>
    {/if}

    {#if hr.length}
      <h3>⛔ Penolakan Keras</h3>
      <div class="grid tools-grid">
        {#each hr as fr}
          <div class="tool-card safety-refuse" role="article">
            <div class="tool-name" style="font-size:15px">
              {RISK_ICON[fr.code] || '⛔'} <code class="safety-code">{fr.code}</code> — {fr.label}
            </div>
            <p class="tool-desc">{fr.body}</p>
          </div>
        {/each}
      </div>
    {/if}

    {#if wf.note}
      <h3>📝 Kontrak Workflow Deklaratif <span style="font-size:.8em;font-weight:400">(<span class="muted">§3.3.6</span>)</span></h3>
      <p class="tool-desc">{wf.note}</p>
      <div class="usage-row">
        <details class="safety-contract">
          <summary>Lihat contoh</summary>
          <pre class="tb-code">{(wf.yaml || '').replace(/^ +/, '')}</pre>
        </details>
        <button class="btn sm" onclick={copyYaml}>{(copiedYaml ? '✓ disalin' : 'salin kontrak YAML')}</button>
      </div>
      <p style="margin-top:10px;font-size:.88em;color:var(--ink-soft)">
        Catatan: Cyense <b>tidak</b> menjalankan konektor — hanya menyajikan kontrak
        sebagai rekomendasi untuk tim yang membangun executor sendiri.
        Gerbang <code>safety-code">policy</code> dievaluasi <b>SEBELUM</b> eksekusi, bukan sesudahnya.
      </p>
    {/if}
  </section>
{/if}

<style>
  /* Layout tweaks */
  .safety-motto { margin-top: 6px; }
</style>
