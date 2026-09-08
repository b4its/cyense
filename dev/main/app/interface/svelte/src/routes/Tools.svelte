<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import SearchInput from '../components/SearchInput.svelte'
  import SearchableSelect from '../components/SearchableSelect.svelte'
  import Pagination from '../components/Pagination.svelte'
  import Toolbench from '../components/Toolbench.svelte'
  import CaseFile from '../components/CaseFile.svelte'
  import PivotMap from '../components/PivotMap.svelte'
  import { caseFile, addToCaseFile, removeFromCaseFile, isInCaseFile } from '../lib/casefile.js'
  import { catalogJsonLd, toolJsonLd } from '../lib/seo.js'

  let catalog = null
  let loading = true
  let error = ''
  let query = ''
  let activeCat = '' // '' = all categories, otherwise a category id
  let haveType = '' // pivot filter: '' off, otherwise one of pivot_types codes
  let view = 'tools' // 'tools' | 'workflows' | 'toolbench' | 'casefile' | 'pivot'
  let selected = null // the tool open in the detail drawer
  let selectedWf = null // the workflow open in the detail drawer
  let page = 1
  let pageSize = 24

  onMount(async () => {
    try {
      catalog = await api.tools()
    } catch (e) { error = String(e) }
    loading = false
  })

  // ---- search ------------------------------------------------------------
  // Derived purely from catalog/query/activeCat so it always recomputes when
  // those change (no captured-then-stale arrays). Paginate the flat result,
  // then regroup only the current page so cards stay grouped by category.
  $: flatTools = catalog?.tools || []

  $: filtered = flatTools.filter((t) => {
    if (activeCat && t.category !== activeCat) return false
    // Pivot map filter: "saya punya X" — keeps tools whose accepted input
    // (OSINT Radar you-have vocabulary) includes the selected identifier type.
    if (haveType && !(t.you_have || []).includes(haveType)) return false
    const q = (query || '').trim().toLowerCase()
    if (!q) return true
    const hay = [
      t.name,
      t.description,
      (t.tags || []).join(' '),
      (t.platforms || []).join(' '),
      (t.features || []).join(' '),
      (t.usage || []).join(' '),
      (t.you_have || []).join(' '),
      (t.you_get || []).join(' '),
      (t.osint_category || ''),
      (t.how_it_works || [])[0] || '',
    ].join(' ').toLowerCase()
    return hay.includes(q)
  })

  $: totalTools = filtered.length
  $: start = (page - 1) * pageSize
  $: paged = filtered.slice(start, start + pageSize)

  // Reset to first page whenever the result set changes (search/category/pivot).
  // The `void` reads register query/activeCat/haveType as dependencies; page
  // changes from the pager itself do NOT retrigger this.
  $: {
    void query; void activeCat; void haveType
    page = 1
  }

  // ---- grouping (preserve catalog category order, skip empty) ------------
  $: visibleGroups = (() => {
    const out = []
    for (const c of catalog?.categories || []) {
      if (activeCat && c.id !== activeCat) continue
      const tools = paged.filter((t) => t.category === c.id)
      if (tools.length) out.push({ ...c, tools })
    }
    return out
  })()

  $: platformLabel = (p) => catalog?.platforms?.[p] || p || ''
  $: selectedRelated = relatedTools(selected)
  $: pivotTypes = catalog?.pivot_types || []
  $: workflows = catalog?.workflows || []
  $: checkpoints = catalog?.reporting_checkpoints || []
  $: confidenceScale = catalog?.confidence_scale || []
  $: health = catalog?.health || null
  $: haveLabel = (c) => pivotTypes.find((p) => p.code === c)?.label || c

  // JSON-LD mirror of the catalog listing / open drawer (§4.2 — names as
  // structured data, not just anchor text).
  $: ld = selected
    ? toolJsonLd(catalog, selected)
    : catalog && (view === 'tools')
      ? catalogJsonLd(catalog, paged, { position0: (page - 1) * pageSize, matched: filtered.length })
      : null
  $: ldText = ld ? JSON.stringify(ld).replace(/</g, '\\u003c') : ''

  const RISK_ICON = {
    biometrik: '🧬', 'privasi-tinggi': '👤', offensif: '💥',
    darkweb: '🕳️', ToS: '📄', mati: '💀',
  }

  function openTool(t) { selected = t }
  function closeTool() { selected = null }
  function openWf(w) { selectedWf = w }
  function closeWf() { selectedWf = null }
  function closeTop() {
    if (selected) closeTool()
    else if (selectedWf) closeWf()
  }

  function toolBy(name) {
    const nl = String(name || '').toLowerCase()
    return flatTools.find((t) => String(t.name).toLowerCase() === nl)
  }
  function relatedTools(t) {
    if (!t) return []
    return (t.related || [])
      .map((n) => toolBy(n))
      .filter(Boolean)
      .map((r) => ({ name: r.name, category: r.category }))
  }
  // Workflow step tools → chip descriptors; names that resolve in the catalog
  // open the tool drawer, the rest render as plain text.
  function wfToolChips(step) {
    return (step.tools || []).map((n) => {
      const t = toolBy(n)
      return t ? { name: t.name, tool: t } : { name: n, tool: null }
    })
  }

  // ---- Case File (client-side localStorage, OSINT Radar style) -----------
  $: inCase = (name) => isInCaseFile($caseFile, name)
  function toggleCase(t) {
    caseFile.update((items) => isInCaseFile(items, t.name)
      ? removeFromCaseFile(items, t.name)
      : addToCaseFile(items, t))
  }

  // ---- "tool ini dipakai di workflow mana?" (saran workflow per tool) ----
  $: workflowsFor = (name) => {
    const nl = String(name || '').toLowerCase()
    const found = []
    for (const w of workflows || []) {
      for (const s of w.steps || []) {
        if ((s.tools || []).some((n) => String(n).toLowerCase() === nl)) {
          found.push({ workflow: w.slug, question: w.question, step: s.title })
          break
        }
      }
    }
    return found
  }
</script>

<svelte:window onkeydown={(e) => { if (e.key === 'Escape') closeTop() }} />

<svelte:head>
  {#if ldText}
    {@html `<script type="application/ld+json" data-cyense-ld>${ldText}</\script>`}
  {/if}
</svelte:head>

<section class="hero" style="padding-bottom:24px">
  <div class="wrap">
    <div class="kicker">Pentest Tools</div>
    {#if view === 'tools'}
      <h1>{loading ? '...' : `${filtered.length} dari ${catalog?.total || 0} tools`}</h1>
    {:else if view === 'workflows'}
      <h1>{loading ? '...' : `${workflows.length} workflows investigasi`}</h1>
    {:else if view === 'toolbench'}
      <h1>Toolbench — 8 utilitas lokal</h1>
    {:else if view === 'pivot'}
      <h1>Pivot Map</h1>
    {:else}
      <h1>🗂 Case File <span class="muted" style="font-size:20px">· {$caseFile.length}</span></h1>
    {/if}
    <p class="lead">
      {#if view === 'tools'}
        Katalog tools penetration testing (Kali-style) + OSINT — dikelompokkan per kategori.
        Klik kartu untuk detail (fitur, usage, bookmark, tool terkait). Filter “Saya punya”
        memakai pivot map OSINT Radar: pilih identifier yang Anda pegang, katalog menampilkan
        tool yang menerimanya.
      {:else if view === 'workflows'}
        Mulai dari pertanyaan investigatif, bukan dari daftar tool — kerangka kerja OSINT
        Radar berlangkah dengan tool dipetakan ke tiap langkah, plus checkpoint pelaporan
        dan level keyakinan. Catatan: workflow adalah metodologi, bukan eksekusi otomatis.
        6 kerangka dari OSINT Radar + {#if workflows.length > 6}{workflows.length - 6} ekspansi Cyense untuk kategori yang dokumen catat belum punya alur (§4.2){/if}.
      {:else if view === 'toolbench'}
        Satu-satunya lapis yang benar-benar memproses data di sisi platform — dibangun
        ulang 1:1 di browser: lokal, tanpa akun, tanpa unggah, tanpa logging. Satu
        pengecualian: IP Lookup, yang secara inheren memanggil API geolokasi publik.
      {:else if view === 'pivot'}
        Visualisasi graf bertipe: tiap tool <code class="wf-conf">you have → you get</code>,
        dan investigasi maju dengan menyerahkan identifier yang Anda pegang ke tool berikutnya.
        Telusuri hop demi hop secara manual — inti nilai OSINT Radar.
      {:else}
        Keranjang bukti ringan ala OSINT Radar: simpan tool selama menyelidiki, beri
        catatan, lalu salin atau ekspor bundel dengan hash integritas SHA-256.
      {/if}
    </p>
    <div class="view-tabs" role="tablist" aria-label="Ganti tampilan katalog">
      <button class="view-tab {view === 'tools' ? 'active' : ''}" role="tab"
              aria-selected={view === 'tools'} onclick={() => view = 'tools'}>🧰 Tools</button>
      <button class="view-tab {view === 'pivot' ? 'active' : ''}" role="tab"
              aria-selected={view === 'pivot'} onclick={() => view = 'pivot'}>🧭 Pivot</button>
      <button class="view-tab {view === 'workflows' ? 'active' : ''}" role="tab"
              aria-selected={view === 'workflows'} onclick={() => view = 'workflows'}>⚙ Workflows</button>
      <button class="view-tab {view === 'toolbench' ? 'active' : ''}" role="tab"
              aria-selected={view === 'toolbench'} onclick={() => view = 'toolbench'}>🧪 Toolbench</button>
      <button class="view-tab {view === 'casefile' ? 'active' : ''}" role="tab"
              aria-selected={view === 'casefile'} onclick={() => view = 'casefile'}>
        {`🗂 Case File${$caseFile.length ? ` (${$caseFile.length})` : ''}`}</button>
    </div>
    {#if view === 'tools'}
      <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
        <div style="flex:1;min-width:240px;max-width:480px">
          <SearchInput bind:value={query} count={filtered.length} placeholder="Cari tool / fitur / usage / platform..." label="Cari tools" />
        </div>
        <SearchableSelect bind:value={activeCat}
          items={[
            { value: '', label: 'Semua kategori' },
            ...(catalog?.categories || []).map((c) => ({ value: c.id, label: `${c.emoji} ${c.label} (${c.count})` })),
          ]}
          placeholder="Semua kategori"
          label="Filter kategori"
        />
      </div>
      {#if pivotTypes.length}
        <div class="pivot-filter" role="group" aria-label="Pivot map — saya punya">
          <span class="pivot-label">Saya punya:</span>
          {#each pivotTypes as p}
            <button class="pivot-chip {haveType === p.code ? 'active' : ''}"
                    aria-pressed={haveType === p.code}
                    onclick={() => haveType = haveType === p.code ? '' : p.code}>{p.label}</button>
          {/each}
          {#if haveType}
            <button class="pivot-chip clear" onclick={() => haveType = ''} aria-label="Hapus filter pivot">✕ {haveLabel(haveType)}</button>
          {/if}
        </div>
      {/if}
    {/if}
  </div>
</section>

{#if view === 'tools'}
<section class="block">
  <div class="wrap">
    {#if loading}<div class="skeleton" style="height:300px"></div>
    {:else if error}<p style="color:var(--err)">{error}</p>
    {:else if query && !filtered.length}
      <p class="muted">Tidak ada tool yang cocok dengan "{query}".</p>
    {:else if !visibleGroups.length}
      <p class="muted">Belum ada tool.</p>
    {:else}
      {#if health}
        <div class="health-bar" role="group" aria-label="Kesehatan verifikasi katalog">
          <span class="pivot-label">Verifikasi:</span>
          <span class="seg"><span class="health-dot" style="background:#22c55e"></span><b>{health.operational}</b> operational</span>
          <span class="seg"><span class="health-dot" style="background:#f59e0b"></span><b>{health.unverified}</b> unverified</span>
          <span class="seg"><span class="health-dot" style="background:#ef4444"></span><b>{health.flagged}</b> flagged</span>
          <span class="tool-src">transparansi status — pembeda katalog terkurasi ini vs daftar link biasa</span>
        </div>
      {/if}
      {#each visibleGroups as g}
        <section class="block">
          <h2>{g.emoji} {g.label}{#if g.risk}<span class="badge high" title="Kelas risiko kategori">⚠ {g.risk}</span>{/if}
            {#if health?.by_category?.[g.id]?.Flagged}
              <span class="badge flagged" title="Verifikasi gagal dalam kategori ini">{health.by_category[g.id].Flagged} flagged</span>
            {/if}
            {#if health?.by_category?.[g.id]?.Unverified}
              <span class="badge unverified" title="Belum diverifikasi dalam kategori ini">{health.by_category[g.id].Unverified} unverified</span>
            {/if}
          </h2>
          <p class="sub">{g.tools.length} tool</p>
          {#if g.note}<p class="cat-note">{g.note}</p>{/if}
          <div class="grid tools-grid">
            {#each g.tools as t}
              <div class="tool-card" onclick={() => openTool(t)} role="button" tabindex="0"
                   onkeydown={(e) => { if (e.key === 'Enter') openTool(t) }}>
                <div class="tool-name">{t.name}</div>
                <p class="tool-desc">{t.description}</p>
                <ul class="tool-features">
                  {#each (t.features || []).slice(0, 3) as f}
                    <li>{f}</li>
                  {/each}
                  {#if (t.features || []).length > 3}
                    <li class="tool-more">+ {(t.features || []).length - 3} lagi…</li>
                  {/if}
                </ul>
                <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px;align-items:center">
                  {#if t.risk}
                    <span class="badge {t.risk === 'mati' ? '' : 'high'} tool-risk"
                          title={t.risk_why || 'kelas risiko per tool (analisis §4.2)'}>⚠ {t.risk}</span>
                  {/if}
                  {#each t.platforms || [] as p}
                    <span class="badge info" title={platformLabel(p)}>{platformLabel(p)}</span>
                  {/each}
                  <button class="badge related {inCase(t.name) ? 'in-case' : ''}"
                          style="margin-left:auto"
                          title={inCase(t.name) ? 'Hapus dari case file' : 'Simpan ke case file'}
                          onclick={(e) => { e.stopPropagation(); toggleCase(t) }}>
                    {inCase(t.name) ? '✓ case' : '＋ case'}</button>
                  <span class="badge">detail →</span>
                </div>
                {#if t.tool_status && t.tool_status !== 'Operational'}
                  <div class="health-dot {t.tool_status === 'Flagged' ? 'flagged' : 'unverified'}"></div>
                  <span class="badge {t.tool_status === 'Flagged' ? 'flagged' : 'unverified'}"
                        style="font-size:10.5px;padding:1px 8px">{t.tool_status}</span>
                {/if}
              </div>
            {/each}
          </div>
        </section>
      {/each}
    {/if}
  </div>
  <div class="wrap">
    <Pagination bind:page={page} bind:pageSize={pageSize}
                total={totalTools} label="Navigasi tool per halaman" />
  </div>
</section>

{:else if view === 'pivot' && !loading && !error}
<!-- Interactive Pivot Map — user-guided typed graph (no auto-ranked
     suggestions, which the analysis flags as occasionally illogical). -->
<section class="block">
  <div class="wrap">
    <PivotMap {catalog} onOpenTool={openTool} />
  </div>
</section>

{:else if view === 'workflows' && !loading && !error}
<!-- Workflows — first 6 from OSINT Radar verbatim; 4 expansions fill the
     categories the analysis (§4.2) flags as lacking an alur. -->
<section class="block">
  <div class="wrap">
    <div class="grid tools-grid">
      {#each workflows as w}
        <div class="tool-card" onclick={() => openWf(w)} role="button" tabindex="0"
             onkeydown={(e) => { if (e.key === 'Enter') openWf(w) }}>
          <div class="tool-name">🧭 {w.question}</div>
          <p class="tool-desc">{w.summary}</p>
          <ul class="tool-features">
            {#each (w.steps || []).slice(0, 3) as s}
              <li>{s.title}</li>
            {/each}
            {#if (w.steps || []).length > 3}
              <li class="tool-more">+ {(w.steps || []).length - 3} langkah lagi…</li>
            {/if}
          </ul>
          <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px;align-items:center">
            <span class="tag-chip-ui">saya punya: {haveLabel(w.start_type)}</span>
            {#if w.extension}<span class="badge info" title="Ekspansi Cyense, bukan dari OSINT Radar — §4.2">ekspansi</span>{/if}
            <span class="badge" style="margin-left:auto">kerangka →</span>
          </div>
        </div>
      {/each}
    </div>
    <p class="cat-note">
      Keterbatasan sadar dari model ini: tidak ada eksekusi otomatis — pengguna tetap
      menjalankan tiap tool di situs aslinya; workflow memberi urutan dan disiplin pelaporan.
      {workflows.filter(w => w.extension).length
        ? `6 kerangka pertama adalah alur asli OSINT Radar; ${workflows.filter(w => w.extension).length} sisanya ekspansi Cyense (label "ekspansi") untuk mengisi kategori yang dokumen catat belum punya workflow — bukan claim dari OSINT Radar.`
        : ''}
    </p>

    {#if catalog?.training?.length}
      <h2 style="margin-top:34px">📚 Training &amp; Reference — Prinsip Metodologi</h2>
      <p class="sub">Menutup kesenjangan kategori osint-training (§4.2) dengan pustaka
        metode internal (bukan tool eksternal yang bisa busuk).</p>
      <div class="grid tools-grid">
        {#each catalog.training as r}
          <div class="tool-card" role="article">
            <div class="tool-name" style="font-size:15px">📘 {r.title}</div>
            <p class="tool-desc">{r.body}</p>
          </div>
        {/each}
      </div>
    {/if}
  </div>
</section>

{:else if view === 'toolbench' && !loading && !error}
<!-- Toolbench — OSINT Radar's local utilities rebuilt client-side. The only
     execution layer; everything offline-capable except IP Lookup. -->
<section class="block">
  <div class="wrap"><Toolbench /></div>
</section>

{:else if view === 'casefile'}
<CaseFile />
{/if}

{#if selected}
  <div class="tool-modal-backdrop" role="presentation" onclick={closeTool} onkeydown={(e) => { if (e.key === 'Escape') closeTool() }}></div>
  <div class="tool-modal" role="dialog" aria-modal="true">
    <div class="tool-modal-head">
      <div>
        <div class="tool-name">{selected.name}</div>
        <a href={selected.url} target="_blank" rel="noopener noreferrer" class="tool-modal-url">
          {selected.url}
        </a>
      </div>
      <div style="display:flex;gap:6px;align-items:flex-start">
        <button class="tool-modal-close" class:cf-on={inCase(selected.name)}
                title={inCase(selected.name) ? 'Hapus dari case file' : 'Simpan ke case file'}
                onclick={() => toggleCase(selected)} aria-label="Case file"
                style="font-size:14px;border:1px solid var(--line);border-radius:8px;padding:4px 10px">
          {inCase(selected.name) ? '✓ case' : '＋ case'}</button>
        <button class="tool-modal-close" onclick={closeTool} aria-label="Tutup">✕</button>
      </div>
    </div>

    <div class="tool-modal-body">
      {#if selected.description}
        <p class="tool-modal-desc">{selected.description}</p>
      {/if}
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin:6px 0 12px">
        {#each selected.platforms || [] as p}
          <span class="badge info">{platformLabel(p)}</span>
        {/each}
        {#if selected.category}
          <span class="badge">{selected.category}</span>
        {/if}
        {#if selected.pricing}
          <span class="badge info">{selected.pricing}</span>
        {/if}
        {#if selected.access}
          <span class="badge">{selected.access}</span>
        {/if}
        {#if selected.tool_status}
          <span class="badge {selected.tool_status === 'Operational' ? 'operational' : (selected.tool_status === 'Flagged' ? 'flagged' : 'unverified')}">{selected.tool_status}</span>
        {/if}
        {#if selected.risk}
          <span class="badge {selected.risk === 'mati' ? '' : 'high'} tool-risk"
                title={selected.risk_why || 'kelas risiko per tool'}>⚠ {selected.risk}</span>
        {/if}
        {#if selected.coverage}
          <span class="badge info" title="Catatan cakupan yurisdiksi (§4.2)">{selected.coverage}</span>
        {/if}
      </div>

      {#if selected.risk && selected.risk_why}
        <div class="wf-caution" style="color:#fcd34d">{RISK_ICON[selected.risk] || '⚠'} {selected.risk_why}</div>
      {/if}

      {#if (selected.how_it_works || []).length}
        <!-- OSINT Radar mirror: the tool's original operating model, kept
             verbatim from the source library (you-have → you-get pivot map
             plus the investigator how-it-works write-up). -->
        <h3 class="tool-modal-h">Cara Kerja (asli — OSINT Radar)</h3>
        {#if (selected.you_have || []).length || (selected.you_get || []).length}
          <div class="tool-pivot">
            {#if (selected.you_have || []).length}
              <div><span class="pivot-label">You have</span>
                {#each selected.you_have as v}<span class="tag-chip-ui">{v}</span>{/each}
              </div>
            {/if}
            {(selected.you_have || []).length && (selected.you_get || []).length ? '→' : ''}
            {#if (selected.you_get || []).length}
              <div><span class="pivot-label">You get</span>
                {#each selected.you_get as v}<span class="tag-chip-ui out">{v}</span>{/each}
              </div>
            {/if}
          </div>
        {/if}
        <div class="tool-mech">
          {#each selected.how_it_works as para}<p>{para}</p>{/each}
        </div>
        {#if selected.source_page}
          <p class="tool-src">Entri & verifikasi:
            <a href={selected.source_page} target="_blank" rel="noopener noreferrer">OSINT Radar · {selected.osint_category || 'tool library'}</a>
          </p>
        {/if}
      {/if}

      {#if (selected.features || []).length}
        <h3 class="tool-modal-h">Fitur</h3>
        <ul class="tool-modal-list">
          {#each selected.features as f}<li>{f}</li>{/each}
        </ul>
      {/if}

      {#if (selected.usage || []).length}
        <h3 class="tool-modal-h">Contoh Penggunaan</h3>
        <div class="tool-modal-usage">
          {#each selected.usage as u}<code>$ {u}</code>{/each}
        </div>
      {/if}

      {#if (selected.bookmarks || []).length}
        <h3 class="tool-modal-h">Bookmark / Referensi</h3>
        <ul class="tool-modal-list">
          {#each selected.bookmarks as b}
            <li><a href={b} target="_blank" rel="noopener noreferrer">{b}</a></li>
          {/each}
        </ul>
      {/if}

      {#if selectedRelated.length}
        <h3 class="tool-modal-h">Tool Terkait</h3>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          {#each selectedRelated as r}
            <button class="badge related" onclick={() => openTool(toolBy(r.name))}>{r.name}</button>
          {/each}
        </div>
      {/if}

      {#if workflowsFor(selected.name).length}
        <h3 class="tool-modal-h">Saran Workflow</h3>
        <p class="tool-src">Tool ini dipakai sebagai langkah dalam kerangka investigasi berikut — konteks nyata untuk menggunakannya.</p>
        {#each workflowsFor(selected.name) as wf}
          <div style="margin:4px 0">
            <button class="badge related" onclick={() => openWf(workflows.find((w) => w.slug === wf.workflow))}>
              {wf.question}</button>
            <span class="tool-src"> · langkah: {wf.step}</span>
          </div>
        {/each}
      {/if}
    </div>
  </div>

{:else if selectedWf}
  <div class="tool-modal-backdrop" role="presentation" onclick={closeWf} onkeydown={(e) => { if (e.key === 'Escape') closeWf() }}></div>
  <div class="tool-modal" role="dialog" aria-modal="true">
    <div class="tool-modal-head">
      <div>
        <div class="tool-name">🧭 {selectedWf.question}</div>
        <p class="tool-modal-desc">{selectedWf.summary}</p>
      </div>
      <button class="tool-modal-close" onclick={closeWf} aria-label="Tutup">✕</button>
    </div>

    <div class="tool-modal-body">
      <div class="wf-caution">⚠ {selectedWf.caution}</div>

      <h3 class="tool-modal-h">Investigation Framework</h3>
      {#each selectedWf.steps || [] as s, i}
        <div class="wf-step">
          <div class="tool-name" style="font-size:15px">
            <span class="wf-step-num">{i + 1}</span> {s.title}
          </div>
          {#if s.detail}<p class="tool-modal-desc" style="margin:2px 0 6px">{s.detail}</p>{/if}
          {#if wfToolChips(s).length}
            <div style="display:flex;gap:6px;flex-wrap:wrap">
              {#each wfToolChips(s) as c}
                {#if c.tool}
                  <button class="badge related" onclick={() => openTool(c.tool)}>{c.name}</button>
                {:else}
                  <span class="badge">{c.name}</span>
                {/if}
              {/each}
            </div>
          {/if}
        </div>
      {/each}

      {#if checkpoints.length}
        <h3 class="tool-modal-h">Reporting Checkpoints (setiap temuan)</h3>
        <ul class="tool-modal-list">
          {#each checkpoints as cp}
            <li><b>{cp.label}</b> — {cp.detail}</li>
          {/each}
        </ul>
      {/if}

      {#if confidenceScale.length}
        <h3 class="tool-modal-h">Level Keyakinan</h3>
        <div class="tool-mech">
          {#each confidenceScale as lv}
            <p><code class="wf-conf">{lv.level}</code> — {lv.criteria} <span class="tool-src">Contoh: {lv.example}</span></p>
          {/each}
        </div>
      {/if}

      <p class="tool-src">
        {#if selectedWf.extension}
          Kerangka ini <b>ekspansi Cyense</b> untuk kategori yang dokumen analisis
          catat belum punya workflow (mengisi §4.2) — bukan alur resmi OSINT Radar.
          Referensi metodologi:
        {:else}
          Kerangka metodologi: mirror analisis OSINT Radar ·
        {/if}
        <a href="https://osintradar.com/workflows" target="_blank" rel="noopener noreferrer">osintradar.com/workflows</a>
        (tool dieksekusi di situs aslinya, bukan di sini).</p>
    </div>
  </div>
{/if}