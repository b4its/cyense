<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import SearchInput from '../components/SearchInput.svelte'
  import SearchableSelect from '../components/SearchableSelect.svelte'
  import Pagination from '../components/Pagination.svelte'

  let catalog = null
  let loading = true
  let error = ''
  let query = ''
  let activeCat = '' // '' = all categories, otherwise a category id
  let haveType = '' // pivot filter: '' off, otherwise one of pivot_types codes
  let view = 'tools' // 'tools' | 'workflows' — OSINT Radar Lapis A: question-first
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
  $: haveLabel = (c) => pivotTypes.find((p) => p.code === c)?.label || c

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
</script>

<svelte:window onkeydown={(e) => { if (e.key === 'Escape') closeTop() }} />

<section class="hero" style="padding-bottom:24px">
  <div class="wrap">
    <div class="kicker">Pentest Tools</div>
    {#if view === 'tools'}
      <h1>{loading ? '...' : `${filtered.length} dari ${catalog?.total || 0} tools`}</h1>
    {:else}
      <h1>{loading ? '...' : `${workflows.length} workflows investigasi`}</h1>
    {/if}
    <p class="lead">
      {#if view === 'tools'}
        Katalog tools penetration testing (Kali-style) + OSINT — dikelompokkan per kategori.
        Klik kartu untuk detail (fitur, usage, bookmark, tool terkait). Filter “Saya punya”
        memakai pivot map OSINT Radar: pilih identifier yang Anda pegang, katalog menampilkan
        tool yang menerimanya.
      {:else}
        Mulai dari pertanyaan investigatif, bukan dari daftar tool — kerangka kerja OSINT
        Radar berlangkah dengan tool dipetakan ke tiap langkah, plus checkpoint pelaporan
        dan level keyakinan. Catatan: workflow adalah metodologi, bukan eksekusi otomatis.
      {/if}
    </p>
    <div class="view-tabs" role="tablist" aria-label="Ganti tampilan katalog">
      <button class="view-tab {view === 'tools' ? 'active' : ''}" role="tab"
              aria-selected={view === 'tools'} onclick={() => view = 'tools'}>🧰 Tools</button>
      <button class="view-tab {view === 'workflows' ? 'active' : ''}" role="tab"
              aria-selected={view === 'workflows'} onclick={() => view = 'workflows'}>🧭 Workflows</button>
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
      {#each visibleGroups as g}
        <section class="block">
          <h2>{g.emoji} {g.label}{#if g.risk}<span class="badge high" title="Kelas risiko kategori">⚠ {g.risk}</span>{/if}</h2>
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
                  {#each t.platforms || [] as p}
                    <span class="badge info" title={platformLabel(p)}>{platformLabel(p)}</span>
                  {/each}
                  <span class="badge" style="margin-left:auto">detail →</span>
                </div>
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

{:else if !loading && !error}
<!-- OSINT Radar Workflows — "Start from an investigative question, not a
     tool list": 6 frameworks, steps mapped to catalog tools. -->
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
            <span class="badge" style="margin-left:auto">kerangka →</span>
          </div>
        </div>
      {/each}
    </div>
    <p class="cat-note">
      Keterbatasan sadar dari model ini: tidak ada eksekusi otomatis — pengguna tetap
      menjalankan tiap tool di situs aslinya; workflow memberi urutan dan disiplin pelaporan.
    </p>
  </div>
</section>
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
      <button class="tool-modal-close" onclick={closeTool} aria-label="Tutup">✕</button>
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
          <span class="badge {selected.tool_status === 'Operational' ? 'info' : 'high'}">{selected.tool_status}</span>
        {/if}
      </div>

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

      <p class="tool-src">Kerangka metodologi: mirror analisis OSINT Radar ·
        <a href="https://osintradar.com/workflows" target="_blank" rel="noopener noreferrer">osintradar.com/workflows</a>
        (tool dieksekusi di situs aslinya, bukan di sini).</p>
    </div>
  </div>
{/if}