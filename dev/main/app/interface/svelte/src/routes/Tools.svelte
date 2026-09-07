<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import SearchInput from '../components/SearchInput.svelte'
  import SearchableSelect from '../components/SearchableSelect.svelte'

  let catalog = null
  let loading = true
  let error = ''
  let query = ''
  let activeCat = '' // '' = all categories, otherwise a category id
  let selected = null // the tool open in the detail drawer

  onMount(async () => {
    try {
      catalog = await api.tools()
    } catch (e) { error = String(e) }
    loading = false
  })

  // ---- search ------------------------------------------------------------
  // Derived purely from catalog/query/activeCat so it always recomputes when
  // those change (no captured-then-stale arrays). 332 rows is tiny.
  $: flatTools = catalog?.tools || []

  $: filtered = flatTools.filter((t) => {
    if (activeCat && t.category !== activeCat) return false
    const q = (query || '').trim().toLowerCase()
    if (!q) return true
    const hay = [
      t.name,
      t.description,
      (t.tags || []).join(' '),
      (t.platforms || []).join(' '),
      (t.features || []).join(' '),
      (t.usage || []).join(' '),
    ].join(' ').toLowerCase()
    return hay.includes(q)
  })

  // ---- grouping (preserve catalog category order, skip empty) ------------
  $: visibleGroups = (() => {
    const out = []
    for (const c of catalog?.categories || []) {
      if (activeCat && c.id !== activeCat) continue
      const tools = filtered.filter((t) => t.category === c.id)
      if (tools.length) out.push({ ...c, tools })
    }
    return out
  })()

  $: platformLabel = (p) => catalog?.platforms?.[p] || p || ''
  $: selectedRelated = relatedTools(selected)

  function openTool(t) { selected = t }
  function closeTool() { selected = null }

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
</script>

<svelte:window onkeydown={(e) => { if (e.key === 'Escape') closeTool() }} />

<section class="hero" style="padding-bottom:24px">
  <div class="wrap">
    <div class="kicker">Pentest Tools</div>
    <h1>{loading ? '...' : `${filtered.length} dari ${catalog?.total || 0} tools`}</h1>
    <p class="lead">Katalog tools penetration testing (Kali-style) + OSINT — dikelompokkan per kategori. Klik kartu untuk detail (fitur, usage, bookmark, tool terkait).</p>
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
  </div>
</section>

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
          <h2>{g.emoji} {g.label}</h2>
          <p class="sub">{g.tools.length} tool</p>
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
</section>

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
      </div>

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
{/if}