<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import SearchInput from '../components/SearchInput.svelte'
  import Pagination from '../components/Pagination.svelte'
  import { buildIndex, searchIndex } from '../lib/search.js'

  let rules = null
  let loading = true
  let error = ''
  let query = ''
  let page = 1
  let pageSize = 24
  let selectedRule = null
  let severityFilter = 'all'
  let categoryFilter = 'all'
  let copiedField = ''

  let flatRule = []
  let flatKey = []
  let catOf = new Map()
  let built = false

  function buildFlat() {
    if (!rules || built) return
    flatRule = []
    flatKey = []
    catOf = new Map()
    for (const [g, list] of Object.entries(rules)) {
      for (const r of list || []) {
        flatRule.push(r)
        catOf.set(r, g)
        flatKey.push(
          [
            r.rule,
            r.title,
            r.cwe,
            Array.isArray(r.severity) ? r.severity.join(',') : r.severity,
            r.lang,
            String(r.cvss_score ?? ''),
          ]
            .join(' ')
            .toLowerCase()
        )
      }
    }
    built = true
  }

  $: if (rules) buildFlat()

  $: index = { rows: flatRule, keys: flatKey }
  $: matched = searchIndex(index, query)

  function copyText(text, fieldName) {
    if (!text) return
    navigator.clipboard.writeText(String(text))
    copiedField = fieldName
    setTimeout(() => { copiedField = '' }, 2000)
  }

  function getSevStr(r) {
    if (!r) return 'info'
    if (Array.isArray(r.severity)) return (r.severity[0] || 'info').toLowerCase()
    return String(r.severity || 'info').toLowerCase()
  }

  // Count by severity across all rules
  $: sevCounts = flatRule.reduce((acc, r) => {
    acc.all = (acc.all || 0) + 1
    const s = getSevStr(r)
    if (s.includes('crit')) acc.critical = (acc.critical || 0) + 1
    else if (s.includes('high')) acc.high = (acc.high || 0) + 1
    else if (s.includes('med')) acc.medium = (acc.medium || 0) + 1
    else acc.low = (acc.low || 0) + 1
    return acc
  }, { all: 0, critical: 0, high: 0, medium: 0, low: 0 })

  // All unique category names
  $: allCategories = rules ? Object.keys(rules) : []

  // Filtered by search query, severity, and category
  $: filteredRules = matched.filter((r) => {
    if (severityFilter !== 'all') {
      const s = getSevStr(r)
      if (severityFilter === 'critical' && !s.includes('crit')) return false
      if (severityFilter === 'high' && !s.includes('high')) return false
      if (severityFilter === 'medium' && !s.includes('med')) return false
      if (severityFilter === 'low' && (s.includes('crit') || s.includes('high') || s.includes('med'))) return false
    }
    if (categoryFilter !== 'all') {
      const cat = catOf.get(r)
      if (cat !== categoryFilter) return false
    }
    return true
  })

  // Pagination over the filtered set
  $: totalRules = filteredRules.length
  $: start = (page - 1) * pageSize
  $: paged = filteredRules.slice(start, start + pageSize)

  // Reset page to 1 when filters change
  $: {
    void query
    void severityFilter
    void categoryFilter
    page = 1
  }

  // Regroup paged rules by category, preserving the order they appear in.
  $: visibleGroups = (() => {
    const out = []
    const order = new Map()
    for (const r of paged) {
      const cat = catOf.get(r) || 'Uncategorized'
      if (!order.has(cat)) {
        order.set(cat, out.length)
        out.push([cat, []])
      }
      out[order.get(cat)][1].push(r)
    }
    return out
  })()

  onMount(async () => {
    try {
      rules = await api.rules()
      buildFlat()
    } catch (e) {
      error = String(e)
    }
    loading = false
  })
</script>

<section class="rules-hero reveal">
  <div class="wrap">
    <div class="hero-top-row">
      <div class="tag-pill">
        <span class="pill-blink">●</span>
        <span class="pill-text">VECTOR REPOSITORY // OFFENSIVE SECURITY MATRIX</span>
      </div>
      <div class="hero-actions-top">
        <a class="btn-sm-tactical active" href="#/pentest">&gt;&gt; LAUNCH PENTEST</a>
        <a class="btn-sm-tactical" href="#/scans">AUDIT LIBRARY &rarr;</a>
      </div>
    </div>

    <h1 class="page-title">VECTOR RULES &amp; SIGNATURES</h1>
    <p class="page-desc">
      // {flatRule.length} aturan deteksi kerentanan deterministik yang mencakup IDOR taint-tracking, deep DOM XSS execution, SQL injection AST mutation, port profiling, dan korelasi CVE MITRE/NVD.
    </p>

    <!-- Toolbar & Filters -->
    <div class="toolbar-container">
      <div class="search-box-wrap">
        <SearchInput
          bind:value={query}
          count={totalRules}
          placeholder="Cari rule ID / CWE / severity / keyword…"
          label="Cari rules"
        />
      </div>

      <!-- Severity Filter Pills -->
      <div class="filter-pills">
        <button
          class="pill-btn"
          class:active={severityFilter === 'all'}
          onclick={() => (severityFilter = 'all')}
        >
          ALL ({sevCounts.all})
        </button>
        {#if sevCounts.critical > 0}
          <button
            class="pill-btn crit"
            class:active={severityFilter === 'critical'}
            onclick={() => (severityFilter = 'critical')}
          >
            CRITICAL ({sevCounts.critical})
          </button>
        {/if}
        {#if sevCounts.high > 0}
          <button
            class="pill-btn high"
            class:active={severityFilter === 'high'}
            onclick={() => (severityFilter = 'high')}
          >
            HIGH ({sevCounts.high})
          </button>
        {/if}
        {#if sevCounts.medium > 0}
          <button
            class="pill-btn med"
            class:active={severityFilter === 'medium'}
            onclick={() => (severityFilter = 'medium')}
          >
            MEDIUM ({sevCounts.medium})
          </button>
        {/if}
        {#if sevCounts.low > 0}
          <button
            class="pill-btn low"
            class:active={severityFilter === 'low'}
            onclick={() => (severityFilter = 'low')}
          >
            LOW/INFO ({sevCounts.low})
          </button>
        {/if}
      </div>

      <!-- Category Filter Pills -->
      {#if allCategories.length > 1}
        <div class="cat-pills">
          <span class="filter-label">KATEGORI:</span>
          <button
            class="cat-chip"
            class:active={categoryFilter === 'all'}
            onclick={() => (categoryFilter = 'all')}
          >
            SEMUA
          </button>
          {#each allCategories as cat}
            <button
              class="cat-chip"
              class:active={categoryFilter === cat}
              onclick={() => (categoryFilter = cat)}
            >
              {cat.toUpperCase()}
            </button>
          {/each}
        </div>
      {/if}
    </div>
  </div>
</section>

<section class="rules-list-section reveal">
  <div class="wrap">
    {#if loading}
      <div class="skeleton-box">
        <span class="pill-blink">●</span> LOADING VECTOR RULES REPOSITORY...
      </div>
    {:else if error}
      <div class="error-box">
        // REPOSITORY ERROR: {error}
      </div>
    {:else if !totalRules}
      <div class="empty-box">
        <p class="empty-title">// NO MATCHING RULES FOUND</p>
        <p class="empty-desc">Tidak ada aturan yang cocok dengan filter atau kata kunci "{query}".</p>
        <button
          class="pill-btn active"
          style="margin-top:14px"
          onclick={() => { query = ''; severityFilter = 'all'; categoryFilter = 'all' }}
        >
          RESET SEMUA FILTER
        </button>
      </div>
    {:else}
      {#each visibleGroups as [g, list]}
        <div class="category-block">
          <div class="cat-header">
            <div class="cat-title">
              <span class="cat-prefix">// CATEGORY:</span>
              <span class="cat-name">{g.replace(/_/g, ' ').toUpperCase()}</span>
            </div>
            <span class="cat-count-badge">{list.length} RULES ON THIS PAGE</span>
          </div>

          <div class="table-container">
            <table class="rules-table">
              <thead>
                <tr>
                  <th>RULE ID</th>
                  <th>SEVERITY</th>
                  <th>LANG</th>
                  <th>CWE TAXONOMY</th>
                  <th>CVSS</th>
                  <th>SIGNATURE TITLE</th>
                  <th style="text-align:right">ACTION</th>
                </tr>
              </thead>
              <tbody>
                {#each list as r}
                  {@const sev = getSevStr(r)}
                  <tr onclick={() => (selectedRule = { ...r, category: g })}>
                    <td class="rule-id-cell">
                      <span class="mono-code">{r.rule}</span>
                    </td>
                    <td>
                      <span class="sev-tag {sev}">
                        {(Array.isArray(r.severity) ? r.severity.join(',') : (r.severity || 'info')).toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <span class="lang-tag">{r.lang || 'GLOBAL'}</span>
                    </td>
                    <td class="cwe-cell">
                      {#if r.cwe}
                        <span class="cwe-pill">{r.cwe}</span>
                      {:else}
                        <span class="muted">—</span>
                      {/if}
                    </td>
                    <td>
                      <span class="cvss-badge">{r.cvss_score != null ? Number(r.cvss_score).toFixed(1) : '—'}</span>
                    </td>
                    <td class="title-cell" title={r.title || r.description || ''}>
                      {r.title || r.description || '—'}
                    </td>
                    <td style="text-align:right">
                      <button
                        class="inspect-btn"
                        onclick={(e) => {
                          e.stopPropagation()
                          selectedRule = { ...r, category: g }
                        }}
                      >
                        INSPECT &rarr;
                      </button>
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        </div>
      {/each}

      <div style="margin-top:24px">
        <Pagination
          bind:page={page}
          bind:pageSize={pageSize}
          total={totalRules}
          label="Navigasi rules per halaman"
        />
      </div>
    {/if}
  </div>
</section>

<!-- Tactical Rule Inspector Modal / Drawer -->
{#if selectedRule}
  {@const modalSev = getSevStr(selectedRule)}
  <div class="modal-backdrop" onclick={() => (selectedRule = null)} role="presentation">
    <div
      class="modal-panel"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => { if (e.key === 'Escape') selectedRule = null }}
      role="dialog"
      aria-modal="true"
      tabindex="-1"
    >
      <div class="modal-header">
        <div class="modal-tag">
          <span class="pill-blink">●</span>
          <span>VECTOR INSPECTOR // {selectedRule.category?.toUpperCase() || 'RULE'}</span>
        </div>
        <button class="close-btn" onclick={() => (selectedRule = null)} aria-label="Close modal">✕</button>
      </div>

      <div class="modal-body">
        <div class="modal-title-row">
          <h2 class="modal-title">{selectedRule.rule}</h2>
          <span class="sev-tag {modalSev}">
            {(Array.isArray(selectedRule.severity) ? selectedRule.severity.join(',') : (selectedRule.severity || 'info')).toUpperCase()}
          </span>
        </div>

        <p class="modal-desc">
          {selectedRule.title || selectedRule.description || 'Offensive security vector signature.'}
        </p>

        <div class="spec-grid">
          <div class="spec-cell">
            <span class="spec-label">CATEGORY</span>
            <span class="spec-value">{selectedRule.category || 'general'}</span>
          </div>
          <div class="spec-cell">
            <span class="spec-label">TARGET LANGUAGE / STACK</span>
            <span class="spec-value">{selectedRule.lang || 'multi-platform'}</span>
          </div>
          <div class="spec-cell">
            <span class="spec-label">CVSS BASE SCORE</span>
            <span class="spec-value highlight">{selectedRule.cvss_score != null ? Number(selectedRule.cvss_score).toFixed(1) : '9.0 (Heuristic)'}</span>
          </div>
          <div class="spec-cell">
            <span class="spec-label">CWE REFERENCE</span>
            <span class="spec-value">{selectedRule.cwe || 'CWE-UNDEFINED'}</span>
          </div>
        </div>

        {#if selectedRule.description && selectedRule.description !== selectedRule.title}
          <div class="desc-box">
            <div class="desc-label">// TECHNICAL MECHANISM</div>
            <p class="desc-content">{selectedRule.description}</p>
          </div>
        {/if}

        {#if selectedRule.vector}
          <div class="desc-box">
            <div class="desc-label">// ATTACK VECTOR / PATTERN</div>
            <code class="vector-code">{selectedRule.vector}</code>
          </div>
        {/if}

        <div class="remediation-guidance">
          <div class="desc-label">// DETERMINISTIC MITIGATION</div>
          <p class="desc-content">
            Pastikan seluruh masukan pengguna diproses melalui validasi tipe statis (schema validation), parameter binding pada database engine, output escaping kontekstual (DOM context), dan penegakan otorisasi berbasis token objek (AST authorization gates).
          </p>
        </div>
      </div>

      <div class="modal-footer">
        <button
          class="btn-action-tactical"
          onclick={() => copyText(selectedRule.rule, 'rule')}
        >
          {copiedField === 'rule' ? 'COPIED!' : 'COPY RULE ID'}
        </button>
        {#if selectedRule.cwe}
          <button
            class="btn-action-tactical"
            onclick={() => copyText(selectedRule.cwe, 'cwe')}
          >
            {copiedField === 'cwe' ? 'COPIED CWE!' : 'COPY CWE ID'}
          </button>
        {/if}
        <a
          class="btn-action-tactical active"
          href="#/pentest"
          onclick={() => (selectedRule = null)}
        >
          TEST VECTOR IN PENTEST &rarr;
        </a>
      </div>
    </div>
  </div>
{/if}

<style>
  .rules-hero {
    padding: 48px 0 24px;
    border-bottom: 1px solid var(--line, rgba(255, 26, 60, 0.25));
  }

  .wrap {
    max-width: 1320px;
    margin: 0 auto;
    padding: 0 24px;
    box-sizing: border-box;
  }

  .hero-top-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
    margin-bottom: 20px;
  }

  .tag-pill {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: rgba(255, 26, 60, 0.1);
    border: 1px solid var(--red, #ff1a3c);
    padding: 4px 10px;
  }

  .pill-blink {
    color: var(--red, #ff1a3c);
    font-size: 9px;
    animation: blink 1.5s infinite;
  }

  .pill-text {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--red, #ff1a3c);
    font-weight: 700;
  }

  .hero-actions-top {
    display: flex;
    gap: 10px;
    align-items: center;
  }

  .btn-sm-tactical {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    padding: 8px 16px;
    text-decoration: none;
    border: 1px solid var(--mute, #8a5a64);
    color: var(--fg, #f5e8e8);
    transition: all 0.2s ease;
  }

  .btn-sm-tactical.active {
    background: var(--red, #ff1a3c);
    border-color: var(--red, #ff1a3c);
    color: #ffffff;
  }

  .btn-sm-tactical:hover {
    border-color: var(--red, #ff1a3c);
    color: var(--red, #ff1a3c);
  }

  .btn-sm-tactical.active:hover {
    background: transparent;
    color: var(--red, #ff1a3c);
  }

  .page-title {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: clamp(28px, 4vw, 42px);
    letter-spacing: -0.02em;
    color: var(--fg, #f5e8e8);
    margin: 0 0 12px 0;
  }

  .page-desc {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 13px;
    line-height: 1.65;
    color: var(--mute, #8a5a64);
    max-width: 860px;
    margin: 0 0 24px 0;
  }

  .toolbar-container {
    display: flex;
    flex-direction: column;
    gap: 16px;
    margin-top: 20px;
  }

  .search-box-wrap {
    max-width: 520px;
  }

  .filter-pills {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    align-items: center;
  }

  .pill-btn {
    background: var(--panel, #0e0508);
    border: 1px solid var(--line, rgba(255, 26, 60, 0.25));
    color: var(--mute, #8a5a64);
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    letter-spacing: 0.08em;
    padding: 7px 14px;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .pill-btn:hover {
    color: var(--fg, #f5e8e8);
    border-color: var(--red, #ff1a3c);
  }

  .pill-btn.active {
    background: rgba(255, 26, 60, 0.15);
    border-color: var(--red, #ff1a3c);
    color: var(--red, #ff1a3c);
    font-weight: 700;
  }

  .pill-btn.crit.active {
    background: var(--red, #ff1a3c);
    color: #ffffff;
  }

  .pill-btn.high.active {
    background: #ff8a3a;
    border-color: #ff8a3a;
    color: #050204;
    font-weight: 700;
  }

  .pill-btn.med.active {
    background: var(--acid, #42ff8a);
    border-color: var(--acid, #42ff8a);
    color: #050204;
    font-weight: 700;
  }

  .cat-pills {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    align-items: center;
    padding-top: 10px;
    border-top: 1px dashed var(--line, rgba(255, 26, 60, 0.2));
  }

  .filter-label {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    letter-spacing: 0.12em;
    color: var(--mute, #8a5a64);
    margin-right: 6px;
  }

  .cat-chip {
    background: transparent;
    border: 1px solid var(--line, rgba(255, 26, 60, 0.2));
    color: var(--mute, #8a5a64);
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    letter-spacing: 0.06em;
    padding: 4px 10px;
    cursor: pointer;
    transition: all 0.15s ease;
  }

  .cat-chip:hover {
    color: var(--fg, #f5e8e8);
    border-color: var(--mute, #8a5a64);
  }

  .cat-chip.active {
    background: rgba(66, 255, 138, 0.1);
    border-color: var(--acid, #42ff8a);
    color: var(--acid, #42ff8a);
    font-weight: 700;
  }

  .rules-list-section {
    padding: 32px 0 64px;
  }

  .category-block {
    margin-bottom: 36px;
  }

  .cat-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
  }

  .cat-title {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .cat-prefix {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    letter-spacing: 0.1em;
    color: var(--red, #ff1a3c);
  }

  .cat-name {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 14px;
    color: var(--fg, #f5e8e8);
    font-weight: 700;
  }

  .cat-count-badge {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    letter-spacing: 0.08em;
    color: var(--mute, #8a5a64);
  }

  .table-container {
    width: 100%;
    overflow-x: auto;
    border: 1px solid var(--line, rgba(255, 26, 60, 0.25));
    background: var(--panel, #0e0508);
  }

  .rules-table {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 13px;
  }

  .rules-table th {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: var(--mute, #8a5a64);
    background: var(--bg-soft, #14080c);
    border-bottom: 1px solid var(--line, rgba(255, 26, 60, 0.25));
    padding: 12px 16px;
    text-align: left;
  }

  .rules-table td {
    padding: 12px 16px;
    border-bottom: 1px solid var(--line, rgba(255, 26, 60, 0.12));
    color: var(--fg, #f5e8e8);
    cursor: pointer;
  }

  .rules-table tr:hover td {
    background: rgba(255, 26, 60, 0.04);
  }

  .rule-id-cell .mono-code {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 12px;
    font-weight: 700;
    color: var(--red, #ff1a3c);
  }

  .sev-tag {
    display: inline-block;
    padding: 2px 7px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }

  .sev-tag.critical {
    background: var(--red, #ff1a3c);
    color: #ffffff;
  }

  .sev-tag.high {
    background: #ff8a3a;
    color: #050204;
  }

  .sev-tag.medium {
    background: var(--acid, #42ff8a);
    color: #050204;
  }

  .sev-tag.low,
  .sev-tag.info {
    border: 1px solid var(--line, rgba(255, 26, 60, 0.3));
    color: var(--mute, #8a5a64);
  }

  .lang-tag {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--mute, #8a5a64);
  }

  .cwe-pill {
    display: inline-block;
    background: rgba(255, 26, 60, 0.08);
    border: 1px solid var(--line, rgba(255, 26, 60, 0.2));
    padding: 2px 6px;
    font-size: 11px;
    color: var(--fg, #f5e8e8);
  }

  .cvss-badge {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 12px;
    color: var(--acid, #42ff8a);
  }

  .title-cell {
    max-width: 360px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 12px;
    color: var(--fg, #f5e8e8);
  }

  .inspect-btn {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.04em;
    background: transparent;
    border: 1px solid var(--line, rgba(255, 26, 60, 0.3));
    color: var(--mute, #8a5a64);
    padding: 5px 10px;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .inspect-btn:hover {
    border-color: var(--red, #ff1a3c);
    color: var(--red, #ff1a3c);
    background: rgba(255, 26, 60, 0.1);
  }

  /* Modal / Drawer Inspector */
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.85);
    backdrop-filter: blur(4px);
    z-index: 10000;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    box-sizing: border-box;
  }

  .modal-panel {
    background: #0d0407;
    border: 1px solid var(--red, #ff1a3c);
    box-shadow: 0 0 32px rgba(255, 26, 60, 0.35);
    max-width: 680px;
    width: 100%;
    max-height: 90vh;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 20px;
    background: var(--bg-soft, #14080c);
    border-bottom: 1px solid var(--line, rgba(255, 26, 60, 0.25));
  }

  .modal-tag {
    display: flex;
    align-items: center;
    gap: 8px;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    letter-spacing: 0.12em;
    color: var(--red, #ff1a3c);
    font-weight: 700;
  }

  .close-btn {
    background: transparent;
    border: none;
    color: var(--mute, #8a5a64);
    font-size: 16px;
    cursor: pointer;
    transition: color 0.2s;
  }

  .close-btn:hover {
    color: var(--red, #ff1a3c);
  }

  .modal-body {
    padding: 24px 20px;
    display: flex;
    flex-direction: column;
    gap: 18px;
  }

  .modal-title-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }

  .modal-title {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 20px;
    color: var(--fg, #f5e8e8);
    margin: 0;
  }

  .modal-desc {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 13px;
    line-height: 1.6;
    color: var(--fg, #f5e8e8);
    margin: 0;
  }

  .spec-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    background: var(--panel, #0e0508);
    border: 1px solid var(--line, rgba(255, 26, 60, 0.2));
    padding: 16px;
  }

  .spec-cell {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .spec-label {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--mute, #8a5a64);
  }

  .spec-value {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 13px;
    color: var(--fg, #f5e8e8);
  }

  .spec-value.highlight {
    font-family: var(--font-display, 'Michroma', sans-serif);
    color: var(--acid, #42ff8a);
    font-weight: 700;
  }

  .desc-box,
  .remediation-guidance {
    background: var(--panel, #0e0508);
    border: 1px solid var(--line, rgba(255, 26, 60, 0.2));
    padding: 14px 16px;
  }

  .desc-label {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    letter-spacing: 0.12em;
    color: var(--red, #ff1a3c);
    margin-bottom: 8px;
    font-weight: 700;
  }

  .desc-content {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 12px;
    line-height: 1.6;
    color: var(--mute, #8a5a64);
    margin: 0;
  }

  .vector-code {
    display: block;
    background: #050204;
    border: 1px solid var(--line, rgba(255, 26, 60, 0.2));
    padding: 8px 12px;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    color: var(--acid, #42ff8a);
    word-break: break-all;
  }

  .modal-footer {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
    padding: 16px 20px;
    background: var(--bg-soft, #14080c);
    border-top: 1px solid var(--line, rgba(255, 26, 60, 0.25));
    flex-wrap: wrap;
  }

  .btn-action-tactical {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    background: transparent;
    border: 1px solid var(--mute, #8a5a64);
    color: var(--fg, #f5e8e8);
    padding: 8px 14px;
    cursor: pointer;
    text-decoration: none;
    transition: all 0.2s ease;
  }

  .btn-action-tactical:hover {
    border-color: var(--red, #ff1a3c);
    color: var(--red, #ff1a3c);
  }

  .btn-action-tactical.active {
    background: var(--red, #ff1a3c);
    border-color: var(--red, #ff1a3c);
    color: #ffffff;
  }

  .btn-action-tactical.active:hover {
    background: transparent;
    color: var(--red, #ff1a3c);
    box-shadow: 0 0 14px rgba(255, 26, 60, 0.35);
  }

  .skeleton-box,
  .error-box,
  .empty-box {
    padding: 40px;
    background: var(--panel, #0e0508);
    border: 1px solid var(--line, rgba(255, 26, 60, 0.25));
    font-family: var(--font-mono, 'Space Mono', monospace);
  }

  .empty-title {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 16px;
    color: var(--fg, #f5e8e8);
    margin: 0 0 8px 0;
  }

  .empty-desc {
    color: var(--mute, #8a5a64);
    font-size: 13px;
    margin: 0;
  }

  @keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.2; }
  }

  @media (max-width: 880px) {
    .rules-hero {
      padding: 32px 0 16px;
    }

    .hero-top-row {
      flex-direction: column;
      align-items: flex-start;
    }

    .spec-grid {
      grid-template-columns: 1fr;
    }

    .modal-footer {
      flex-direction: column;
      align-items: stretch;
    }

    .btn-action-tactical {
      text-align: center;
    }
  }
</style>