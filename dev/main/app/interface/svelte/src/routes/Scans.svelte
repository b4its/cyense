<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import ScanCard from '../components/ScanCard.svelte'
  import SearchInput from '../components/SearchInput.svelte'
  import SearchableSelect from '../components/SearchableSelect.svelte'
  import Pagination from '../components/Pagination.svelte'
  import { buildIndex, searchIndex } from '../lib/search.js'

  let scans = []
  let loading = true
  let error = ''
  let url = ''
  let mode = 'website'
  let submitting = false
  let msg = ''
  let query = ''
  let page = 1
  let pageSize = 12
  let statusFilter = 'all'
  let modeFilter = 'all'

  onMount(async () => {
    try {
      scans = (await api.listScans()) || []
    } catch (e) {
      error = String(e)
    }
    loading = false
  })

  async function submit() {
    submitting = true
    msg = ''
    try {
      const payload = { mode, i_have_permission: true }
      if (mode === 'pentest') {
        if (!url) throw new Error('Target URL / domain wajib diisi')
        payload.target = url
        payload.url = url
        payload.workflow = 'adaptive'
      }
      if (mode === 'full') {
        if (!url) throw new Error('Target URL / domain wajib diisi')
        payload.target = url
        payload.url = url
        payload.workflow = 'full'
      }
      if (mode === 'website' || mode === 'link') {
        if (!url) throw new Error('URL/domain target wajib diisi')
        payload.url = url
      }
      if (mode === 'domain') {
        if (!url) throw new Error('Domain wajib diisi')
        payload.domain = url
        delete payload.url
      }
      if (mode === 'program') {
        payload.source_type = 'sample'
        delete payload.url
      }
      if (mode === 'github') {
        if (!url) throw new Error('Repo URL wajib diisi')
        payload.repo_url = url
      }
      const r = await api.submitScan(payload)
      msg = `Scan diajukan: ${r.scan_id}`
      // Auto-navigate to the realtime detail view so the user sees the
      // step-by-step progress (and the results) as they happen.
      setTimeout(() => {
        location.hash = `#/scan/${r.scan_id}`
      }, 600)
      setTimeout(async () => {
        scans = (await api.listScans()) || []
      }, 1500)
    } catch (e) {
      msg = String(e)
    }
    submitting = false
  }

  // Single-pass search index over the scan library (rebuild only on change).
  $: index = buildIndex(scans, (s) =>
    [
      s.scan_id,
      s.target,
      s.domain,
      s.url,
      s.workflow,
      s.mode,
      s.status,
      s.stage,
      s.summary?.total,
      s.summary?.critical,
      s.summary?.high,
      s.summary?.medium,
    ].join(' ')
  )
  $: searched = searchIndex(index, query)
  $: filtered = searched.filter((s) => {
    if (statusFilter === 'running' && (s.status === 'completed' || s.status === 'failed')) return false
    if (statusFilter !== 'all' && statusFilter !== 'running' && s.status !== statusFilter) return false
    if (modeFilter !== 'all') {
      if (modeFilter === 'pentest' && s.mode !== 'pentest' && s.mode !== 'full') return false
      if (modeFilter !== 'pentest' && s.mode !== modeFilter) return false
    }
    return true
  })

  $: counts = scans.reduce(
    (acc, s) => {
      acc.all = (acc.all || 0) + 1
      if (s.status === 'completed') acc.completed = (acc.completed || 0) + 1
      else if (s.status === 'failed') acc.failed = (acc.failed || 0) + 1
      else acc.running = (acc.running || 0) + 1
      return acc
    },
    { all: 0, completed: 0, failed: 0, running: 0 }
  )

  $: start = (page - 1) * pageSize
  $: paged = filtered.slice(start, start + pageSize)
  $: {
    void query
    void statusFilter
    void modeFilter
    page = 1
  }
</script>

<section class="scans-hero reveal">
  <div class="wrap">
    <div class="hero-top-row">
      <div class="tag-pill">
        <span class="pill-blink">●</span>
        <span class="pill-text">SYS.AUDIT // GLOBAL SCAN QUEUE &amp; HISTORY</span>
      </div>
      <div class="hero-actions-top">
        <a class="btn-sm-tactical active" href="#/pentest">&gt;&gt; ADAPTIVE PENTEST</a>
        <a class="btn-sm-tactical" href="#/websites">SAVED PERIMETERS &rarr;</a>
      </div>
    </div>

    <h1 class="page-title">SCAN LIBRARY &amp; QUEUE</h1>
    <p class="page-desc">
      // Kirim job audit baru untuk target tunggal, perimeter domain, atau repo, atau telusuri hasil audit historis lengkap dengan telemetry temuan dan remedi AST.
    </p>

    <!-- Scan submission form -->
    <div class="dispatch-panel">
      <div class="panel-header">
        <span>// DISPATCH AUDIT JOB</span>
        <a href="#/pentest" class="alt-link">Butuh 6-stage adaptive pentest dengan subdomain profiling? &rarr;</a>
      </div>

      <form
        onsubmit={(e) => {
          e.preventDefault()
          submit()
        }}
        class="scan-form"
      >
        <div class="form-group field-target">
          <label for="target-url">TARGET URL / DOMAIN / REPO</label>
          <input
            id="target-url"
            bind:value={url}
            placeholder="https://example.com atau target-domain.com"
          />
        </div>

        <div class="form-group field-mode">
          <label for="scan-mode">AUDIT MODE</label>
          <SearchableSelect
            id="scan-mode"
            bind:value={mode}
            items={[
              { value: 'pentest', label: 'pentest 6-stage adaptive (684 tools)' },
              { value: 'full', label: 'pentest full matrix (684 tools)' },
              { value: 'website', label: 'website (standard perimeter)' },
              { value: 'domain', label: 'domain (multi-host crawler)' },
              { value: 'link', label: 'link (deep spider)' },
              { value: 'program', label: 'program (sample benchmark)' },
              { value: 'github', label: 'github (repo audit)' },
            ]}
            label="Mode scan"
          />
        </div>

        <button class="btn-dispatch" disabled={submitting}>
          {submitting ? 'DISPATCHING...' : '>> DISPATCH SCAN'}
        </button>
      </form>

      {#if msg}
        <div class="dispatch-msg">
          // RESPONSE: {msg}
        </div>
      {/if}
    </div>

    <!-- Search and filter pills -->
    <div class="toolbar-box">
      <div class="search-wrap">
        <SearchInput
          bind:value={query}
          count={filtered.length}
          placeholder="Cari scan_id / URL / mode / status…"
          label="Cari scan"
        />
      </div>

      <div class="filter-pills">
        <button
          class="pill-btn"
          class:active={statusFilter === 'all'}
          onclick={() => (statusFilter = 'all')}
        >
          ALL ({counts.all})
        </button>
        {#if counts.running > 0}
          <button
            class="pill-btn live"
            class:active={statusFilter === 'running'}
            onclick={() => (statusFilter = 'running')}
          >
            ACTIVE ({counts.running})
          </button>
        {/if}
        <button
          class="pill-btn"
          class:active={statusFilter === 'completed'}
          onclick={() => (statusFilter = 'completed')}
        >
          COMPLETED ({counts.completed})
        </button>
        {#if counts.failed > 0}
          <button
            class="pill-btn err"
            class:active={statusFilter === 'failed'}
            onclick={() => (statusFilter = 'failed')}
          >
            FAILED ({counts.failed})
          </button>
        {/if}
      </div>
    </div>
  </div>
</section>

<section class="scans-list-section reveal">
  <div class="wrap">
    {#if loading}
      <div class="skeleton-box">
        <span class="pill-blink">●</span> LOADING SCAN QUEUE TELEMETRY...
      </div>
    {:else if error}
      <div class="error-box">
        // TELEMETRY ERROR: {error}
      </div>
    {:else if paged.length}
      <div class="scans-grid">
        {#each paged as s}
          <ScanCard {s} />
        {/each}
      </div>
      <div style="margin-top:24px">
        <Pagination
          bind:page={page}
          bind:pageSize={pageSize}
          total={filtered.length}
          label="Navigasi scan per halaman"
        />
      </div>
    {:else if filtered.length === 0 && scans.length > 0}
      <div class="empty-box">
        <p class="empty-title">// NO MATCHING AUDIT SCANS</p>
        <p class="empty-desc">Tidak ada scan yang cocok dengan filter atau kata kunci "{query}".</p>
        <button
          class="pill-btn active"
          style="margin-top:12px"
          onclick={() => {
            query = ''
            statusFilter = 'all'
            modeFilter = 'all'
          }}
        >
          RESET FILTERS
        </button>
      </div>
    {:else}
      <div class="empty-box">
        <p class="empty-title">// BELUM ADA SCAN DALAM QUEUE</p>
        <p class="empty-desc">Kirim audit pertama Anda menggunakan form di atas atau luncurkan Pentest Suite.</p>
        <a class="btn-dispatch" style="display:inline-block;margin-top:16px;text-decoration:none" href="#/pentest">
          &gt;&gt; LAUNCH FIRST PENTEST
        </a>
      </div>
    {/if}
  </div>
</section>

<style>
  .scans-hero {
    padding: 48px 0 24px;
    border-bottom: 1px solid var(--line);
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
    max-width: 840px;
    margin: 0 0 24px 0;
  }

  .dispatch-panel {
    background: var(--panel, #0e0508);
    border: 1px solid var(--line, rgba(255, 26, 60, 0.25));
    padding: 20px 24px;
    margin-bottom: 24px;
  }

  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    letter-spacing: 0.12em;
    color: var(--red, #ff1a3c);
    margin-bottom: 16px;
  }

  .alt-link {
    color: var(--mute, #8a5a64);
    text-decoration: none;
    transition: color 0.2s;
  }

  .alt-link:hover {
    color: var(--acid, #42ff8a);
  }

  .scan-form {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    align-items: flex-end;
  }

  .form-group {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .form-group label {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--mute, #8a5a64);
  }

  .field-target {
    flex: 2;
    min-width: 260px;
  }

  .field-target input {
    background: var(--bg-soft, #14080c);
    border: 1px solid var(--line, rgba(255, 26, 60, 0.3));
    color: var(--fg, #f5e8e8);
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 13px;
    padding: 10px 14px;
    outline: none;
    transition: border-color 0.2s;
    width: 100%;
    box-sizing: border-box;
  }

  .field-target input:focus {
    border-color: var(--red, #ff1a3c);
  }

  .field-mode {
    flex: 1;
    min-width: 220px;
  }

  .btn-dispatch {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    background: var(--red, #ff1a3c);
    border: 1px solid var(--red, #ff1a3c);
    color: #ffffff;
    padding: 11px 24px;
    cursor: pointer;
    transition: all 0.2s ease;
    white-space: nowrap;
    border-radius: 0;
  }

  .btn-dispatch:hover:not(:disabled) {
    background: transparent;
    color: var(--red, #ff1a3c);
    box-shadow: 0 0 16px rgba(255, 26, 60, 0.35);
  }

  .btn-dispatch:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .dispatch-msg {
    margin-top: 14px;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 12px;
    color: var(--acid, #42ff8a);
  }

  .toolbar-box {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
    margin-top: 20px;
  }

  .search-wrap {
    flex: 1;
    min-width: 280px;
    max-width: 480px;
  }

  .filter-pills {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }

  .pill-btn {
    background: var(--panel, #0e0508);
    border: 1px solid var(--line, rgba(255, 26, 60, 0.25));
    color: var(--mute, #8a5a64);
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    letter-spacing: 0.08em;
    padding: 8px 14px;
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

  .pill-btn.live.active {
    background: rgba(66, 255, 138, 0.15);
    border-color: var(--acid, #42ff8a);
    color: var(--acid, #42ff8a);
  }

  .pill-btn.err.active {
    background: rgba(255, 26, 60, 0.25);
    border-color: var(--red, #ff1a3c);
    color: #ffffff;
  }

  .scans-list-section {
    padding: 32px 0 64px;
  }

  .scans-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
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

  @media (max-width: 1024px) {
    .scans-grid {
      grid-template-columns: repeat(2, 1fr);
    }
  }

  @media (max-width: 680px) {
    .scans-grid {
      grid-template-columns: 1fr;
    }

    .hero-top-row {
      flex-direction: column;
      align-items: flex-start;
    }

    .toolbar-box {
      flex-direction: column;
      align-items: stretch;
    }

    .search-wrap {
      max-width: 100%;
    }

    .scan-form {
      flex-direction: column;
      align-items: stretch;
    }

    .btn-dispatch {
      width: 100%;
    }
  }
</style>
