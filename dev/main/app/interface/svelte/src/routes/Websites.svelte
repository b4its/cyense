<script>
  import { onMount, onDestroy } from 'svelte'
  import { api, fmtTime } from '../lib/api.js'
  import SearchInput from '../components/SearchInput.svelte'
  import Pagination from '../components/Pagination.svelte'
  import { buildIndex, searchIndex } from '../lib/search.js'

  let sites = []
  let loading = true
  let error = ''
  let pollTimer = null
  let query = ''
  let page = 1
  let pageSize = 12

  let statusFilter = 'all'

  // Saved results are persisted server-side (store.json + report.json per
  // scan) — poll so newly finished scans appear without a manual refresh.
  async function refresh() {
    try {
      sites = (await api.websites()) || []
      error = ''
    } catch (e) {
      error = String(e)
    }
    loading = false
  }

  onMount(() => {
    refresh()
    pollTimer = setInterval(refresh, 4000)
  })
  onDestroy(() => {
    if (pollTimer) clearInterval(pollTimer)
  })

  // ---- filter / search with pagination ---------------------------------
  $: index = buildIndex(sites, (s) =>
    [
      s.host,
      s.target,
      s.mode,
      s.status,
      s.scan_id,
      s.summary?.critical,
      s.summary?.high,
      s.summary?.medium,
      s.summary?.low,
      s.summary?.info,
      s.summary?.total,
    ].join(' ')
  )
  $: searched = searchIndex(index, query)
  $: filtered = searched.filter((s) => {
    if (statusFilter === 'all') return true
    if (statusFilter === 'running') return s.status !== 'completed' && s.status !== 'failed'
    return s.status === statusFilter
  })
  $: totalSites = filtered.length
  $: start = (page - 1) * pageSize
  $: pagedSites = filtered.slice(start, start + pageSize)
  $: {
    void query
    void statusFilter
    page = 1
  }

  $: totalFindings = (s) =>
    (s.summary?.critical || 0) +
    (s.summary?.high || 0) +
    (s.summary?.medium || 0) +
    (s.summary?.low || 0) +
    (s.summary?.info || 0)

  $: counts = sites.reduce(
    (acc, s) => {
      acc.all = (acc.all || 0) + 1
      if (s.status === 'completed') acc.completed = (acc.completed || 0) + 1
      else if (s.status === 'failed') acc.failed = (acc.failed || 0) + 1
      else acc.running = (acc.running || 0) + 1
      return acc
    },
    { all: 0, completed: 0, failed: 0, running: 0 }
  )
</script>

<section class="websites-hero reveal">
  <div class="wrap">
    <div class="hero-top-row">
      <div class="tag-pill">
        <span class="pill-blink">●</span>
        <span class="pill-text">TARGET PERIMETER // RECONNAISSANCE LEDGER</span>
      </div>
      <div class="hero-actions-top">
        <a class="btn-sm-tactical active" href="#/pentest">&gt;&gt; LAUNCH PENTEST</a>
        <a class="btn-sm-tactical" href="#/scans">SCAN LIBRARY &rarr;</a>
      </div>
    </div>

    <h1 class="page-title">SAVED TARGET PERIMETERS</h1>
    <p class="page-desc">
      // Setiap target domain/host terdaftar dengan telemetry jejak audit dan temuan tersimpan. Luncurkan pengujian penetrasi adaptif 6-tahap secara instan pada target perimeter mana pun.
    </p>

    <!-- Filter toolbar -->
    <div class="toolbar-box">
      <div class="search-wrap">
        <SearchInput bind:value={query} count={totalSites} placeholder="Cari host / URL / mode target…" label="Cari target" />
      </div>

      <div class="filter-pills">
        <button
          class="pill-btn"
          class:active={statusFilter === 'all'}
          onclick={() => (statusFilter = 'all')}
        >
          ALL ({counts.all})
        </button>
        <button
          class="pill-btn"
          class:active={statusFilter === 'completed'}
          onclick={() => (statusFilter = 'completed')}
        >
          COMPLETED ({counts.completed})
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

<section class="websites-list-section reveal">
  <div class="wrap">
    {#if loading}
      <div class="skeleton-box">
        <span class="pill-blink">●</span> LOADING TARGET PERIMETER DATA...
      </div>
    {:else if error}
      <div class="error-box">
        // PERIMETER ERROR: {error}
      </div>
    {:else if pagedSites.length}
      <div class="table-container">
        <table class="websites-table">
          <thead>
            <tr>
              <th>TARGET HOST & URL</th>
              <th>SCAN MODE</th>
              <th>STATUS</th>
              <th>VULN FINDINGS</th>
              <th>LAST ENGAGEMENT</th>
              <th style="text-align:right">ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            {#each pagedSites as s}
              <tr>
                <td>
                  <a class="host-link" href="#/scan/{s.scan_id}">{s.host}</a>
                  <div class="target-sub" title={s.target}>{s.target}</div>
                </td>
                <td>
                  <span class="mode-tag {s.mode === 'pentest' ? 'pentest' : ''}">{s.mode}</span>
                </td>
                <td>
                  <span
                    class="status-pill {s.status === 'completed'
                      ? 'completed'
                      : s.status === 'failed'
                      ? 'failed'
                      : 'running'}"
                  >
                    {#if s.status !== 'completed' && s.status !== 'failed'}
                      <span class="pill-blink">●</span>
                    {/if}
                    {s.status}
                  </span>
                </td>
                <td>
                  <div class="findings-badges">
                    {#if (s.summary?.critical || 0) > 0}
                      <span class="sev-badge crit">CRIT {s.summary.critical}</span>
                    {/if}
                    {#if (s.summary?.high || 0) > 0}
                      <span class="sev-badge high">HIGH {s.summary.high}</span>
                    {/if}
                    {#if (s.summary?.medium || 0) > 0}
                      <span class="sev-badge med">MED {s.summary.medium}</span>
                    {/if}
                    {#if totalFindings(s) === 0}
                      <span class="sev-badge zero">0 FINDINGS</span>
                    {:else}
                      <span class="sev-badge total">TOTAL {totalFindings(s)}</span>
                    {/if}
                  </div>
                </td>
                <td>
                  <span class="time-cell">
                    {fmtTime(s.created_at)}{s.scan_count > 1 ? ` · ${s.scan_count}×` : ''}
                  </span>
                </td>
                <td style="text-align:right">
                  <div class="row-actions">
                    <a
                      class="act-btn pentest"
                      href="#/pentest?target={encodeURIComponent(s.target || s.host)}"
                      title="Luncurkan Adaptive Pentest pada target ini"
                    >
                      &gt;&gt; PENTEST
                    </a>
                    <a
                      class="act-btn view"
                      href="#/scan/{s.scan_id}"
                      title="Lihat Detail Audit"
                    >
                      AUDIT &rarr;
                    </a>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>

      <div style="margin-top:20px">
        <Pagination
          bind:page={page}
          bind:pageSize={pageSize}
          total={totalSites}
          label="Navigasi websites per halaman"
        />
      </div>
    {:else if totalSites === 0 && sites.length > 0}
      <div class="empty-box">
        <p class="empty-title">// NO MATCHING PERIMETERS</p>
        <p class="empty-desc">Tidak ada target perimeter yang cocok dengan filter atau kata kunci "{query}".</p>
        <button class="pill-btn active" onclick={() => { query = ''; statusFilter = 'all' }}>RESET FILTERS</button>
      </div>
    {:else}
      <div class="empty-box">
        <p class="empty-title">// BELUM ADA TARGET DISIMPAN</p>
        <p class="empty-desc">
          Setiap kali Anda menjalankan scan website, domain, atau pentest, perimeter target akan otomatis tercatat dan tersimpan di sini.
        </p>
        <div style="display:flex;gap:12px;margin-top:16px">
          <a class="act-btn pentest" style="padding:12px 20px" href="#/pentest">&gt;&gt; LAUNCH FIRST PENTEST</a>
          <a class="act-btn view" style="padding:12px 20px" href="#/scans">SCAN LIBRARY &rarr;</a>
        </div>
      </div>
    {/if}
  </div>
</section>

<style>
  .websites-hero {
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
    max-width: 820px;
    margin: 0 0 24px 0;
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

  .websites-list-section {
    padding: 32px 0 64px;
  }

  .table-container {
    width: 100%;
    overflow-x: auto;
    border: 1px solid var(--line, rgba(255, 26, 60, 0.25));
    background: var(--panel, #0e0508);
  }

  .websites-table {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 13px;
  }

  .websites-table th {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: var(--mute, #8a5a64);
    background: var(--bg-soft, #14080c);
    border-bottom: 1px solid var(--line, rgba(255, 26, 60, 0.25));
    padding: 12px 16px;
    text-align: left;
  }

  .websites-table td {
    padding: 14px 16px;
    border-bottom: 1px solid var(--line, rgba(255, 26, 60, 0.15));
    color: var(--fg, #f5e8e8);
  }

  .websites-table tr:hover td {
    background: rgba(255, 26, 60, 0.04);
  }

  .host-link {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 13px;
    color: var(--fg, #f5e8e8);
    text-decoration: none;
    font-weight: 700;
    letter-spacing: 0.02em;
    transition: color 0.2s;
  }

  .host-link:hover {
    color: var(--red, #ff1a3c);
  }

  .target-sub {
    font-size: 11px;
    color: var(--mute, #8a5a64);
    word-break: break-all;
    margin-top: 3px;
  }

  .mode-tag {
    display: inline-block;
    padding: 2px 6px;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    border: 1px solid var(--line, rgba(255, 26, 60, 0.25));
    color: var(--mute, #8a5a64);
  }

  .mode-tag.pentest {
    border-color: var(--red, #ff1a3c);
    color: var(--red, #ff1a3c);
    background: rgba(255, 26, 60, 0.08);
    font-weight: 700;
  }

  .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 8px;
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }

  .status-pill.completed {
    background: rgba(66, 255, 138, 0.12);
    border: 1px solid var(--acid, #42ff8a);
    color: var(--acid, #42ff8a);
  }

  .status-pill.running {
    background: rgba(255, 180, 0, 0.12);
    border: 1px solid #ffb400;
    color: #ffb400;
  }

  .status-pill.failed {
    background: rgba(255, 26, 60, 0.15);
    border: 1px solid var(--red, #ff1a3c);
    color: var(--red, #ff1a3c);
  }

  .findings-badges {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }

  .sev-badge {
    padding: 2px 6px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.04em;
  }

  .sev-badge.crit {
    background: var(--red, #ff1a3c);
    color: #ffffff;
  }

  .sev-badge.high {
    background: #ff8a3a;
    color: #050204;
  }

  .sev-badge.med {
    background: var(--acid, #42ff8a);
    color: #050204;
  }

  .sev-badge.zero {
    border: 1px solid var(--line);
    color: var(--mute);
    font-weight: normal;
  }

  .sev-badge.total {
    border: 1px solid var(--line);
    color: var(--fg);
  }

  .time-cell {
    color: var(--mute, #8a5a64);
    font-size: 11px;
    white-space: nowrap;
  }

  .row-actions {
    display: inline-flex;
    gap: 8px;
    justify-content: flex-end;
  }

  .act-btn {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.04em;
    padding: 6px 12px;
    text-decoration: none;
    text-transform: uppercase;
    transition: all 0.2s ease;
    white-space: nowrap;
  }

  .act-btn.pentest {
    background: rgba(255, 26, 60, 0.15);
    border: 1px solid var(--red, #ff1a3c);
    color: var(--red, #ff1a3c);
  }

  .act-btn.pentest:hover {
    background: var(--red, #ff1a3c);
    color: #ffffff;
    box-shadow: 0 0 12px rgba(255, 26, 60, 0.4);
  }

  .act-btn.view {
    background: transparent;
    border: 1px solid var(--mute, #8a5a64);
    color: var(--fg, #f5e8e8);
  }

  .act-btn.view:hover {
    border-color: var(--red, #ff1a3c);
    color: var(--red, #ff1a3c);
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
    .websites-hero {
      padding: 32px 0 16px;
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
  }
</style>