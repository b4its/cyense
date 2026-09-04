<script>
  import { onMount, onDestroy } from 'svelte'
  import { api, fmtTime } from '../lib/api.js'

  let sites = []
  let loading = true
  let error = ''
  let pollTimer = null

  // Saved results are persisted server-side (store.json + report.json per
  // scan) — poll so newly finished scans appear without a manual refresh.
  async function refresh() {
    try {
      sites = await api.websites() || []
      error = ''
    } catch (e) { error = String(e) }
    loading = false
  }

  onMount(() => {
    refresh()
    pollTimer = setInterval(refresh, 4000)
  })
  onDestroy(() => { if (pollTimer) clearInterval(pollTimer) })

  $: totalFindings = (s) =>
    (s.summary?.critical || 0) + (s.summary?.high || 0) +
    (s.summary?.medium || 0) + (s.summary?.low || 0) + (s.summary?.info || 0)

  $: countByStatus = sites.reduce((a, s) => {
    a[s.status] = (a[s.status] || 0) + 1
    return a
  }, {})
</script>

<section class="hero" style="padding-bottom:24px">
  <div class="wrap">
    <div class="kicker">Saved Results</div>
    <h1>Daftar Website yang Sudah Di-scan</h1>
    <p class="lead">
      Setiap entri = satu target (host/domain) dengan hasil scan tersimpan.
      {sites.length} website · {countByStatus.completed || 0} selesai
      {#if countByStatus.failed}{countByStatus.failed} gagal{/if}
    </p>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <a class="btn primary" href="#/scans">← Scan Library</a>
      <a class="btn" href="#/rules">Lihat Rules</a>
    </div>
  </div>
</section>

<section class="block">
  <div class="wrap">
    {#if loading}
      <div class="skeleton" style="height:240px"></div>
    {:else if error}
      <p style="color:var(--err)">{error}</p>
    {:else if sites.length}
      <div class="table-scroll">
      <table class="tbl">
        <thead>
          <tr><th>Website</th><th>Mode</th><th>Status</th><th>Temuan</th><th>Terakhir di-scan</th></tr>
        </thead>
        <tbody>
        {#each sites as s}
          <tr>
            <td>
              <a class="mono" href="#/scan/{s.scan_id}" style="font-weight:600">{s.host}</a>
              <div class="card-sub" style="word-break:break-all">{s.target}</div>
            </td>
            <td><span class="badge">{s.mode}</span></td>
            <td>
              <span class="badge {s.status === 'completed' ? 'info' : s.status === 'failed' ? 'critical' : 'warn'}">{s.status}</span>
            </td>
            <td>
              <div style="display:flex;gap:6px;flex-wrap:wrap">
                {#each ['critical','high','medium','low','info'] as sev}
                  {#if s.summary?.[sev] > 0}<span class="badge {sev}">{sev} {s.summary[sev]}</span>{/if}
                {/each}
                <span class="badge">total {totalFindings(s)}</span>
              </div>
            </td>
            <td class="card-sub">{fmtTime(s.created_at)}{s.scan_count > 1 ? ` · ${s.scan_count}×` : ''}</td>
          </tr>
        {/each}
        </tbody>
      </table>
      </div>
    {:else}
      <p class="muted">Belum ada hasil tersimpan. Jalankan scan website/link/domain dari
        <a href="#/scans">Scan Library</a>, hasilnya akan tersimpan dan muncul di sini.</p>
    {/if}
  </div>
</section>
