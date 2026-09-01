<script>
  import { fmtTime } from '../lib/api.js'
  export let scan
  $: pct = Math.min(scan.progress ?? 0, 100)
  $: status = scan.status ?? 'unknown'
  $: hue = status === 'completed' ? 'ok' : status === 'failed' ? 'err' : 'warn'
</script>

<a class="card" href="#/scan/{scan.scan_id}" style="text-decoration:none;color:inherit">
  <div class="card-sub">{scan.mode} · {fmtTime(scan.created_at)}</div>
  <div class="card-title">{scan.scan_id}</div>
  <div class="progress"><div class="bar" style="width:{pct}%"></div></div>
  <div class="progress-label">{status} · {pct}%</div>
  {#if scan.summary}
    <div style="display:flex;gap:6px;flex-wrap:wrap">
      {#each ['critical','high','medium'] as sev}
        {#if scan.summary[sev] > 0}
          <span class="badge {sev}">{sev} {scan.summary[sev]}</span>
        {/if}
      {/each}
      <span class="badge">total {scan.summary.total ?? 0}</span>
    </div>
  {/if}
</a>
