<script>
  import { fmtTime } from '../lib/api.js'
  export let scan
  $: pct = Math.min(scan.progress ?? 0, 100)
  $: status = scan.status ?? 'unknown'
  $: hue = status === 'completed' ? 'ok' : status === 'failed' ? 'err' : 'warn'
</script>

<a class="card" href="#/scan/{scan.scan_id}" style="text-decoration:none;color:inherit">
  <div class="card-sub">{scan.workflow ? `${scan.workflow} · ` : ''}{scan.mode} · {fmtTime(scan.created_at)}</div>
  <div class="card-title" style="word-break:break-all">{scan.target || scan.url || scan.domain || scan.scan_id}</div>
  {#if scan.target || scan.url || scan.domain}
    <div class="card-sub mono" style="font-size:11px;margin-top:-2px">{scan.scan_id}</div>
  {/if}
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
  {#if scan.error}
    <div class="card-sub" style="color:var(--err);font-size:11px;margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title={scan.error}>{scan.error}</div>
  {/if}
</a>
