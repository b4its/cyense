<script>
  export let f
  import { fmtTime } from '../lib/api.js'
  $: sev = (f.severity || 'info').toLowerCase()
</script>

<div class="card" style="gap:6px">
  <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
    <span class="badge {sev}">{sev.toUpperCase()}</span>
    <span class="card-sub">{f.rule}</span>
    <span style="flex:1"></span>
    {#if f.confidence != null}<span class="card-sub">conf {(f.confidence * 100).toFixed(0)}%</span>{/if}
  </div>
  <div class="card-title" style="font-size:16px">{f.title}</div>
  {#if f.description}<p class="muted" style="margin:0;font-size:14px">{f.description}</p>{/if}
  {#if f.location}<div class="card-sub" style="word-break:break-all">{f.location}</div>{/if}
  {#if f.remediation}<p style="margin:6px 0 0;font-size:14px"><b>Fix:</b> {f.remediation}</p>{/if}
</div>
