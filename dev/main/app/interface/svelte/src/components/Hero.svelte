<script>
  import { fmtTime } from '../lib/api.js'
  export let scan = null
  export let stats = {}
</script>

<section class="hero">
  <div class="wrap">
    <div class="kicker">Agentic Security Insight</div>
    <h1>Audit website, source code, dan API — satu pipeline.</h1>
    <p class="lead">
      Cyense mengorkestrasi crawler, deteksi teknologi, port scan, pencarian CVE
      (database lokal + NVD/MITRE), dan probe IDOR/XSS/SQLi — semuanya read-only
      dan deterministik.
    </p>
    <div class="meta">
      <span class="stat"><b>{stats.total ?? 0}</b> scan</span>
      <span class="stat"><b>{stats.cves ?? 0}</b> CVE matched</span>
      <span class="stat"><b>{stats.ports ?? 0}</b> port terbuka</span>
      {#if scan}
        <span class="stat">Terakhir: <b>{fmtTime(scan.created_at)}</b></span>
      {/if}
    </div>
  </div>
</section>
