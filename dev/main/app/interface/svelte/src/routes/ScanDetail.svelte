<script>
  import { onMount } from 'svelte'
  import { api, sevRank, fmtDuration } from '../lib/api.js'
  import StageGraph from '../components/StageGraph.svelte'
  import StickyToc from '../components/StickyToc.svelte'
  import ProgressChecklist from '../components/ProgressChecklist.svelte'
  import FindingCard from '../components/FindingCard.svelte'
  import Celebration from '../components/Celebration.svelte'
  import DiffWidget from '../components/DiffWidget.svelte'

  export let scanId = ''
  let report = null
  let job = null
  let loading = true
  let error = ''
  let activeHeading = ''
  let celebrate = false
  let celebrated = false

  const PIPELINE = ['crawl', 'analyze', 'framework', 'port-scan', 'cve', 'discovery',
                     'harvest', 'nikto', 'nuclei', 'probe', 'sqli', 'report']

  async function load() {
    loading = true; error = ''
    try {
      job = await api.getScan(scanId)
      if (job.status === 'completed' || job.status === 'failed') {
        try { report = await api.getReport(scanId) } catch { report = null }
      } else {
        report = null
      }
      if (job.status === 'completed' && !celebrated) {
        celebrate = true; celebrated = true
      }
    } catch (e) { error = String(e) }
    loading = false
  }

  onMount(load)

  // Stage graph status derived from pipeline + summary progress.
  $: stages = (report?.meta?.pipeline || PIPELINE).map((name, i) => {
    const isCompleted = job?.status === 'completed'
    const isFailed = job?.status === 'failed'
    return {
      name,
      status: isCompleted ? 'done'
        : isFailed ? (i === 0 ? 'done' : 'failed')
        : i === 0 ? 'active' : 'pending',
    }
  })

  $: findings = (report?.findings || []).slice().sort((a, b) => sevRank(a.severity) - sevRank(b.severity))
  $: cves = findings.filter((f) => f.rule === 'CVE-MATCH')
  $: techs = findings.filter((f) => f.rule?.startsWith('DETECT-'))
  $: ports = findings.filter((f) => f.rule === 'PORT-OPEN' || f.rule === 'PORT-SCAN-SUMMARY')
  $: harvest = findings.filter((f) => f.rule?.startsWith('HARVEST'))
  $: nikto = findings.filter((f) => f.rule?.startsWith('NIKTO'))
  $: nuclei = findings.filter((f) => f.rule?.startsWith('NUCLEUS'))
  $: xs = findings.filter((f) => f.rule?.startsWith('XS'))
  $: sqli = findings.filter((f) => f.rule?.includes('SQLI'))
  $: idor = findings.filter((f) => f.rule?.startsWith('IDOR'))
  $: routesF = findings.filter((f) => f.rule === 'DISC-ROUTE')
  $: apiRoutes = findings.filter((f) => f.rule === 'API-ROUTE')
  $: discovery = findings.filter((f) =>
    f.rule === 'SECRET-LEAK' || f.rule === 'EXPOSED-FILE' ||
    f.rule === 'WP-EXPOSED' || f.rule === 'SSRF-SINK' ||
    f.rule === 'GRAPHQL-INTROSPECTION' ||
    f.rule?.startsWith('DISC-')
  )
  $: secrets = discovery.filter((f) => f.rule === 'SECRET-LEAK')
  $: exposedFiles = discovery.filter((f) => f.rule === 'EXPOSED-FILE' || f.rule === 'WP-EXPOSED')

  // OWASP Top 10 posture, grouped per category — mirrors the CLI renderer.
  const OWASP_LABELS = [
    ['OWASP-SENSITIVE', 'Sensitive Data (A02)'],
    ['OWASP-AUTH', 'Authentication (A07)'],
    ['OWASP-CSRF', 'CSRF (A04)'],
    ['OWASP-DESER', 'Insecure Deserialization (A08)'],
    ['OWASP-CONF', 'Security Misconfiguration (A05)'],
    ['OWASP-MONITOR', 'Logging & Monitoring (A09)'],
  ]
  $: owasp = findings.filter((f) => f.rule?.startsWith('OWASP'))
  $: owaspGroups = OWASP_LABELS
    .map(([prefix, label]) => ({
      prefix,
      label,
      items: owasp.filter((f) => f.rule?.startsWith(prefix)),
    }))
    .filter((g) => g.items.length)

  // Sticky TOC + scroll-spy for finding sections.
  let ids = []
  $: ids = findings.map((f, i) => ({ id: `f-${i}`, label: `${f.rule} · ${(f.severity||'info').toUpperCase()}` }))

  function onScroll() {
    let cur = ''
    for (const it of ids) {
      const el = document.getElementById(it.id)
      if (el && el.getBoundingClientRect().top < 140) cur = it.id
    }
    activeHeading = cur
  }
  onMount(() => window.addEventListener('scroll', onScroll, { passive: true }))

  // Remediation diff preview for the first critical/high finding.
  $: diffFinding = findings.find((f) => f.remediation) || null
</script>

{#if loading}
  <section class="block"><div class="wrap"><div class="skeleton" style="height:300px"></div></div></section>
{:else if error}
  <section class="block"><div class="wrap"><p style="color:var(--err)">{error}</p></div></section>
{:else}
  <section class="hero" style="padding-bottom:20px">
    <div class="wrap">
      <div class="kicker">Scan · {(report?.meta?.mode) || job.mode}</div>
      <h1 style="font-size:30px;font-family:var(--mono)">{scanId}</h1>
      <p class="lead">
        {job.status} · durasi {fmtDuration(report?.summary?.duration_ms)}
        {#if report?.summary?.cves_matched} · <b>{report.summary.cves_matched}</b> CVE{/if}
        {#if report?.summary?.open_ports} · <b>{report.summary.open_ports}</b> port{/if}
      </p>
      <div class="meta">
        {#each ['critical','high','medium','low','info'] as sev}
          {#if report?.summary?.[sev] > 0}<span class="badge {sev}">{sev} {report.summary[sev]}</span>{/if}
        {/each}
        <span class="badge">total {report?.summary?.total ?? 0}</span>
      </div>
    </div>
  </section>

  <!-- Pipeline as interactive node graph -->
  <section class="block">
    <div class="wrap">
      <h2>Pipeline</h2>
      <p class="sub">Stage scan sebagai peta prasyarat.</p>
      <StageGraph {stages} />
    </div>
  </section>

  <!-- Domain scan: per-host table -->
  {#if report?.hosts?.length}
    <section class="block">
      <div class="wrap">
        <h2>Host yang Di-scan ({report.hosts.length})</h2>
        <p class="sub">Hasil per subdomain — temuan diagregasi lintas host.</p>
        <table class="tbl">
          <thead><tr><th>Host</th><th>Status</th><th>Temuan</th></tr></thead>
          <tbody>
          {#each report.hosts as h}
            <tr>
              <td class="mono">{h.host}</td>
              <td><span class="badge {h.status === 'completed' ? 'info' : 'critical'}">{h.status}</span></td>
              <td>{h.findings_count}</td>
            </tr>
          {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}

  <!-- Progress checklist -->
  <section class="block">
    <div class="wrap">
      <h2>Checklist Progres</h2>
      <p class="sub">Stage ditandai otomatis saat terlewati.</p>
      <ProgressChecklist
        items={stages.map((s) => ({ id: s.name, label: s.name, detail: s.status }))}
        activeId={stages.find((s) => s.status === 'active')?.name || ''}
      />
    </div>
  </section>

  <!-- Findings layout: sticky TOC + content -->
  <section class="block">
    <div class="wrap" style="display:grid;grid-template-columns:240px 1fr;gap:28px;align-items:start">
      <StickyToc {ids} activeId={activeHeading} />
      <div>
        {#if cves.length}
          <section class="block" id="cves" style="padding-top:0">
            <h2>CVE — Kerentanan Terkenal</h2>
            <div style="display:flex;flex-direction:column;gap:12px">
              {#each cves as f, i}<div id="f-cve-{i}"><FindingCard f={f} /></div>{/each}
            </div>
          </section>
        {/if}

        {#if techs.length}
          <section class="block" id="techs">
            <h2>Teknologi Terdeteksi</h2>
            <div class="grid">
              {#each techs as t}
                <div class="card" style="padding:12px">
                  <div class="card-sub">{t.rule}</div>
                  <div class="card-title" style="font-size:15px">{t.title}</div>
                  {#if t.evidence?.version}<span class="badge">v{t.evidence.version}</span>{/if}
                </div>
              {/each}
            </div>
          </section>
        {/if}

        {#if ports.length}
          <section class="block" id="ports">
            <h2>Port Terbuka</h2>
            <table class="tbl">
              <thead><tr><th>Port</th><th>Service</th><th>Versi</th><th>Banner</th></tr></thead>
              <tbody>
              {#each ports as p}
                <tr>
                  <td class="mono">{p.evidence?.port ?? '—'}</td>
                  <td>{p.evidence?.service ?? '—'}</td>
                  <td>{p.evidence?.version ?? '—'}</td>
                  <td class="mono" style="max-width:260px;overflow:hidden;text-overflow:ellipsis">{p.evidence?.banner ?? '—'}</td>
                </tr>
              {/each}
              </tbody>
            </table>
          </section>
        {/if}

        {#if secrets.length}
          <section class="block" id="secrets">
            <h2>Secret Ter-expose</h2>
            <p class="sub">Deteksi TruffleHog-style — nilai selalu di-redaksi.</p>
            <div style="display:flex;flex-direction:column;gap:12px">
              {#each secrets as f, i}<div id="f-secret-{i}"><FindingCard f={f} /></div>{/each}
            </div>
          </section>
        {/if}

        {#if exposedFiles.length}
          <section class="block" id="exposed">
            <h2>File / Panel Ter-expose</h2>
            <p class="sub">Adaptasi Nikto/Dirsearch/Nuclei/Wpscan.</p>
            <div style="display:flex;flex-direction:column;gap:12px">
              {#each exposedFiles as f, i}<div id="f-exposed-{i}"><FindingCard f={f} /></div>{/each}
            </div>
          </section>
        {/if}

        {#if discovery.filter((f) => !secrets.includes(f) && !exposedFiles.includes(f)).length}
          <section class="block" id="recon">
            <h2>Recon &amp; Discovery</h2>
            <p class="sub">Subdomain, API endpoints, SSRF sinks, GraphQL, vhost, hidden params, wayback.</p>
            <div style="display:flex;flex-direction:column;gap:12px">
              {#each discovery.filter((f) => !secrets.includes(f) && !exposedFiles.includes(f)) as f, i}
                <div id="f-recon-{i}"><FindingCard f={f} /></div>
              {/each}
            </div>
          </section>
        {/if}

        {#if harvest.length}
          <section class="block" id="harvest">
            <h2>Harvest — OSINT Pasif</h2>
            <p class="sub">Subdomain dari crt.sh &amp; Wayback, fingerprint teknologi, email, IP.</p>
            <div style="display:flex;flex-direction:column;gap:12px">
              {#each harvest as f, i}<div id="f-harvest-{i}"><FindingCard f={f} /></div>{/each}
            </div>
          </section>
        {/if}

        {#if nikto.length}
          <section class="block" id="nikto">
            <h2>Nikto — Keamanan Server</h2>
            <p class="sub">Header berbahaya, header hilang, directory listing, info disclosure, software usang.</p>
            <div style="display:flex;flex-direction:column;gap:12px">
              {#each nikto as f, i}<div id="f-nikto-{i}"><FindingCard f={f} /></div>{/each}
            </div>
          </section>
        {/if}

        {#if nuclei.length}
          <section class="block" id="nuclei">
            <h2>Nuclei — Template Vulnerability</h2>
            <p class="sub">CORS misconfig, XSS protection, data sensitif, SSTI, SSRF, shell exec, CRLF.</p>
            <div style="display:flex;flex-direction:column;gap:12px">
              {#each nuclei as f, i}<div id="f-nuclei-{i}"><FindingCard f={f} /></div>{/each}
            </div>
          </section>
        {/if}

        {#if owasp.length}
          <section class="block" id="owasp">
            <h2>OWASP Top 10 Postur</h2>
            <p class="sub">Plaintext HTTP, cookie flags, CSRF, auth-surface reachability, insecure deserialization, logging &amp; monitoring.</p>
            {#each owaspGroups as g}
              <h3>{g.label} ({g.items.length})</h3>
              <div style="display:flex;flex-direction:column;gap:12px">
                {#each g.items as f, i}<div id="f-owasp-{g.prefix}-{i}"><FindingCard f={f} /></div>{/each}
              </div>
            {/each}
          </section>
        {/if}

        {#if xs.length}
          <section class="block" id="xss">
            <h2>XSS Live</h2>
            <p class="sub">Reflected XSS, inline handlers, eval, document.cookie exfil, DOM sinks.</p>
            <div style="display:flex;flex-direction:column;gap:12px">
              {#each xs as f, i}<div id="f-xss-{i}"><FindingCard f={f} /></div>{/each}
            </div>
          </section>
        {/if}

        {#if sqli.length}
          <section class="block" id="sqli">
            <h2>SQLi Live</h2>
            <p class="sub">Error-based SQL injection dan boolean differential pada parameter URL.</p>
            <div style="display:flex;flex-direction:column;gap:12px">
              {#each sqli as f, i}<div id="f-sqli-{i}"><FindingCard f={f} /></div>{/each}
            </div>
          </section>
        {/if}

        {#if idor.length}
          <section class="block" id="idor">
            <h2>IDOR</h2>
            <p class="sub">Endpoint dengan parameter ID yang berpotensi IDOR.</p>
            <div style="display:flex;flex-direction:column;gap:12px">
              {#each idor as f, i}<div id="f-idor-{i}"><FindingCard f={f} /></div>{/each}
            </div>
          </section>
        {/if}

        {#if routesF.length || apiRoutes.length}
          <section class="block" id="routes">
            <h2>Routing / Endpoints</h2>
            <p class="sub">Enumerasi: robots.txt · sitemap · OpenAPI · crawl · JS · wayback.</p>
            {#if routesF.length}
              {#each routesF as rf}
                {#if rf.evidence?.routes?.length}
                  <table class="tbl">
                    <thead><tr><th>Path</th><th>Sumber</th><th>Klasifikasi</th></tr></thead>
                    <tbody>
                    {#each rf.evidence.routes.slice(0, 30) as r}
                      <tr>
                        <td class="mono">{r.path}</td>
                        <td>{r.source}</td>
                        <td><span class="badge {r.classification === 'sensitive' ? 'critical' : r.classification === 'api' ? 'high' : 'info'}">{r.classification}</span></td>
                      </tr>
                    {/each}
                    </tbody>
                  </table>
                {/if}
              {/each}
            {/if}
            {#if apiRoutes.length}
              <div style="display:flex;flex-direction:column;gap:12px;margin-top:12px">
                {#each apiRoutes as f, i}<div id="f-apiroute-{i}"><FindingCard f={f} /></div>{/each}
              </div>
            {/if}
          </section>
        {/if}

        {#if findings.length}
          <section class="block" id="findings">
            <h2>Semua Temuan</h2>
            <p class="sub">Klik entri di TOC untuk lompat ke detail.</p>
            <div style="display:flex;flex-direction:column;gap:14px">
              {#each findings as f, i}
                <div id="f-{i}"><FindingCard f={f} /></div>
              {/each}
            </div>
          </section>
        {:else}
          <section class="block"><p class="muted">Tidak ada temuan.</p></section>
        {/if}

        {#if diffFinding}
          <section class="block" id="remediation">
            <h2>Diff Remediasi (Contoh)</h2>
            <p class="sub">Klik tombol untuk melihat perubahan sebelum → sesudah.</p>
            <DiffWidget before={diffFinding.location || '---'} after={diffFinding.remediation || ''} />
          </section>
        {/if}
      </div>
    </div>
  </section>

  {#if celebrate}
    <Celebration message="Scan selesai — semua stage berhasil" onClose={() => (celebrate = false)} />
  {/if}
{/if}
