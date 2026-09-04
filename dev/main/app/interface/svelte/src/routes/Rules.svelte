<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'

  let rules = null
  let loading = true
  let error = ''
  let groups = []
  let total = 0

  onMount(async () => {
    try {
      rules = await api.rules()
      groups = Object.entries(rules || {})
      total = groups.reduce((a, [, list]) => a + (list?.length || 0), 0)
    } catch (e) { error = String(e) }
    loading = false
  })
</script>

<section class="hero" style="padding-bottom:24px">
  <div class="wrap">
    <div class="kicker">Rule Catalog</div>
    <h1>{loading ? '…' : `${total} rules deteksi`}</h1>
    <p class="lead">IDOR, XSS, SQLi, deteksi teknologi, port scan, dan CVE — dikelompokkan per kategori.</p>
  </div>
</section>

<section class="block">
  <div class="wrap">
    {#if loading}<div class="skeleton" style="height:300px"></div>
    {:else if error}<p style="color:var(--err)">{error}</p>
    {:else}
      {#each groups as [group, list]}
        <section class="block">
          <h2>{group.replace(/_/g, ' ')}</h2>
          <p class="sub">{list?.length || 0} rule</p>
          <div class="table-scroll">
          <table class="tbl">
            <thead><tr><th>Rule</th><th>Severity</th><th>Lang</th><th>CWE</th><th>CVSS</th><th>Title</th></tr></thead>
            <tbody>
            {#each list || [] as r}
              <tr>
                <td class="mono">{r.rule}</td>
                <td><span class="badge {((Array.isArray(r.severity) ? (r.severity[0] || 'info') : (r.severity || 'info')).toLowerCase())}">{(Array.isArray(r.severity) ? r.severity.join(',') : (r.severity || 'info')).toUpperCase()}</span></td>
                <td>{r.lang || '—'}</td>
                <td class="mono">{r.cwe || '—'}</td>
                <td>{r.cvss_score ?? '—'}</td>
                <td style="max-width:380px">{r.title || '—'}</td>
              </tr>
            {/each}
            </tbody>
          </table>
          </div>
        </section>
      {/each}
    {/if}
  </div>
</section>
