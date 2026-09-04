<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import SearchInput from '../components/SearchInput.svelte'
  import { buildIndex, searchIndex } from '../lib/search.js'

  let rules = null
  let loading = true
  let error = ''
  let query = ''

  // ---- search index ------------------------------------------------------
  // Built ONCE when the catalog arrives. Flat arrays stay aligned by index:
  //   flatRule[i]  → the rule object
  //   flatKey[i]   → lowercased searchable string
  //   flatCat[i]   → owning category label
  // Filtering then is a single linear pass — no nested per-group re-walks,
  // no N+1.
  let flatRule = []
  let flatKey = []
  let flatCat = []
  let built = false

  function buildFlat() {
    if (!rules || built) return
    flatRule = []
    flatKey = []
    flatCat = []
    for (const [g, list] of Object.entries(rules)) {
      for (const r of list || []) {
        flatRule.push(r)
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
        flatCat.push(g)
      }
    }
    built = true
  }

  $: if (rules) buildFlat()

  const index = { rows: flatRule, keys: flatKey }
  $: matched = searchIndex(index, query)

  // Regroup the flat matches by category, preserving the catalog order of
  // groups and skipping empty ones.
  $: visibleGroups = (() => {
    const out = []
    const order = new Map()
    for (let i = 0; i < matched.length; i++) {
      const cat = flatCat[i]
      if (!order.has(cat)) {
        order.set(cat, out.length)
        out.push([cat, []])
      }
      out[order.get(cat)][1].push(matched[i])
    }
    return out
  })()

  onMount(async () => {
    try {
      rules = await api.rules()
      buildFlat()
    } catch (e) { error = String(e) }
    loading = false
  })
</script>

<section class="hero" style="padding-bottom:24px">
  <div class="wrap">
    <div class="kicker">Rule Catalog</div>
    <h1>{loading ? '…' : `${matched.length} dari ${flatRule.length} rules`}</h1>
    <p class="lead">IDOR, XSS, SQLi, deteksi teknologi, port scan, dan CVE — dikelompokkan per kategori.</p>
    <div style="max-width:480px">
      <SearchInput bind:value={query} count={matched.length} placeholder="Cari rule / CWE / severity…" label="Cari rules" />
    </div>
  </div>
</section>

<section class="block">
  <div class="wrap">
    {#if loading}<div class="skeleton" style="height:300px"></div>
    {:else if error}<p style="color:var(--err)">{error}</p>
    {:else if query && !matched.length}
      <p class="muted">Tidak ada rule yang cocok dengan "{query}".</p>
    {:else}
      {#each visibleGroups as [g, list]}
        <section class="block">
          <h2>{g.replace(/_/g, ' ')}</h2>
          <p class="sub">{list.length} rule</p>
          <div class="table-scroll">
          <table class="tbl">
            <thead><tr><th>Rule</th><th>Severity</th><th>Lang</th><th>CWE</th><th>CVSS</th><th>Title</th></tr></thead>
            <tbody>
            {#each list as r}
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