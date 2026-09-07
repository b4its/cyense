<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import SearchInput from '../components/SearchInput.svelte'
  import Pagination from '../components/Pagination.svelte'
  import { buildIndex, searchIndex } from '../lib/search.js'

  let rules = null
  let loading = true
  let error = ''
  let query = ''
  let page = 1
  let pageSize = 24

  // ---- search index ------------------------------------------------------
  // Built ONCE when the catalog arrives. Flat arrays stay aligned by index:
  //   flatRule[i]  → the rule object
  //   flatKey[i]   → lowercased searchable string
  //   catOf(rule)  → owning category label (by row identity, so it survives
  //                   searchIndex filtering which may drop rows and shift i).
  let flatRule = []
  let flatKey = []
  let catOf = new Map()
  let built = false

  function buildFlat() {
    if (!rules || built) return
    flatRule = []
    flatKey = []
    catOf = new Map()
    for (const [g, list] of Object.entries(rules)) {
      for (const r of list || []) {
        flatRule.push(r)
        catOf.set(r, g)
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
      }
    }
    built = true
  }

  $: if (rules) buildFlat()

  // Reactive index: recompute when flatRule/flatKey are rebuilt (they'd
  // otherwise be captured by a const and stay empty → 0 rules forever).
  $: index = { rows: flatRule, keys: flatKey }
  $: matched = searchIndex(index, query)

  // Pagination over the flat matched set (regrouped by category within the
  // current page so each visible section only shows rules from this slice).
  $: totalRules = matched.length
  $: start = (page - 1) * pageSize
  $: paged = matched.slice(start, start + pageSize)

  // Reset page to 1 when the search filter changes (not when paging itself).
  $: { void query; page = 1 }

  // Regroup paged rules by category, preserving the order they appear in.
  // catOf() keys rule → group by object identity, so filtered rows resolve
  // their true category even when searchIndex removed some rows upstream.
  $: visibleGroups = (() => {
    const out = []
    const order = new Map()
    for (const r of paged) {
      const cat = catOf.get(r) || 'Uncategorized'
      if (!order.has(cat)) {
        order.set(cat, out.length)
        out.push([cat, []])
      }
      out[order.get(cat)][1].push(r)
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
    <h1>{loading ? '…' : `${totalRules} dari ${flatRule.length} rules`}</h1>
    <p class="lead">IDOR, XSS, SQLi, deteksi teknologi, port scan, dan CVE — dikelompokkan per kategori.</p>
    <div style="max-width:480px">
      <SearchInput bind:value={query} count={totalRules} placeholder="Cari rule / CWE / severity…" label="Cari rules" />
    </div>
  </div>
</section>

<section class="block">
  <div class="wrap">
    {#if loading}<div class="skeleton" style="height:300px"></div>
    {:else if error}<p style="color:var(--err)">{error}</p>
    {:else if query && !totalRules}
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
      <Pagination bind:page={page} bind:pageSize={pageSize}
                  total={totalRules} label="Navigasi rules per halaman" />
    {/if}
  </div>
</section>