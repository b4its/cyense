<script>
  // Reusable pagination controls for data-heavy lists (Tools grid, Rules table,
  // Scan/Website lists). Keeps the DOM light: render only `pageSize` rows per
  // page. `page` is two-way bound to the parent (bind:page). When the parent's
  // filter/search changes, it resets `page` to 1.
  export let page = 1
  export let total = 0
  export let pageSize = 24
  export let label = 'Navigasi halaman'

  $: pages = Math.max(1, Math.ceil((total || 0) / pageSize))
  $: start = total ? (page - 1) * pageSize + 1 : 0
  $: end = Math.min(page * pageSize, total || 0)

  function goto(p) {
    page = Math.min(Math.max(1, p), pages)
  }

  // Windowed page-number list with ellipses, e.g. [1,'…',4,5,6,'…',12].
  $: window = (() => {
    const out = []
    const span = 2
    const lo = Math.max(1, page - span)
    const hi = Math.min(pages, page + span)
    if (lo > 1) { out.push(1); if (lo > 2) out.push('…') }
    for (let i = lo; i <= hi; i++) out.push(i)
    if (hi < pages) { if (hi < pages - 1) out.push('…'); out.push(pages) }
    return out
  })()
</script>

{#if pages > 1}
  <nav class="pager" aria-label={label}>
    <div class="pager-info" aria-live="polite">
      {#if total}Menampilkan {start}–{end} dari {total}{:else}0 hasil{/if}
    </div>
    <div class="pager-btns" role="group" aria-label="Kontrol halaman">
      <button type="button" class="pager-btn" onclick={() => goto(page - 1)}
              disabled={page <= 1} aria-label="Halaman sebelumnya">‹</button>
      {#each window as n}
        {#if n === '…'}
          <span class="pager-ellipsis" aria-hidden="true">…</span>
        {:else}
          <button type="button"
                  class="pager-btn {n === page ? 'active' : ''}"
                  onclick={() => goto(n)}
                  aria-current={n === page ? 'page' : undefined}>{n}</button>
        {/if}
      {/each}
      <button type="button" class="pager-btn" onclick={() => goto(page + 1)}
              disabled={page >= pages} aria-label="Halaman berikutnya">›</button>
    </div>
    <label class="pager-size">
      Baris/halaman
      <select class="pager-select" value={String(pageSize)}
              onchange={(e) => { pageSize = Number(e.currentTarget.value); page = 1 }}>
        <option value="12">12</option>
        <option value="24">24</option>
        <option value="48">48</option>
        <option value="96">96</option>
      </select>
    </label>
  </nav>
{/if}
