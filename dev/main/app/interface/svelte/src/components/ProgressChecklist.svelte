<script>
  // Progress checklist — auto-checks items as the user scrolls past them.
  export let items = []   // [{id, label, detail}]
  export let activeId = ''
  $: checked = (id) => {
    // Items before the currently-active one (or all if none active) count done.
    if (!activeId) return false
    const idx = items.findIndex((i) => i.id === activeId)
    return items.findIndex((i) => i.id === id) < idx
  }
</script>

<ul class="checklist">
  {#each items as it}
    <li class:checked={checked(it.id)}>
      <div class="tick">✓</div>
      <div>
        <div style="font-weight:600">{it.label}</div>
        {#if it.detail}<div class="muted" style="font-size:14px">{it.detail}</div>{/if}
      </div>
    </li>
  {/each}
</ul>
