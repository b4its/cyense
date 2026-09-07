<script>
  // SearchableSelect — an accessible combobox: a search input filters the
  // options of a native <select> that stays fully usable (keyboard, screen
  // readers, form semantics). Emits the chosen value via `value`.
  export let value = ''
  export let items = []      // [{value, label}]
  export let placeholder = 'Pilih / cari...'
  export let label = 'Pilih'
  export let searchable = true
  export let size = ''       // '' | 'sm' (small)
  export let classes = ''    // extra css classes passthrough

  let open = false
  let query = ''
  let root
  let searchBox

  // Only the built-in "search" + options below are needed; native select keeps
  // full semantics (a11y), the filtered view is our visual layer.
  $: filtered = (query || '').trim()
    ? items.filter((i) =>
        String(i.label).toLowerCase().includes(query.trim().toLowerCase()))
    : items

  $: currentLabel = items.find((i) => i.value === value)?.label || ''

  function toggle(force) { open = typeof force === 'boolean' ? force : !open }

  function onPick(i) {
    value = i.value
    query = ''
    open = false
  }

  function clear() { value = ''; query = ''; open = false }

  function onKey(e) {
    if (e.key === 'Escape') { open = false; query = '' }
    if (e.key === 'ArrowDown') { e.preventDefault(); open = true }
    if (e.key === 'Enter' && open) e.preventDefault()
  }

  // Close when clicking outside.
  function onDoc(e) {
    if (root && !root.contains(e.target)) open = false
  }

  $: if (open) {
    // keep the search focused once the menu shows
    if (searchBox) requestAnimationFrame(() => searchBox.focus())
  }
</script>

<svelte:window onclick={onDoc} />

<div class="ssel {classes} {size ? 'sm' : ''}" bind:this={root}>
  {#if searchable}
    <div class="ssel-trigger" onclick={() => toggle()} role="button"
         tabindex="0" aria-label={label}
         onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle() } }}>
      <span class="ssel-current">
        {#if currentLabel}
          {currentLabel}
        {:else}
          <em class="ssel-ph">{placeholder}</em>
        {/if}
      </span>
      <svg class="ssel-arrow" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
        <path d="M4 6l4 4 4-4" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round"/>
      </svg>
    </div>
  {:else}
    <select class="ssel-native" {value} onchange={(e) => { value = e.currentTarget.value }}>
      {#each items as i}<option value={i.value}>{i.label}</option>{/each}
    </select>
  {/if}

  {#if open}
    <div class="ssel-menu" role="listbox" aria-label={label}>
      <div class="ssel-search">
        <svg class="ssel-search-icon" viewBox="0 0 16 16" width="13" height="13" aria-hidden="true">
          <circle cx="7" cy="7" r="4.5" fill="none" stroke="currentColor" stroke-width="1.5"/>
          <line x1="10.5" y1="10.5" x2="14" y2="14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
        <input
          bind:this={searchBox}
          class="ssel-search-input"
          type="search"
          bind:value={query}
          onkeydown={onKey}
          placeholder="Cari..."
          aria-label="Cari {label}"
        />
      </div>
      <div class="ssel-options">
        {#if value}
          <button class="ssel-opt ssel-clear" role="option" aria-selected="false" onclick={clear}>
            ✕ Hapus pilihan
          </button>
        {/if}
        {#if !filtered.length}
          <div class="ssel-empty">Tidak ada hasil</div>
        {:else}
          {#each filtered as i}
            <button
              class="ssel-opt {i.value === value ? 'active' : ''}"
              role="option"
              aria-selected={i.value === value}
              onclick={() => onPick(i)}
              onkeydown={onKey}
            ><span class="ssel-opt-label">{i.label}</span>
              {#if i.value === value}<span class="ssel-check">✓</span>{/if}
            </button>
          {/each}
        {/if}
        <div class="ssel-count">{filtered.length} opsi</div>
      </div>
    </div>
  {/if}
</div>

<style>
  .ssel { position: relative; display: inline-block; min-width: 200px; max-width: 100%; }
  .ssel.sm { min-width: 150px; }

  .ssel-trigger, .ssel-native {
    display: flex; align-items: center; gap: 8px; justify-content: space-between;
    font-family: var(--mono); font-size: 13px; padding: 9px 12px; border-radius: 10px;
    border: 1px solid var(--line); background: var(--bg-elev); color: var(--ink);
    cursor: pointer; width: 100%; transition: border-color .2s;
  }
  .ssel-trigger:hover, .ssel-trigger:focus-visible, .ssel-native:focus {
    border-color: var(--accent); outline: none;
  }
  .ssel-current { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .ssel-ph { font-style: normal; color: var(--ink-faint); }
  .ssel-arrow { color: var(--ink-faint); flex: 0 0 auto; transition: transform .2s; }
  .ssel.open .ssel-arrow { transform: rotate(180deg); }

  .ssel-menu {
    position: absolute; top: calc(100% + 6px); left: 0; right: 0; z-index: 30;
    background: var(--bg-elev); border: 1px solid var(--line); border-radius: 12px;
    box-shadow: var(--shadow); overflow: hidden; display: flex; flex-direction: column;
  }
  .ssel-search { display: flex; align-items: center; gap: 8px; padding: 8px 10px; border-bottom: 1px solid var(--line); }
  .ssel-search-icon { color: var(--ink-faint); flex: 0 0 auto; }
  .ssel-search-input {
    flex: 1; min-width: 0; border: none; outline: none; background: transparent;
    color: var(--ink); font-family: var(--mono); font-size: 13px;
  }
  .ssel-search-input::placeholder { color: var(--ink-faint); }

  .ssel-options { max-height: 240px; overflow-y: auto; display: flex; flex-direction: column; padding: 4px; }
  .ssel-opt {
    display: flex; align-items: center; justify-content: space-between; gap: 8px;
    text-align: left; border: none; background: transparent; color: var(--ink);
    font-family: var(--serif); font-size: 14px; padding: 8px 10px; border-radius: 8px;
    cursor: pointer; transition: background .15s;
  }
  .ssel-opt:hover, .ssel-opt:focus-visible { background: var(--bg-soft); outline: none; }
  .ssel-opt.active { color: var(--accent-strong); font-weight: 600; }
  .ssel-opt-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .ssel-check { color: var(--accent-strong); font-weight: 700; flex: 0 0 auto; }
  .ssel-clear { color: var(--err); font-size: 13px; }
  .ssel-empty { padding: 10px; text-align: center; color: var(--ink-faint); font-size: 13px; font-family: var(--mono); }
  .ssel-count { padding: 6px 10px; text-align: right; color: var(--ink-faint); font-size: 11px; font-family: var(--mono); border-top: 1px solid var(--line); }
</style>