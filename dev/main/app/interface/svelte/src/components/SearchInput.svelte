<script>
  // Reusable search input — debounced, with a clear button and a result
  // count. Emits `value` upward via the two-way bind (bind:value on the
  // parent's `query`) and updates `count` inside.
  import { debounce } from '../lib/search.js'

  export let value = ''
  export let count = null          // visible result count (optional)
  export let placeholder = 'Cari…'
  export let label = 'Cari'

  let inner = value
  const push = debounce(() => { value = inner }, 120)

  function onChange() { push() }
  function clear() { inner = ''; value = '' }
</script>

<div class="searchbar">
  <svg class="searchbar-icon" viewBox="0 0 16 16" aria-hidden="true" width="14" height="14">
    <circle cx="7" cy="7" r="4.5" fill="none" stroke="currentColor" stroke-width="1.5"></circle>
    <line x1="10.5" y1="10.5" x2="14" y2="14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"></line>
  </svg>
  <input
    class="searchbar-input"
    type="search"
    bind:value={inner}
    oninput={onChange}
    placeholder={placeholder}
    aria-label={label}
  />
  {#if inner}
    <button class="searchbar-clear" type="button" onclick={clear} aria-label="Bersihkan pencarian">✕</button>
  {/if}
  {#if count !== null}
    <span class="searchbar-count">{count} hasil</span>
  {/if}
</div>