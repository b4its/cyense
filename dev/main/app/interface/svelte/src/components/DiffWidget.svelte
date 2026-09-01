<script>
  // Animated before → after diff widget for remediation previews.
  export let before = ''
  export let after = ''
  export let label = 'Remediasi'
  let showAfter = false
</script>

<div class="diff">
  <div class="diff-head">
    <span>{label}</span>
    <button onclick={() => (showAfter = !showAfter)}>
      {showAfter ? '◀ Sebelum' : '▶ Sesudah ▶'}
    </button>
  </div>
  {#if !showAfter}
    <pre class="mono">{before || '(tidak ada diff)'}</pre>
  {:else}
    <pre class="mono"><span class="del">{before}</span>{after ? '\n' : ''}<span class="add">{after}</span></pre>
  {/if}
</div>
