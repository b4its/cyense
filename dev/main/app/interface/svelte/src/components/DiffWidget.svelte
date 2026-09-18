<script>
  // Animated before → after diff widget for remediation previews.
  export let before = ''
  export let after = ''
  export let label = 'AST REMEDIATION PATCH'
  let viewMode = 'diff' // 'diff' | 'before' | 'after'
  let copied = false

  function copyPatch() {
    const text = after || before
    navigator.clipboard.writeText(text)
    copied = true
    setTimeout(() => { copied = false }, 1800)
  }
</script>

<div class="tactical-diff">
  <div class="diff-head">
    <div class="head-tag">
      <span class="diff-dot">●</span>
      <span class="diff-title">{label}</span>
    </div>

    <div class="diff-actions">
      <div class="mode-toggles">
        <button
          class="mode-btn"
          class:active={viewMode === 'diff'}
          onclick={() => (viewMode = 'diff')}
        >
          UNIFIED
        </button>
        <button
          class="mode-btn"
          class:active={viewMode === 'before'}
          onclick={() => (viewMode = 'before')}
        >
          VULNERABLE
        </button>
        <button
          class="mode-btn"
          class:active={viewMode === 'after'}
          onclick={() => (viewMode = 'after')}
        >
          SECURE FIX
        </button>
      </div>

      <button class="copy-patch-btn" onclick={copyPatch}>
        {copied ? 'COPIED!' : 'COPY FIX'}
      </button>
    </div>
  </div>

  <div class="diff-content">
    {#if viewMode === 'before'}
      <pre class="code-block del-block"><span class="gutter">-</span> {before || '// Tidak ada kode rentan awal'}</pre>
    {:else if viewMode === 'after'}
      <pre class="code-block add-block"><span class="gutter">+</span> {after || '// Tidak ada patch kode baru'}</pre>
    {:else}
      <pre class="code-block unified-block"><span class="del"><span class="gutter">-</span> {before || '(vulnerable code)'}</span>{'\n'}<span class="add"><span class="gutter">+</span> {after || '(secure AST fix)'}</span></pre>
    {/if}
  </div>
</div>

<style>
  .tactical-diff {
    background: #080306;
    border: 1px solid var(--line, rgba(255, 26, 60, 0.25));
    border-radius: 0;
    overflow: hidden;
    margin-top: 10px;
  }

  .diff-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 16px;
    background: var(--bg-soft, #14080c);
    border-bottom: 1px solid var(--line, rgba(255, 26, 60, 0.2));
    flex-wrap: wrap;
    gap: 8px;
  }

  .head-tag {
    display: flex;
    align-items: center;
    gap: 8px;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    color: var(--fg, #f5e8e8);
    font-weight: 700;
    letter-spacing: 0.08em;
  }

  .diff-dot {
    color: var(--acid, #42ff8a);
    font-size: 9px;
  }

  .diff-actions {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .mode-toggles {
    display: flex;
    border: 1px solid var(--line, rgba(255, 26, 60, 0.25));
  }

  .mode-btn {
    background: transparent;
    border: none;
    border-right: 1px solid var(--line, rgba(255, 26, 60, 0.25));
    color: var(--mute, #8a5a64);
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    letter-spacing: 0.06em;
    padding: 4px 10px;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .mode-btn:last-child {
    border-right: none;
  }

  .mode-btn:hover {
    color: var(--fg, #f5e8e8);
  }

  .mode-btn.active {
    background: rgba(255, 26, 60, 0.15);
    color: var(--red, #ff1a3c);
    font-weight: 700;
  }

  .copy-patch-btn {
    background: transparent;
    border: 1px solid var(--line, rgba(255, 26, 60, 0.3));
    color: var(--mute, #8a5a64);
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 9px;
    letter-spacing: 0.04em;
    padding: 4px 10px;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .copy-patch-btn:hover {
    border-color: var(--acid, #42ff8a);
    color: var(--acid, #42ff8a);
  }

  .diff-content {
    padding: 12px 16px;
    background: #050204;
    overflow-x: auto;
  }

  .code-block {
    margin: 0;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 12px;
    line-height: 1.6;
    color: var(--fg, #f5e8e8);
  }

  .gutter {
    display: inline-block;
    width: 14px;
    user-select: none;
    font-weight: 700;
  }

  .del-block,
  .del {
    color: #ff5c73;
    background: rgba(255, 26, 60, 0.08);
    display: block;
    padding: 2px 4px;
  }

  .add-block,
  .add {
    color: #42ff8a;
    background: rgba(66, 255, 138, 0.08);
    display: block;
    padding: 2px 4px;
  }
</style>
