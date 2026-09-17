<script>
  import { theme, toggleTheme } from '../lib/theme.js'

  function handleKeydown(e) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      toggleTheme()
    }
  }
</script>

<div class="theme-switch-wrap">
  <button
    type="button"
    class="theme-switch"
    role="switch"
    aria-checked={$theme === 'dark'}
    aria-label="Toggle dark and light operational theme"
    onclick={toggleTheme}
    onkeydown={handleKeydown}
    title="Switch between CRT Dark and Tactical Light theme"
  >
    <span class="ts-label">// THEME</span>
    <div class="ts-track" class:is-dark={$theme === 'dark'}>
      <span class="ts-thumb"></span>
    </div>
    <span class="ts-mode">{$theme === 'dark' ? 'DARK' : 'LIGHT'}</span>
  </button>
</div>

<style>
  .theme-switch-wrap {
    display: inline-flex;
    align-items: center;
  }

  .theme-switch {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: transparent;
    border: 1px solid rgba(255, 26, 60, 0.3);
    padding: 4px 8px;
    cursor: pointer;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    letter-spacing: 0.12em;
    color: var(--fg, #f5e8e8);
    transition: border-color 0.2s, box-shadow 0.2s;
    border-radius: 0;
  }

  .theme-switch:hover {
    border-color: var(--red, #ff1a3c);
    box-shadow: 0 0 12px rgba(255, 26, 60, 0.25);
  }

  .ts-label {
    color: var(--mute, #8a5a64);
    font-weight: 400;
  }

  .ts-track {
    position: relative;
    width: 32px;
    height: 14px;
    background: var(--panel, #0e0508);
    border: 1px solid var(--mute, #8a5a64);
    border-radius: 0;
    transition: border-color 0.2s, background-color 0.2s;
  }

  .ts-thumb {
    position: absolute;
    top: 1px;
    left: 1px;
    width: 10px;
    height: 10px;
    background: var(--mute, #8a5a64);
    border-radius: 0;
    transition: transform 0.2s ease, background-color 0.2s ease;
  }

  .ts-track.is-dark {
    border-color: var(--red, #ff1a3c);
  }

  .ts-track.is-dark .ts-thumb {
    transform: translateX(18px);
    background: var(--red, #ff1a3c);
    box-shadow: 0 0 6px var(--red, #ff1a3c);
  }

  :global([data-theme='light']) .ts-track:not(.is-dark) {
    border-color: var(--acid, #0d8236);
  }

  :global([data-theme='light']) .ts-track:not(.is-dark) .ts-thumb {
    transform: translateX(0);
    background: var(--acid, #0d8236);
  }

  .ts-mode {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 10px;
    color: var(--acid, #42ff8a);
    letter-spacing: 0.08em;
  }

  :global([data-theme='light']) .ts-mode {
    color: var(--red, #d90f2f);
  }
</style>
