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
    background: var(--panel);
    border: 1px solid var(--line);
    padding: 4px 10px;
    cursor: pointer;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    letter-spacing: 0.12em;
    color: var(--fg);
    transition: border-color 0.2s, box-shadow 0.2s, background-color 0.2s;
    border-radius: 0;
  }

  .theme-switch:hover {
    border-color: var(--red);
    box-shadow: 0 0 12px rgba(255, 26, 60, 0.25);
  }

  :global([data-theme='light']) .theme-switch:hover {
    border-color: var(--red);
    box-shadow: 0 0 12px rgba(217, 15, 47, 0.2);
  }

  .ts-label {
    color: var(--mute);
    font-weight: 400;
  }

  .ts-track {
    position: relative;
    width: 32px;
    height: 14px;
    background: var(--bg);
    border: 1px solid var(--mute);
    border-radius: 0;
    transition: border-color 0.2s, background-color 0.2s;
  }

  .ts-thumb {
    position: absolute;
    top: 1px;
    left: 1px;
    width: 10px;
    height: 10px;
    background: var(--mute);
    border-radius: 0;
    transition: transform 0.2s ease, background-color 0.2s ease;
  }

  .ts-track.is-dark {
    border-color: var(--red);
  }

  .ts-track.is-dark .ts-thumb {
    transform: translateX(18px);
    background: var(--red);
    box-shadow: 0 0 6px var(--red);
  }

  :global([data-theme='light']) .ts-track:not(.is-dark) {
    border-color: var(--acid);
  }

  :global([data-theme='light']) .ts-track:not(.is-dark) .ts-thumb {
    transform: translateX(0);
    background: var(--acid);
  }

  .ts-mode {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 10px;
    color: var(--acid);
    letter-spacing: 0.08em;
    min-width: 38px;
    text-align: left;
  }

  :global([data-theme='light']) .ts-mode {
    color: var(--acid);
  }
</style>
