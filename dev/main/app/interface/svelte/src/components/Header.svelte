<script>
  import { onMount, onDestroy } from 'svelte'
  import ThemeSwitch from './ThemeSwitch.svelte'

  let route = ''
  let open = false
  let utcClock = '--:--:--Z'
  let timer = null

  function updateUtc() {
    const d = new Date()
    const hh = String(d.getUTCHours()).padStart(2, '0')
    const mm = String(d.getUTCMinutes()).padStart(2, '0')
    const ss = String(d.getUTCSeconds()).padStart(2, '0')
    utcClock = `${hh}:${mm}:${ss}Z`
  }

  onMount(() => {
    const sync = () => { route = (location.hash || '#/').replace('#', '') || '/' }
    sync()
    window.addEventListener('hashchange', sync)
    updateUtc()
    timer = setInterval(updateUtc, 1000)
  })

  onDestroy(() => {
    if (timer) clearInterval(timer)
  })

  $: active = (p) => (p === '/' ? route === '/' : route.startsWith(p))
  function nav() { open = false }
</script>

<div class="header-container">
  <header class="ops-header">
    <div class="brand-slot">
      <a class="brand-mark" href="#/" onclick={nav} title="Cyense // Tactical Offensive Security">
        NOX<span class="slash">//</span>SEC
      </a>
      <span class="ops-version">(v4.2 · OPS LIVE)</span>
      <span class="cyense-tag">CYENSE</span>
    </div>

    <nav class="center-nav" class:mobile-open={open}>
      <a href="#/" class:active={active('/')} onclick={nav}>dashboard</a>
      <a href="#/websites" class:active={active('/websites')} onclick={nav}>websites</a>
      <a href="#/scans" class:active={active('/scans')} onclick={nav}>scans</a>
      <a href="#/tools" class:active={active('/tools')} onclick={nav}>tools</a>
      <a href="#/rules" class:active={active('/rules')} onclick={nav}>rules</a>
    </nav>

    <div class="right-slot">
      <div class="utc-clock" title="Live UTC Military Operations Clock">
        <span class="utc-dot">●</span>
        <span class="utc-time">{utcClock}</span>
      </div>
      <ThemeSwitch />
      <button class="mobile-toggle" onclick={() => (open = !open)} aria-label="Toggle navigation">
        <span></span><span></span><span></span>
      </button>
    </div>
  </header>

  <div class="status-bar">
    <div class="status-cell">STATUS: <b>OPS NOMINAL</b></div>
    <div class="status-cell">HONEYPOTS: <b>14</b></div>
    <div class="status-cell">ACTIVE PROBES: <b>312</b></div>
    <div class="status-cell">ZERODAYS '26: <b>3 SHIPPED</b></div>
    <div class="status-cell alert-cell">
      <span class="blink-siren">●</span>
      <span>ON CALL: <b>OPEN INTAKE</b></span>
    </div>
  </div>
</div>

<style>
  .header-container {
    position: sticky;
    top: 0;
    z-index: 1000;
    background: var(--bg);
  }

  .ops-header {
    display: grid;
    grid-template-columns: auto 1fr auto;
    align-items: center;
    height: 48px;
    padding: 0 24px;
    border-bottom: 1px solid var(--line);
    background: var(--panel);
    gap: 16px;
  }

  .brand-slot {
    display: flex;
    align-items: center;
    gap: 10px;
    white-space: nowrap;
  }

  .brand-mark {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 15px;
    font-weight: 700;
    color: var(--fg);
    text-decoration: none;
    letter-spacing: 0.04em;
    display: inline-flex;
    align-items: center;
  }

  .brand-mark .slash {
    color: var(--red);
  }

  .ops-version {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    letter-spacing: 0.08em;
    color: var(--mute);
  }

  .cyense-tag {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 9px;
    padding: 1px 5px;
    border: 1px solid var(--line);
    color: var(--red);
    letter-spacing: 0.14em;
    text-transform: uppercase;
  }

  .center-nav {
    display: flex;
    justify-content: center;
    gap: 20px;
  }

  .center-nav a {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 13px;
    color: var(--fg);
    text-decoration: none;
    text-transform: lowercase;
    transition: color 0.2s ease, text-shadow 0.2s ease;
  }

  .center-nav a::before {
    content: '> ';
    color: var(--mute);
    margin-right: 2px;
    transition: color 0.2s ease;
  }

  .center-nav a:hover,
  .center-nav a.active {
    color: var(--red);
    text-shadow: 0 0 8px var(--red);
  }

  .center-nav a:hover::before,
  .center-nav a.active::before {
    color: var(--red);
  }

  .right-slot {
    display: flex;
    align-items: center;
    gap: 16px;
  }

  .utc-clock {
    display: flex;
    align-items: center;
    gap: 6px;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 12px;
    color: var(--acid);
    letter-spacing: 0.08em;
  }

  .utc-dot {
    font-size: 8px;
    color: var(--acid);
    animation: blink 1.5s infinite;
  }

  .mobile-toggle {
    display: none;
    background: transparent;
    border: 1px solid var(--line);
    padding: 6px;
    cursor: pointer;
    flex-direction: column;
    gap: 4px;
  }

  .mobile-toggle span {
    display: block;
    width: 18px;
    height: 2px;
    background: var(--fg);
  }

  .status-bar {
    display: grid;
    grid-template-columns: repeat(5, auto);
    justify-content: space-between;
    padding: 6px 24px;
    background: var(--bg);
    border-bottom: 1px solid var(--line);
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--mute);
  }

  .status-cell b {
    color: var(--acid);
    font-weight: 700;
  }

  .alert-cell {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .blink-siren {
    color: var(--red);
    animation: blink 1.5s infinite;
    font-size: 10px;
  }

  @keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.15; }
  }

  @media (max-width: 880px) {
    .ops-header {
      grid-template-columns: 1fr auto;
    }

    .center-nav {
      display: none;
      position: absolute;
      top: 48px;
      left: 0;
      right: 0;
      background: var(--panel);
      flex-direction: column;
      padding: 16px 24px;
      gap: 12px;
      border-bottom: 1px solid var(--red);
      z-index: 1001;
    }

    .center-nav.mobile-open {
      display: flex;
    }

    .mobile-toggle {
      display: flex;
    }

    .status-bar {
      display: none !important;
    }
  }
</style>
