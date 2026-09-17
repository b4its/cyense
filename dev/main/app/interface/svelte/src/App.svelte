<script>
  import Header from './components/Header.svelte'
  import Dashboard from './routes/Dashboard.svelte'
  import Scans from './routes/Scans.svelte'
  import ScanDetail from './routes/ScanDetail.svelte'
  import Websites from './routes/Websites.svelte'
  import Rules from './routes/Rules.svelte'
  import Tools from './routes/Tools.svelte'
  import { onMount } from 'svelte'

  let route = '/'
  const currentYear = new Date().getFullYear()

  onMount(() => {
    const sync = () => { route = (location.hash || '#/').replace('#', '') || '/' }
    sync()
    window.addEventListener('hashchange', sync)

    // IntersectionObserver -> tambah class .in ke .reveal saat 10% masuk viewport
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('in')
          }
        })
      },
      { threshold: 0.10 }
    )

    const scanAndObserve = () => {
      document.querySelectorAll('.reveal:not(.in)').forEach((el) => observer.observe(el))
    }

    scanAndObserve()
    const checkTimer = setInterval(scanAndObserve, 500)

    return () => {
      observer.disconnect()
      clearInterval(checkTimer)
      window.removeEventListener('hashchange', sync)
    }
  })

  // Extract /scan/:id
  $: scanMatch = route.match(/^\/scan\/([^/]+)/)
  $: scanId = scanMatch ? decodeURIComponent(scanMatch[1]) : null
</script>

<!-- 4. LAYER OVERLAY GLOBAL (WAJIB, position:fixed, pointer-events:none)
     Susun urutan z-index dari bawah ke atas:
     .vignette -> radial gradient hitam di pinggir (z-index:9997).
     .flicker -> radial merah lemah rgba(255,26,60,.04), animasi opacity 4s (z-index:9998).
     .scan -> scanlines repeating-linear-gradient(180deg, transparent 3px, rgba(255,26,60,.025) 4px), mix-blend-mode:overlay (z-index:9999).
     .frame-b -> border tipis 1px solid rgba(255,26,60,.25) inset:14px dengan 4 corner brackets (2px solid merah, 24x24px) di tiap sudut -->
<div class="vignette" aria-hidden="true"></div>
<div class="flicker" aria-hidden="true"></div>
<div class="scan" aria-hidden="true"></div>
<div class="frame-b" aria-hidden="true">
  <span class="corner-bracket tl"></span>
  <span class="corner-bracket tr"></span>
  <span class="corner-bracket bl"></span>
  <span class="corner-bracket br"></span>
</div>

<Header />

<main class="main-content">
  {#if scanId}
    <ScanDetail scanId={scanId} />
  {:else if route.startsWith('/websites')}
    <Websites />
  {:else if route.startsWith('/scans')}
    <Scans />
  {:else if route.startsWith('/tools')}
    <Tools />
  {:else if route.startsWith('/rules')}
    <Rules />
  {:else}
    <Dashboard />
  {/if}
</main>

<!-- 12. FOOTER
     Grid 2fr 1fr 1fr 1fr 1fr, max-width 1280px.
     Kolom 1: brand mark + tagline mono pendek.
     Kolom 2-5: judul H5 Michroma 11px merah + list link mono dengan prefix › .
     Baris bawah: copyright uppercase 10px + disclaimer teknikal (RESPONSIBLE DISCLOSURE · PRIVACY · BUG BOUNTY). -->
<footer class="site-footer">
  <div class="footer-wrap">
    <div class="footer-grid">
      <div class="footer-col-1">
        <div class="footer-brand">NOX<span class="slash">//</span>SEC</div>
        <p class="footer-tagline">
          // No compliance theatre. Just receipts. Autonomous attack surface discovery, deterministic AST remediation.
        </p>
      </div>

      <div class="footer-col">
        <h5>OPERATIONS</h5>
        <ul>
          <li><a href="#/">› live telemetry</a></li>
          <li><a href="#/websites">› attack perimeters</a></li>
          <li><a href="#/scans">› scan library</a></li>
          <li><a href="#/tools">› toolbench</a></li>
        </ul>
      </div>

      <div class="footer-col">
        <h5>TACTICAL VECTORS</h5>
        <ul>
          <li><a href="#/rules">› idor probes</a></li>
          <li><a href="#/rules">› xss tainted dom</a></li>
          <li><a href="#/rules">› cve dictionary</a></li>
          <li><a href="#/rules">› control-id bypass</a></li>
        </ul>
      </div>

      <div class="footer-col">
        <h5>TELEMETRY FEED</h5>
        <ul>
          <li><a href="#/scans">› honeypot traces</a></li>
          <li><a href="#/scans">› agent trajectories</a></li>
          <li><a href="#/scans">› active probes</a></li>
          <li><a href="#/scans">› diff patches</a></li>
        </ul>
      </div>

      <div class="footer-col">
        <h5>CLEARANCE PROTOCOL</h5>
        <ul>
          <li><a href="#/">› protocol v4.2</a></li>
          <li><a href="#/">› terminal access</a></li>
          <li><a href="#/">› intake status</a></li>
          <li><a href="#/">› air-gapped node</a></li>
        </ul>
      </div>
    </div>

    <div class="footer-bottom">
      <span class="copyright">COPYRIGHT &copy; {currentYear} NOX//SEC CYENSE. ALL RIGHTS RESERVED.</span>
      <span class="disclaimer">RESPONSIBLE DISCLOSURE &middot; PRIVACY &middot; BUG BOUNTY</span>
    </div>
  </div>
</footer>

<style>
  .main-content {
    min-height: calc(100vh - 48px - 32px);
    position: relative;
    z-index: 10;
  }

  /* 4. Overlays */
  .vignette {
    position: fixed;
    inset: 0;
    pointer-events: none;
    z-index: 9997;
    background: radial-gradient(circle at center, transparent 65%, rgba(5, 2, 4, 0.88) 100%);
  }

  .flicker {
    position: fixed;
    inset: 0;
    pointer-events: none;
    z-index: 9998;
    background: radial-gradient(circle at center, rgba(255, 26, 60, 0.04) 0%, transparent 80%);
    animation: flickerPulse 4s ease-in-out infinite;
  }

  @keyframes flickerPulse {
    0%, 100% { opacity: 0.35; }
    50% { opacity: 0.9; }
  }

  .scan {
    position: fixed;
    inset: 0;
    pointer-events: none;
    z-index: 9999;
    background: repeating-linear-gradient(180deg, transparent 3px, rgba(255, 26, 60, 0.025) 4px);
    mix-blend-mode: overlay;
  }

  .frame-b {
    position: fixed;
    inset: 14px;
    pointer-events: none;
    z-index: 10000;
    border: 1px solid rgba(255, 26, 60, 0.25);
  }

  .corner-bracket {
    position: absolute;
    width: 24px;
    height: 24px;
  }

  .corner-bracket.tl {
    top: -2px;
    left: -2px;
    border-top: 2px solid var(--red, #ff1a3c);
    border-left: 2px solid var(--red, #ff1a3c);
  }

  .corner-bracket.tr {
    top: -2px;
    right: -2px;
    border-top: 2px solid var(--red, #ff1a3c);
    border-right: 2px solid var(--red, #ff1a3c);
  }

  .corner-bracket.bl {
    bottom: -2px;
    left: -2px;
    border-bottom: 2px solid var(--red, #ff1a3c);
    border-left: 2px solid var(--red, #ff1a3c);
  }

  .corner-bracket.br {
    bottom: -2px;
    right: -2px;
    border-bottom: 2px solid var(--red, #ff1a3c);
    border-right: 2px solid var(--red, #ff1a3c);
  }

  /* 12. Footer */
  .site-footer {
    border-top: 1px solid rgba(255, 26, 60, 0.2);
    background: var(--panel, #0e0508);
    padding: 60px 0 32px;
    position: relative;
    z-index: 10;
  }

  .footer-wrap {
    max-width: 1280px;
    margin: 0 auto;
    padding: 0 24px;
    box-sizing: border-box;
  }

  .footer-grid {
    display: grid;
    grid-template-columns: 2fr 1fr 1fr 1fr 1fr;
    gap: 32px;
    margin-bottom: 48px;
  }

  .footer-brand {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 18px;
    font-weight: 700;
    letter-spacing: 0.04em;
    color: var(--fg, #f5e8e8);
    margin-bottom: 12px;
  }

  .footer-brand .slash {
    color: var(--red, #ff1a3c);
  }

  .footer-tagline {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 12px;
    line-height: 1.6;
    color: var(--mute, #8a5a64);
    margin: 0;
    max-width: 340px;
  }

  .footer-col h5 {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 11px;
    letter-spacing: 0.08em;
    color: var(--red, #ff1a3c);
    margin: 0 0 16px 0;
    text-transform: uppercase;
  }

  .footer-col ul {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .footer-col a {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 12px;
    color: var(--mute, #8a5a64);
    text-decoration: none;
    transition: color 0.2s ease;
  }

  .footer-col a:hover {
    color: var(--red, #ff1a3c);
    text-decoration: none;
  }

  .footer-bottom {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-top: 1px solid rgba(255, 26, 60, 0.15);
    padding-top: 24px;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--mute, #8a5a64);
    flex-wrap: wrap;
    gap: 12px;
  }

  @media (max-width: 880px) {
    .frame-b {
      display: none !important;
    }

    .footer-grid {
      grid-template-columns: 1fr 1fr;
      gap: 32px 20px;
    }

    .footer-col-1 {
      grid-column: 1 / -1;
    }

    .footer-bottom {
      flex-direction: column;
      align-items: flex-start;
      gap: 8px;
    }
  }
</style>
