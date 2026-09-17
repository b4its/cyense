<script>
  import { fmtTime } from '../lib/api.js'
  export let scan = null
  export let stats = {}
</script>

<section class="hero-wrap reveal">
  <div class="hero-grid">
    <!-- Kiri: tag pill merah kecil dengan ● blinking -> H1 raksasa Michroma -> paragraf mono prefix // -> 2 CTA -->
    <div class="hero-col-left">
      <div class="tag-pill">
        <span class="pill-blink">●</span>
        <span class="pill-text">SYS.STATE // ACTIVE HARVEST</span>
      </div>

      <h1 class="hero-title">
        WE <em>ATTACK</em> FIRST.<br />
        <span class="stk">ASSUMPTIONS</span> SO THEY DON'T.
      </h1>

      <p class="hero-mono-p">
        // Eight years quiet. Forty-one breaches not yours. Autonomous IDOR, XSS, and zero-day vector suppression across all production surfaces. No compliance theatre. Just receipts.
      </p>

      <div class="hero-ctas">
        <a href="#/scans" class="btn-n">&gt;&gt; INITIATE AUDIT</a>
        <a href="#/rules" class="btn-ng">VECTOR RULES &rarr;</a>
      </div>

      <div class="hero-quick-ledger">
        <div class="ledger-stat">
          <span class="l-tag">// COMPLETED SCANS</span>
          <span class="l-num"><b>{stats.total ?? 0}</b></span>
        </div>
        <div class="ledger-stat">
          <span class="l-tag">// CVE MATCHED</span>
          <span class="l-num"><b>{stats.cves ?? 0}</b></span>
        </div>
        <div class="ledger-stat">
          <span class="l-tag">// OPEN PORTS</span>
          <span class="l-num"><b>{stats.ports ?? 0}</b></span>
        </div>
        {#if scan}
          <div class="ledger-stat">
            <span class="l-tag">// LAST ENGAGEMENT</span>
            <span class="l-num" style="font-size: 11px;">{fmtTime(scan.created_at)}</span>
          </div>
        {/if}
      </div>
    </div>

    <!-- Kanan: image container aspect-ratio:16/10, border merah 40%, filter:contrast(1.15) saturate(.9) -->
    <div class="hero-col-right">
      <div class="hero-display-box">
        <svg
          class="tactical-canvas"
          viewBox="0 0 800 500"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          preserveAspectRatio="xMidYMid slice"
        >
          <!-- Dark background -->
          <rect width="800" height="500" fill="#090306" />

          <!-- Monospace telemetry watermarks -->
          <defs>
            <pattern id="h-grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255, 26, 60, 0.08)" stroke-width="1" />
            </pattern>
            <radialGradient id="h-radar-glow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stop-color="rgba(255, 26, 60, 0.22)" />
              <stop offset="65%" stop-color="rgba(255, 26, 60, 0.02)" />
              <stop offset="100%" stop-color="transparent" />
            </radialGradient>
          </defs>

          <rect width="800" height="500" fill="url(#h-grid)" />
          <circle cx="400" cy="250" r="190" fill="url(#h-radar-glow)" />

          <!-- Radar geometry -->
          <circle cx="400" cy="250" r="190" stroke="rgba(255, 26, 60, 0.28)" stroke-width="1" stroke-dasharray="3 6" />
          <circle cx="400" cy="250" r="130" stroke="rgba(66, 255, 138, 0.3)" stroke-width="1" />
          <circle cx="400" cy="250" r="75" stroke="rgba(255, 26, 60, 0.45)" stroke-width="1.5" />
          <circle cx="400" cy="250" r="20" fill="rgba(255, 26, 60, 0.25)" stroke="#ff1a3c" stroke-width="1.5" />

          <!-- Axis lines -->
          <line x1="80" y1="250" x2="720" y2="250" stroke="rgba(255, 26, 60, 0.2)" stroke-width="1" />
          <line x1="400" y1="30" x2="400" y2="470" stroke="rgba(255, 26, 60, 0.2)" stroke-width="1" />

          <!-- Dynamic sweep beam -->
          <line x1="400" y1="250" x2="570" y2="120" stroke="rgba(66, 255, 138, 0.8)" stroke-width="2" />
          <polygon points="400,250 570,120 540,90" fill="rgba(66, 255, 138, 0.12)" />

          <!-- Circuit interconnects -->
          <path d="M 120 100 L 220 100 L 280 160 L 360 160" stroke="rgba(66, 255, 138, 0.5)" stroke-width="1.5" fill="none" />
          <circle cx="120" cy="100" r="3" fill="#42ff8a" />
          <path d="M 680 400 L 580 400 L 520 340 L 440 340" stroke="rgba(255, 26, 60, 0.6)" stroke-width="1.5" fill="none" />
          <circle cx="680" cy="400" r="3" fill="#ff1a3c" />

          <!-- Target Nodes -->
          <rect x="274" y="154" width="12" height="12" fill="none" stroke="#42ff8a" stroke-width="1.5" />
          <rect x="514" y="334" width="12" height="12" fill="none" stroke="#ff1a3c" stroke-width="1.5" />
          <rect x="540" y="210" width="8" height="8" fill="#42ff8a" />
          <rect x="230" y="310" width="8" height="8" fill="#ff1a3c" />

          <!-- Waveform HUD trace -->
          <path
            d="M 60 450 L 140 450 L 160 420 L 180 470 L 200 430 L 220 450 L 360 450 L 380 410 L 400 460 L 420 450 L 580 450 L 600 430 L 620 460 L 640 450 L 740 450"
            stroke="rgba(66, 255, 138, 0.6)"
            stroke-width="1.5"
            fill="none"
          />

          <!-- Monospace labels inside SVG -->
          <text x="60" y="65" font-family="'Space Mono', monospace" font-size="11" fill="rgba(138, 90, 100, 0.85)">// SPECTRAL RADAR :: AZIMUTH 342.8&deg;</text>
          <text x="60" y="85" font-family="'Space Mono', monospace" font-size="10" fill="rgba(66, 255, 138, 0.95)">CARRIER FREQ: 9.412 GHZ &middot; SYNC LOCKED</text>
        </svg>

        <!-- Tempel 3 HUD badge absolute:
             .h1 top-left -> status node
             .h2 bottom-right -> telemetry (SCAN 41% · R-T-T 0.42ms)
             .h3 di sisi kiri, rotate(-90deg) -> label clearance
             Setiap HUD: teks 10px acid green uppercase, background rgba(5,2,4,.85), border 1px acid, dengan <b> merah Michroma di bawahnya -->
        <div class="hud-badge h1">
          <span class="hud-title">STATUS NODE</span>
          <b class="hud-value">NODE // US-EAST-01 &middot; ACTIVE</b>
        </div>

        <div class="hud-badge h2">
          <span class="hud-title">TELEMETRY</span>
          <b class="hud-value">SCAN 41% &middot; R-T-T 0.42ms</b>
        </div>

        <div class="hud-badge h3">
          <span class="hud-title">CLEARANCE</span>
          <b class="hud-value">LEVEL 5 // TS-SCI &middot; RED</b>
        </div>
      </div>
    </div>
  </div>
</section>

<style>
  .hero-wrap {
    min-height: 75vh;
    padding: 80px 32px 120px;
    box-sizing: border-box;
    display: flex;
    align-items: center;
    max-width: 1400px;
    margin: 0 auto;
  }

  .hero-grid {
    display: grid;
    grid-template-columns: 1.4fr 1fr;
    gap: 48px;
    align-items: center;
    width: 100%;
  }

  .hero-col-left {
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .tag-pill {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: rgba(255, 26, 60, 0.1);
    border: 1px solid var(--red, #ff1a3c);
    padding: 4px 10px;
    width: fit-content;
  }

  .pill-blink {
    color: var(--red, #ff1a3c);
    font-size: 9px;
    animation: blink 1.5s infinite;
  }

  .pill-text {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--red, #ff1a3c);
    font-weight: 700;
  }

  .hero-title {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: clamp(48px, 7vw, 108px);
    line-height: 1.05;
    letter-spacing: -0.02em;
    color: var(--fg, #f5e8e8);
    margin: 0;
    font-weight: 700;
  }

  .hero-title em {
    color: var(--red, #ff1a3c);
    font-style: normal;
  }

  .stk {
    text-decoration: line-through;
    text-decoration-color: var(--red, #ff1a3c);
    text-decoration-thickness: 3px;
    color: var(--mute, #8a5a64);
  }

  .hero-mono-p {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 14px;
    line-height: 1.7;
    color: var(--fg, #f5e8e8);
    opacity: 0.92;
    margin: 0;
    max-width: 640px;
  }

  .hero-ctas {
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    margin-top: 8px;
  }

  .btn-n {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: var(--red, #ff1a3c);
    color: #ffffff;
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    padding: 14px 24px;
    text-decoration: none;
    border: 1px solid var(--red, #ff1a3c);
    border-radius: 0;
    cursor: pointer;
    transition: background 0.25s, color 0.25s, box-shadow 0.25s;
  }

  .btn-n:hover {
    background: transparent;
    color: var(--red, #ff1a3c);
    box-shadow: 0 0 24px rgba(255, 26, 60, 0.3);
    text-decoration: none;
  }

  .btn-ng {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: transparent;
    outline: none;
    border: 1px solid var(--mute, #8a5a64);
    color: var(--fg, #f5e8e8);
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 13px;
    letter-spacing: 0.08em;
    padding: 14px 24px;
    text-decoration: none;
    border-radius: 0;
    cursor: pointer;
    transition: border-color 0.25s, color 0.25s;
  }

  .btn-ng:hover {
    border-color: var(--red, #ff1a3c);
    color: var(--red, #ff1a3c);
    text-decoration: none;
  }

  .hero-quick-ledger {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    padding-top: 16px;
    border-top: 1px dashed rgba(255, 26, 60, 0.3);
    margin-top: 12px;
  }

  .ledger-stat {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .l-tag {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--mute, #8a5a64);
  }

  .l-num {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 14px;
    color: var(--fg, #f5e8e8);
  }

  .l-num b {
    color: var(--acid, #42ff8a);
    font-weight: 700;
  }

  .hero-col-right {
    position: relative;
    width: 100%;
  }

  .hero-display-box {
    position: relative;
    aspect-ratio: 16 / 10;
    width: 100%;
    border: 1px solid rgba(255, 26, 60, 0.4);
    filter: contrast(1.15) saturate(0.9);
    background: var(--panel, #0e0508);
    overflow: visible;
  }

  .tactical-canvas {
    width: 100%;
    height: 100%;
    display: block;
  }

  .hud-badge {
    position: absolute;
    background: rgba(5, 2, 4, 0.85);
    border: 1px solid var(--acid, #42ff8a);
    padding: 8px 12px;
    display: flex;
    flex-direction: column;
    gap: 3px;
    z-index: 10;
    box-shadow: 0 0 12px rgba(66, 255, 138, 0.15);
  }

  .hud-title {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--acid, #42ff8a);
  }

  .hud-value {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 11px;
    letter-spacing: 0.04em;
    color: var(--red, #ff1a3c);
    font-weight: 700;
    white-space: nowrap;
  }

  .hud-badge.h1 {
    top: 16px;
    left: 16px;
  }

  .hud-badge.h2 {
    bottom: 16px;
    right: 16px;
  }

  .hud-badge.h3 {
    top: 50%;
    left: -50px;
    transform: translateY(-50%) rotate(-90deg);
    transform-origin: center center;
  }

  @keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.15; }
  }

  @media (max-width: 880px) {
    .hero-wrap {
      padding: 40px 16px 60px;
      min-height: auto;
    }

    .hero-grid {
      grid-template-columns: 1fr;
      gap: 32px;
    }

    .hero-title {
      font-size: 42px !important;
      line-height: 1.1;
    }

    .hud-badge.h3 {
      left: 16px;
      top: 50%;
      transform: none;
    }
  }
</style>
