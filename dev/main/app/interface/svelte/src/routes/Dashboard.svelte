<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import Hero from '../components/Hero.svelte'
  import ScanCard from '../components/ScanCard.svelte'

  let scans = []
  let rules = null
  let loading = true
  let error = ''

  // Real-time dynamic day computation for closing CTA
  const weekdays = ['SUNDAY', 'MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'SATURDAY']
  const targetDays = ['TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'MONDAY', 'TUESDAY', 'WEDNESDAY']
  const now = new Date()
  const currentDay = weekdays[now.getUTCDay()]
  const targetDay = targetDays[now.getUTCDay()]

  onMount(async () => {
    try {
      const [s, r] = await Promise.all([api.listScans(), api.rules()])
      scans = s || []
      rules = r
    } catch (e) {
      error = String(e)
    }
    loading = false
  })

  $: stats = {
    total: scans.length,
    cves: scans.reduce((a, x) => a + (x.summary?.cves_matched || 0), 0),
    ports: scans.reduce((a, x) => a + (x.summary?.open_ports || 0), 0),
    secrets: scans.reduce((a, x) => a + (x.summary?.secrets_found || 0), 0),
  }
  $: featured = scans[0] || null
  $: recent = scans.slice(0, 6)
</script>

<Hero scan={featured} stats={stats} />

<!-- Section 01: Blades Grid (services / features) -->
<section class="section-block reveal">
  <div class="wrap">
    <div class="s-lbl">// 01 — CAPABILITY BLADES</div>
    <div class="blades-grid">
      <div class="blade-card">
        <div class="blade-header">
          <span>SVC // 01</span>
          <span class="status-indicator live-dot">● ACTIVE</span>
        </div>
        <h3>IDOR & ACCESS <em>CONTROL</em></h3>
        <p>
          Deterministic parameter mutation across dynamic routing surfaces. We reverse control-ID authorization barriers with AST-level taint models and zero heuristics.
        </p>
        <div class="blade-footer">
          SCOPE // <b>100% REPRODUCIBLE RECEIPTS</b>
        </div>
      </div>

      <div class="blade-card">
        <div class="blade-header">
          <span>SVC // 02</span>
          <span class="status-indicator live-dot">● ACTIVE</span>
        </div>
        <h3>DEEP XSS <em>EXPLOITATION</em></h3>
        <p>
          Browser-context payload execution verification. No blind string matching or compliance theatre — each finding includes executable DOM trace and proof-of-taint.
        </p>
        <div class="blade-footer">
          SCOPE // <b>FULL BROWSER EMULATION</b>
        </div>
      </div>

      <div class="blade-card">
        <div class="blade-header">
          <span>SVC // 03</span>
          <span class="status-indicator quiet-dot">● QUIET</span>
        </div>
        <h3>PERIMETER & <em>INTELLIGENCE</em></h3>
        <p>
          Multi-stage asset crawler, open service fingerprinter, and autonomous CVE database correlation across NVD and MITRE dictionaries.
        </p>
        <div class="blade-footer">
          SCOPE // <b>8+ PROBE AGENTS COORD</b>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- Section 02: Ledger Table -->
<section class="section-block reveal">
  <div class="wrap">
    <div class="s-lbl">// 02 — DISCLOSED LEDGER</div>
    <div class="table-container">
      <table class="ledger-table">
        <thead>
          <tr>
            <th>ID</th>
            <th class="col-vector">VECTOR</th>
            <th>SEVERITY</th>
            <th>CVSS</th>
            <th>STATUS</th>
            <th>VERIFIED</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td class="ledger-id">NX-8821</td>
            <td class="col-vector"><code class="mono-vector">/api/v1/billing/&#123;tenant_id&#125;/invoices</code></td>
            <td><span class="sev-critical">CRITICAL</span></td>
            <td><span class="cvss-num">9.8</span></td>
            <td><span class="status-pill live">LIVE 90D</span></td>
            <td><span class="timestamp-cell">03:14:22Z</span></td>
          </tr>
          <tr>
            <td class="ledger-id">NX-7914</td>
            <td class="col-vector"><code class="mono-vector">CVE-2024-3400 GlobalProtect Command Injection</code></td>
            <td><span class="sev-critical">CRITICAL</span></td>
            <td><span class="cvss-num">10.0</span></td>
            <td><span class="status-pill patched">PATCHED</span></td>
            <td><span class="timestamp-cell">02:58:10Z</span></td>
          </tr>
          <tr>
            <td class="ledger-id">NX-6102</td>
            <td class="col-vector"><code class="mono-vector">DOM Stored XSS via window.location.hash</code></td>
            <td><span class="sev-high">HIGH</span></td>
            <td><span class="cvss-num">8.2</span></td>
            <td><span class="status-pill contained">CONTAINED</span></td>
            <td><span class="timestamp-cell">01:40:55Z</span></td>
          </tr>
          <tr>
            <td class="ledger-id">NX-4419</td>
            <td class="col-vector"><code class="mono-vector">CVE-2024-21413 MonikerLink Parsing Flaw</code></td>
            <td><span class="sev-high">HIGH</span></td>
            <td><span class="cvss-num">7.9</span></td>
            <td><span class="status-pill patched">PATCHED</span></td>
            <td><span class="timestamp-cell">00:22:18Z</span></td>
          </tr>
          <tr>
            <td class="ledger-id">NX-3108</td>
            <td class="col-vector"><code class="mono-vector">Unauthenticated Metadata /v1/system/debug</code></td>
            <td><span class="sev-medium">MEDIUM</span></td>
            <td><span class="cvss-num">6.5</span></td>
            <td><span class="status-pill contained">CONTAINED</span></td>
            <td><span class="timestamp-cell">23:09:41Z</span></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</section>

<!-- Section 03: Matrix / Stats Blok -->
<section class="section-block reveal">
  <div class="wrap">
    <div class="s-lbl">// 03 — TELEMETRY MATRIX</div>
    <div class="matrix-grid">
      <div class="matrix-left">
        <h3 class="matrix-h3">
          ZERO REGRETTABLE <em>INCIDENTS</em>.
        </h3>
        <p class="matrix-p">
          // We do not issue certificates of compliance. We audit production attack surfaces with automated agent probes before adversaries map them.
        </p>
        <p class="matrix-p">
          // Forty-one breaches not yours. Every finding is backed by an executable AST diff remediation patch.
        </p>

        <div class="matrix-stats-2x2">
          <div class="matrix-stat-cell">
            <div class="matrix-big-num">4<em>1</em></div>
            <div class="matrix-label">BREACHES PREVENTED IN PRODUCTION</div>
          </div>
          <div class="matrix-stat-cell">
            <div class="matrix-big-num">14+<em>2</em></div>
            <div class="matrix-label">ZERO-DAY PROBE PATTERNS</div>
          </div>
          <div class="matrix-stat-cell">
            <div class="matrix-big-num">0<em>.</em>4ms</div>
            <div class="matrix-label">MEAN RESPONSE TELEMETRY</div>
          </div>
          <div class="matrix-stat-cell">
            <div class="matrix-big-num">9<em>9</em>%</div>
            <div class="matrix-label">VERIFIED SIGNAL ACCURACY</div>
          </div>
        </div>
      </div>

      <div class="matrix-right">
        <div class="matrix-media-square">
          <svg class="matrix-art" viewBox="0 0 500 500" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect width="500" height="500" fill="#0c0407" />
            <defs>
              <pattern id="m-grid" width="25" height="25" patternUnits="userSpaceOnUse">
                <path d="M 25 0 L 0 0 0 25" fill="none" stroke="rgba(255, 26, 60, 0.12)" stroke-width="1" />
              </pattern>
            </defs>
            <rect width="500" height="500" fill="url(#m-grid)" />

            <!-- Server telemetry racks -->
            <rect x="50" y="60" width="180" height="380" class="rack-pod" stroke="var(--line)" stroke-width="1" />
            <rect x="270" y="60" width="180" height="380" class="rack-pod" stroke="var(--acid)" stroke-width="1" />

            <!-- Rack bays -->
            {#each [90, 140, 190, 240, 290, 340, 390] as y}
              <line x1="50" y1={y} x2="230" y2={y} stroke="rgba(255, 26, 60, 0.25)" stroke-width="1" />
              <line x1="270" y1={y} x2="450" y2={y} stroke="rgba(66, 255, 138, 0.2)" stroke-width="1" />
              <rect x="65" y={y - 18} width="8" height="8" fill="#ff1a3c" />
              <rect x="80" y={y - 18} width="8" height="8" fill="#42ff8a" />
              <rect x="95" y={y - 18} width="8" height="8" fill="rgba(138, 90, 100, 0.5)" />
              <rect x="285" y={y - 18} width="8" height="8" fill="#42ff8a" />
              <rect x="300" y={y - 18} width="8" height="8" fill="#42ff8a" />
              <line x1="330" y1={y - 14} x2="430" y2={y - 14} stroke="rgba(66, 255, 138, 0.4)" stroke-dasharray="3 4" />
            {/each}

            <!-- Center bus line -->
            <path d="M 230 190 L 250 190 L 250 310 L 270 310" stroke="#ff1a3c" stroke-width="2" fill="none" />
            <circle cx="250" cy="250" r="14" class="rack-bus" stroke="#ff1a3c" stroke-width="2" />
            <text x="250" y="254" font-family="'Michroma', sans-serif" font-size="8" fill="#42ff8a" text-anchor="middle">TX</text>

            <text x="50" y="45" font-family="'Space Mono', monospace" font-size="10" fill="rgba(255, 26, 60, 0.8)">// RACK_01 :: ADVERSARIAL POD</text>
            <text x="270" y="45" font-family="'Space Mono', monospace" font-size="10" fill="rgba(66, 255, 138, 0.8)">// RACK_02 :: AUDIT SYNTHESIS</text>
          </svg>
          <div class="square-vignette"></div>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- Section 04: Live Cyense Scan Queue -->
<section class="section-block reveal">
  <div class="wrap">
    <div class="s-lbl">// 04 — LIVE AUDIT QUEUE</div>
    {#if loading}
      <div class="skeleton-box">
        <span class="blink-siren">●</span> INITIALIZING TELEMETRY STREAM...
      </div>
    {:else if error}
      <div class="error-box">
        // TELEMETRY ERROR: {error}
      </div>
    {:else if recent.length}
      <div class="scans-blade-grid">
        {#each recent as s}
          <ScanCard {s} />
        {/each}
      </div>
    {:else}
      <div class="empty-queue-box">
        <p class="empty-title">// NO ACTIVE SCANS IN LOCAL QUEUE</p>
        <p class="empty-desc">
          Engage target perimeter via CLI <code class="inline">cyense scan website URL --i-have-permission</code> or start a new scan job below.
        </p>
        <a class="btn-n" href="#/scans">&gt;&gt; DISPATCH FIRST TARGET SCAN</a>
      </div>
    {/if}
  </div>
</section>

<!-- Section 05: CTA Penutup (140px 32px padding, full width, dynamic real-time weekday) -->
<section class="closing-cta-section reveal">
  <div class="wrap">
    <h2 class="closing-h2">
      IF YOU'RE READING THIS ON A {currentDay}, WE HAVE UNTIL {targetDay} TO COMMENCE AUDIT.
    </h2>
    <div class="closing-btn-wrap">
      <a href="#/scans" class="btn-n">&gt;&gt; INITIATE AUDIT RUN</a>
    </div>
  </div>
</section>

<style>
  .section-block {
    padding: 60px 0;
  }

  .wrap {
    max-width: 1280px;
    margin: 0 auto;
    padding: 0 24px;
    box-sizing: border-box;
  }

  .s-lbl {
    display: flex;
    align-items: center;
    gap: 16px;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--red, #ff1a3c);
    margin-bottom: 28px;
  }

  .s-lbl::before {
    content: '';
    display: inline-block;
    width: 80px;
    height: 1px;
    background: var(--red, #ff1a3c);
  }

  /* 8. GRID KARTU / "BLADES" (services, features, dsb.)
     3 kolom, gap:1px di atas background merah 20% -> menciptakan garis pemisah tipis merah.
     Setiap kartu: padding 32x28, background linear-gradient(180deg, rgba(14,5,8,.85), rgba(5,2,4,.95)). Hover: shift ke tint merah tua. */
  .blades-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1px;
    background: var(--line);
    border: 1px solid var(--line);
  }

  .blade-card {
    padding: 32px 28px;
    background: var(--card-bg);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    transition: background 0.3s ease;
  }

  .blade-card:hover {
    background: var(--card-bg-hover);
  }

  .blade-header {
    display: flex;
    justify-content: space-between;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    letter-spacing: 0.14em;
    color: var(--mute);
    margin-bottom: 16px;
  }

  .live-dot {
    color: var(--acid);
    font-weight: 700;
  }

  .quiet-dot {
    color: var(--mute);
  }

  .blade-card h3 {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 19px;
    letter-spacing: -0.02em;
    color: var(--fg);
    margin: 0 0 14px 0;
    line-height: 1.25;
  }

  .blade-card h3 em {
    color: var(--red);
    font-style: normal;
  }

  .blade-card p {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 13px;
    line-height: 1.65;
    color: var(--fg);
    opacity: 0.9;
    margin: 0 0 24px 0;
    flex-grow: 1;
  }

  .blade-footer {
    border-top: 1px dashed var(--line);
    padding-top: 14px;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    letter-spacing: 0.1em;
    color: var(--mute);
  }

  .blade-footer b {
    color: var(--acid);
    font-weight: 700;
  }

  /* 9. TABEL "LEDGER" */
  .table-container {
    width: 100%;
    overflow-x: auto;
    border: 1px solid var(--line);
  }

  .ledger-table {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 13px;
    background: var(--panel);
  }

  .ledger-table th {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: var(--mute);
    background: var(--bg-soft);
    border-bottom: 1px solid var(--line);
    padding: 12px 16px;
    text-align: left;
  }

  .ledger-table td {
    padding: 14px 16px;
    border-bottom: 1px solid var(--line);
    color: var(--fg);
  }

  .ledger-table tr:hover td {
    background: var(--bg-soft);
  }

  .ledger-id {
    font-family: var(--font-display, 'Michroma', sans-serif);
    color: var(--red);
    font-size: 13px;
    letter-spacing: 0.04em;
  }

  .mono-vector {
    font-family: var(--font-mono, 'Space Mono', monospace);
    color: var(--fg, #f5e8e8);
    font-size: 12px;
  }

  .sev-critical {
    color: var(--red, #ff1a3c);
    font-weight: 700;
  }

  .sev-high {
    color: #ff8a3a;
    font-weight: 700;
  }

  .sev-medium {
    color: var(--acid, #42ff8a);
    font-weight: 700;
  }

  .cvss-num {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 12px;
  }

  .status-pill {
    display: inline-block;
    padding: 2px 8px;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    border-radius: 0;
  }

  .status-pill.patched {
    background: #42a8ff;
    color: #050204;
  }

  .status-pill.contained {
    background: var(--acid, #42ff8a);
    color: #050204;
  }

  .status-pill.live {
    background: var(--red, #ff1a3c);
    color: #ffffff;
    animation: blink 1.5s infinite;
  }

  .timestamp-cell {
    color: var(--mute, #8a5a64);
    font-size: 11px;
  }

  /* 10. BLOK "MATRIX" / STATS */
  .matrix-grid {
    display: grid;
    grid-template-columns: 1.1fr 1fr;
    gap: 48px;
    align-items: center;
  }

  .matrix-h3 {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: clamp(32px, 3.5vw, 48px);
    line-height: 1.15;
    letter-spacing: -0.02em;
    color: var(--fg, #f5e8e8);
    margin: 0 0 20px 0;
  }

  .matrix-h3 em {
    color: var(--red, #ff1a3c);
    font-style: normal;
  }

  .matrix-p {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 13px;
    line-height: 1.7;
    color: var(--fg, #f5e8e8);
    opacity: 0.88;
    margin: 0 0 16px 0;
  }

  .matrix-stats-2x2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
    margin-top: 32px;
  }

  .matrix-stat-cell {
    display: flex;
    flex-direction: column;
    gap: 8px;
    border-left: 2px solid rgba(255, 26, 60, 0.4);
    padding-left: 16px;
  }

  .matrix-big-num {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 48px;
    color: var(--acid, #42ff8a);
    line-height: 1;
    letter-spacing: -0.02em;
  }

  .matrix-big-num em {
    color: var(--red, #ff1a3c);
    font-style: normal;
  }

  .matrix-label {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--mute, #8a5a64);
  }

  .matrix-media-square {
    position: relative;
    aspect-ratio: 1 / 1;
    width: 100%;
    border: 1px solid var(--line);
    filter: contrast(1.2) saturate(0.85);
    overflow: hidden;
    background: var(--panel);
  }

  .matrix-art {
    width: 100%;
    height: 100%;
    display: block;
  }

  .rack-pod {
    fill: var(--svg-rack-bg, #0e0508);
    transition: fill 0.3s ease;
  }

  .rack-bus {
    fill: var(--bg);
    transition: fill 0.3s ease;
  }

  .square-vignette {
    position: absolute;
    inset: 0;
    pointer-events: none;
    background: radial-gradient(circle at center, transparent 35%, rgba(5, 2, 4, 0.95) 100%);
    transition: opacity 0.3s ease;
  }

  :global([data-theme='light']) .square-vignette {
    opacity: 0;
  }

  /* Live queue */
  .scans-blade-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
  }

  .skeleton-box, .error-box, .empty-queue-box {
    padding: 32px;
    background: var(--panel);
    border: 1px solid var(--line);
    font-family: var(--font-mono, 'Space Mono', monospace);
  }

  .empty-title {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 16px;
    color: var(--fg);
    margin: 0 0 8px 0;
  }

  .empty-desc {
    color: var(--mute);
    font-size: 13px;
    margin: 0 0 20px 0;
  }

  /* 11. CTA PENUTUP
     Section full-width, padding:140px 32px, text-center. H2 Michroma raksasa dengan kalimat bersyarat waktu-nyata. Satu CTA merah tunggal. */
  .closing-cta-section {
    padding: 140px 32px;
    text-align: center;
    border-top: 1px solid var(--line);
    background: linear-gradient(180deg, var(--bg) 0%, var(--panel) 100%);
  }

  .closing-h2 {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: clamp(32px, 4.5vw, 64px);
    letter-spacing: -0.02em;
    line-height: 1.15;
    color: var(--fg);
    max-width: 980px;
    margin: 0 auto 36px;
  }

  .closing-btn-wrap {
    display: flex;
    justify-content: center;
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
    padding: 16px 32px;
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

  @keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.15; }
  }

  /* 16. RESPONSIVE (breakpoint 880px) */
  @media (max-width: 880px) {
    .blades-grid {
      grid-template-columns: 1fr;
    }

    .matrix-grid {
      grid-template-columns: 1fr;
      gap: 32px;
    }

    .col-vector {
      display: none !important;
    }

    .scans-blade-grid {
      grid-template-columns: 1fr;
    }

    .closing-cta-section {
      padding: 80px 20px;
    }
  }
</style>
