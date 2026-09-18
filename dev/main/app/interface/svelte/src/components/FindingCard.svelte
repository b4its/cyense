<script>
  export let f
  let copied = false

  $: sev = String(f.severity || 'info').toLowerCase()
  $: cwe = f.cwe || f.cwe_id || ''
  $: cvss = f.cvss || f.cvss_score || ''
  $: locationStr = f.location || f.url || f.target || f.endpoint || ''

  function copyLocation() {
    if (!locationStr) return
    navigator.clipboard.writeText(locationStr)
    copied = true
    setTimeout(() => { copied = false }, 1800)
  }
</script>

<div class="finding-card sev-{sev}">
  <!-- Top meta header -->
  <div class="finding-meta-row">
    <div class="badges-left">
      <span class="sev-pill {sev}">{sev.toUpperCase()}</span>
      {#if f.rule || f.rule_id}
        <span class="rule-tag mono">{f.rule || f.rule_id}</span>
      {/if}
      {#if cwe}
        <span class="cwe-tag mono">{cwe}</span>
      {/if}
    </div>

    <div class="badges-right">
      {#if cvss}
        <span class="cvss-pill" title="CVSS Base Score">CVSS {Number(cvss).toFixed(1)}</span>
      {/if}
      {#if f.confidence != null}
        <span class="conf-pill">CONF {(Number(f.confidence) * 100).toFixed(0)}%</span>
      {/if}
    </div>
  </div>

  <!-- Title -->
  <h3 class="finding-title">{f.title || f.rule || 'Vulnerability Finding'}</h3>

  <!-- Description -->
  {#if f.description && f.description !== f.title}
    <p class="finding-desc">{f.description}</p>
  {/if}

  <!-- Location / Attack vector -->
  {#if locationStr}
    <div class="location-box">
      <div class="loc-label">// AFFECTED ENDPOINT / LOC:</div>
      <div class="loc-row">
        <code class="loc-code">{locationStr}</code>
        <button class="copy-loc-btn" onclick={copyLocation} title="Copy endpoint to clipboard">
          {copied ? 'COPIED!' : 'COPY'}
        </button>
      </div>
    </div>
  {/if}

  <!-- Technical evidence receipt -->
  {#if f.evidence && (typeof f.evidence === 'string' ? f.evidence.trim() : Object.keys(f.evidence).length > 0)}
    <div class="evidence-box">
      <div class="ev-label">// TECHNICAL RECEIPT &amp; EVIDENCE:</div>
      <pre class="ev-content">{typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence, null, 2)}</pre>
    </div>
  {/if}

  <!-- Remediation fix -->
  {#if f.remediation}
    <div class="remediation-box">
      <div class="rem-label">// AST REMEDIATION GUIDANCE:</div>
      <p class="rem-content">{f.remediation}</p>
    </div>
  {/if}
</div>

<style>
  .finding-card {
    background: var(--panel, #0e0508);
    border: 1px solid var(--line, rgba(255, 26, 60, 0.25));
    border-left: 4px solid var(--mute, #8a5a64);
    padding: 16px 20px;
    display: flex;
    flex-direction: column;
    gap: 10px;
    transition: all 0.2s ease;
  }

  .finding-card:hover {
    border-color: rgba(255, 26, 60, 0.4);
    background: var(--card-bg-hover, #16080e);
    box-shadow: 0 0 16px rgba(0, 0, 0, 0.4);
  }

  .finding-card.sev-critical {
    border-left-color: var(--red, #ff1a3c);
  }

  .finding-card.sev-high {
    border-left-color: #ff8a3a;
  }

  .finding-card.sev-medium {
    border-left-color: var(--acid, #42ff8a);
  }

  .finding-card.sev-low {
    border-left-color: #42a8ff;
  }

  .finding-card.sev-info {
    border-left-color: var(--mute, #8a5a64);
  }

  .finding-meta-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
  }

  .badges-left,
  .badges-right {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .sev-pill {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.06em;
    padding: 3px 8px;
    text-transform: uppercase;
  }

  .sev-pill.critical {
    background: var(--red, #ff1a3c);
    color: #ffffff;
  }

  .sev-pill.high {
    background: #ff8a3a;
    color: #050204;
  }

  .sev-pill.medium {
    background: var(--acid, #42ff8a);
    color: #050204;
  }

  .sev-pill.low {
    background: #42a8ff;
    color: #050204;
  }

  .sev-pill.info {
    background: rgba(138, 90, 100, 0.25);
    color: var(--fg, #f5e8e8);
    border: 1px solid var(--line);
  }

  .rule-tag {
    font-size: 11px;
    color: var(--red, #ff1a3c);
    letter-spacing: 0.04em;
    font-weight: 700;
  }

  .cwe-tag {
    font-size: 10px;
    background: rgba(255, 26, 60, 0.08);
    border: 1px solid var(--line, rgba(255, 26, 60, 0.2));
    padding: 2px 6px;
    color: var(--fg, #f5e8e8);
  }

  .cvss-pill {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 10px;
    color: var(--acid, #42ff8a);
    font-weight: 700;
  }

  .conf-pill {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    color: var(--mute, #8a5a64);
  }

  .finding-title {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 15px;
    letter-spacing: -0.01em;
    color: var(--fg, #f5e8e8);
    margin: 0;
    line-height: 1.35;
  }

  .finding-desc {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 13px;
    line-height: 1.6;
    color: var(--mute, #8a5a64);
    margin: 0;
  }

  .location-box {
    background: #050204;
    border: 1px solid var(--line, rgba(255, 26, 60, 0.15));
    padding: 8px 12px;
    margin-top: 2px;
  }

  .loc-label {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    letter-spacing: 0.1em;
    color: var(--red, #ff1a3c);
    margin-bottom: 4px;
  }

  .loc-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
  }

  .loc-code {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 12px;
    color: var(--fg, #f5e8e8);
    word-break: break-all;
  }

  .copy-loc-btn {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 9px;
    font-weight: 700;
    padding: 3px 8px;
    background: transparent;
    border: 1px solid var(--mute, #8a5a64);
    color: var(--mute, #8a5a64);
    cursor: pointer;
    transition: all 0.2s ease;
    white-space: nowrap;
    border-radius: 0;
  }

  .copy-loc-btn:hover {
    border-color: var(--red, #ff1a3c);
    color: var(--red, #ff1a3c);
  }

  .remediation-box {
    background: rgba(66, 255, 138, 0.04);
    border: 1px solid rgba(66, 255, 138, 0.2);
    padding: 10px 14px;
    margin-top: 4px;
  }

  .rem-label {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    letter-spacing: 0.1em;
    color: var(--acid, #42ff8a);
    margin-bottom: 4px;
    font-weight: 700;
  }

  .rem-content {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 12px;
    line-height: 1.6;
    color: var(--fg, #f5e8e8);
    margin: 0;
  }

  .evidence-box {
    background: #060205;
    border: 1px solid var(--line, rgba(255, 26, 60, 0.2));
    padding: 10px 12px;
    margin-top: 4px;
    overflow-x: auto;
  }

  .ev-label {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    color: var(--acid, #42ff8a);
    letter-spacing: 0.08em;
    margin-bottom: 6px;
    font-weight: 700;
  }

  .ev-content {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    color: var(--fg, #f5e8e8);
    margin: 0;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 240px;
    overflow-y: auto;
  }
</style>
