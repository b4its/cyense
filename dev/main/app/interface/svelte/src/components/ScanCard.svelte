<script>
  import { fmtTime } from '../lib/api.js'
  export let scan
  $: pct = Math.min(scan.progress ?? 0, 100)
  $: status = scan.status ?? 'unknown'
  $: isRunning = status !== 'completed' && status !== 'failed'
</script>

<a class="tactical-card" href="#/scan/{scan.scan_id}">
  <div class="card-head">
    <div class="mode-badge-wrap">
      <span class="mode-badge {scan.mode === 'pentest' ? 'pentest' : ''}">{scan.mode}</span>
      {#if scan.workflow}
        <span class="wf-badge">{scan.workflow}</span>
      {/if}
    </div>
    <div class="status-indicator {status}">
      {#if isRunning}
        <span class="beacon-dot">●</span>
      {/if}
      <span class="status-text">{status}</span>
    </div>
  </div>

  <div class="target-title" title={scan.target || scan.url || scan.domain || scan.scan_id}>
    {scan.target || scan.url || scan.domain || scan.scan_id}
  </div>

  <div class="meta-row">
    <span class="mono-id">{scan.scan_id}</span>
    <span class="time-stamp">{fmtTime(scan.created_at)}</span>
  </div>

  <!-- Progress bar -->
  <div class="progress-wrap">
    <div class="progress-track">
      <div
        class="progress-fill {status}"
        style="width:{pct}%"
      ></div>
    </div>
    <div class="progress-meta">
      <span class="stage-name">{scan.stage || (isRunning ? 'scanning' : status)}</span>
      <span class="pct-num">{pct}%</span>
    </div>
  </div>

  {#if scan.summary}
    <div class="summary-pills">
      {#if (scan.summary.critical || 0) > 0}
        <span class="pill crit">CRIT {scan.summary.critical}</span>
      {/if}
      {#if (scan.summary.high || 0) > 0}
        <span class="pill high">HIGH {scan.summary.high}</span>
      {/if}
      {#if (scan.summary.medium || 0) > 0}
        <span class="pill med">MED {scan.summary.medium}</span>
      {/if}
      <span class="pill total">TOTAL {scan.summary.total ?? 0}</span>
    </div>
  {/if}

  {#if scan.error}
    <div class="err-sub" title={scan.error}>
      // ERR: {scan.error}
    </div>
  {/if}

  <div class="card-foot">
    <span>// AUDIT TELEMETRY</span>
    <span class="inspect-txt">INSPECT &rarr;</span>
  </div>
</a>

<style>
  .tactical-card {
    display: flex;
    flex-direction: column;
    padding: 20px;
    background: var(--panel, #0e0508);
    border: 1px solid var(--line, rgba(255, 26, 60, 0.25));
    text-decoration: none;
    color: inherit;
    transition: all 0.2s ease;
    position: relative;
  }

  .tactical-card:hover {
    border-color: var(--red, #ff1a3c);
    background: var(--card-bg-hover, #18090f);
    box-shadow: 0 0 16px rgba(255, 26, 60, 0.15);
    transform: translateY(-2px);
  }

  .card-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    margin-bottom: 12px;
  }

  .mode-badge-wrap {
    display: flex;
    gap: 6px;
    align-items: center;
  }

  .mode-badge {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    padding: 2px 6px;
    border: 1px solid var(--line, rgba(255, 26, 60, 0.25));
    color: var(--mute, #8a5a64);
  }

  .mode-badge.pentest {
    border-color: var(--red, #ff1a3c);
    background: rgba(255, 26, 60, 0.12);
    color: var(--red, #ff1a3c);
    font-weight: 700;
  }

  .wf-badge {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 9px;
    color: var(--mute, #8a5a64);
  }

  .status-indicator {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }

  .status-indicator.completed {
    color: var(--acid, #42ff8a);
  }

  .status-indicator.failed {
    color: var(--red, #ff1a3c);
  }

  .beacon-dot {
    color: var(--acid, #42ff8a);
    animation: beacon 1.2s infinite;
  }

  @keyframes beacon {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.3; transform: scale(0.85); }
  }

  .target-title {
    font-family: var(--font-display, 'Michroma', sans-serif);
    font-size: 14px;
    font-weight: 700;
    color: var(--fg, #f5e8e8);
    word-break: break-all;
    margin-bottom: 8px;
    line-height: 1.35;
  }

  .meta-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 11px;
    color: var(--mute, #8a5a64);
    margin-bottom: 14px;
  }

  .mono-id {
    letter-spacing: 0.04em;
  }

  .time-stamp {
    font-size: 10px;
  }

  .progress-wrap {
    margin-bottom: 14px;
  }

  .progress-track {
    height: 3px;
    width: 100%;
    background: var(--bg-soft, #1a0b10);
    overflow: hidden;
  }

  .progress-fill {
    height: 100%;
    background: var(--mute, #8a5a64);
    transition: width 0.3s ease;
  }

  .progress-fill.completed {
    background: var(--acid, #42ff8a);
  }

  .progress-fill.failed {
    background: var(--red, #ff1a3c);
  }

  .progress-meta {
    display: flex;
    justify-content: space-between;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    letter-spacing: 0.06em;
    color: var(--mute, #8a5a64);
    margin-top: 4px;
    text-transform: uppercase;
  }

  .pct-num {
    color: var(--fg, #f5e8e8);
    font-weight: 700;
  }

  .summary-pills {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    margin-bottom: 12px;
  }

  .pill {
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    font-weight: 700;
    padding: 2px 6px;
    letter-spacing: 0.04em;
  }

  .pill.crit {
    background: var(--red, #ff1a3c);
    color: #ffffff;
  }

  .pill.high {
    background: #ff8a3a;
    color: #050204;
  }

  .pill.med {
    background: var(--acid, #42ff8a);
    color: #050204;
  }

  .pill.total {
    border: 1px solid var(--line, rgba(255, 26, 60, 0.25));
    color: var(--fg, #f5e8e8);
  }

  .err-sub {
    font-family: var(--font-mono, 'Space Mono', monospace);
    color: var(--red, #ff1a3c);
    font-size: 11px;
    margin-bottom: 10px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .card-foot {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-top: 1px dashed var(--line, rgba(255, 26, 60, 0.2));
    padding-top: 10px;
    margin-top: auto;
    font-family: var(--font-mono, 'Space Mono', monospace);
    font-size: 10px;
    letter-spacing: 0.1em;
    color: var(--mute, #8a5a64);
  }

  .inspect-txt {
    color: var(--red, #ff1a3c);
    font-weight: 700;
    transition: transform 0.2s ease;
  }

  .tactical-card:hover .inspect-txt {
    transform: translateX(3px);
  }
</style>
