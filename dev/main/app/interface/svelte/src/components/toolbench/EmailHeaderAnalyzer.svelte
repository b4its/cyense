<script>
  // Email header analyzer — parses RFC 5322 raw headers fully in the browser.
  // Extracts the Received relay chain, IPs per hop, and SPF/DKIM/DMARC
  // verdicts from Authentication-Results / header text. No mail leaves the
  // machine: paste only, zero uploads (Toolbench promise).
  import { analyze_headers } from '../../lib/headers.js'

  let raw = ''
  let report = null
  $: report = raw.includes(':') ? analyze_headers(raw) : null
</script>

<div class="tb-panel">
  <p class="tool-modal-desc">Tempel <b>raw header</b> (dari "Show original") — rantai
    relay <code class="wf-conf">Received:</code> diurut dari MTA asal, IP per hop
    diekstrak, dan verdict <code class="wf-conf">spf/dkim/dmarc</code> dibaca dari
    <code class="wf-conf">Authentication-Results</code>. Murni lokal.</p>
  <div class="field"><label for="tb-raw">Raw headers</label>
    <textarea id="tb-raw" rows="10" bind:value={raw}
      placeholder={`Return-Path: <from@example.com>\nReceived: from mx.example.com (mail.example.com [203.0.113.5])\n  by dest.example.org with ESMTPS id 42 for <target@dest.example.org>;\n  Tue, 08 Sep 2026 04:26:40 +0000\nAuthentication-Results: dest.example.org; spf=pass smtp.mailfrom=example.com;\n  dkim=pass header.d=example.com; dmarc=pass header.from=example.com`}
    ></textarea></div>
  <p class="tool-src">Header tidak di-parse = data tidak dapat dipakai. Analisis ini
    tidak melakukan query DNS/SPF live — verdict hanya sevalid kredensial header itu
    sendiri (bisa dipalsukan pada server rentan).</p>

  {#if report}
    <div class="tb-output">
      {#if report.envelope.from || report.envelope.returnPath}
        <h3 class="tool-modal-h">Envelope</h3>
        <dl class="tb-kv">
          <dt>From</dt><dd>{report.envelope.from || '—'}</dd>
          <dt>Return-Path</dt><dd>{report.envelope.returnPath || '—'}</dd>
          <dt>Reply-To</dt><dd>{report.envelope.replyTo || '—'}</dd>
          <dt>To</dt><dd>{report.envelope.to || '—'}</dd>
          <dt>Subject</dt><dd>{report.envelope.subject || '—'}</dd>
          <dt>Message-ID</dt><dd class="tb-mono">{report.envelope.messageId || '—'}</dd>
          <dt>Date</dt><dd>{report.envelope.date || '—'}</dd>
        </dl>
      {/if}

      {#if report.hops.length}
        <h3 class="tool-modal-h">Rantai relay ({report.hops.length} hop — terlama →
          terhitung dari MUA; urutan atas = paling awal)</h3>
        {#each report.hops as hop, i}
          <div class="wf-step">
            <div class="tool-name" style="font-size:14px">
              <span class="wf-step-num">{i + 1}</span>
              by <code class="wf-conf">{hop.by || '?'}</code>
              {#if hop.with} (dengan {hop.with}){/if}
            </div>
            <ul class="tool-modal-list" style="margin:2px 0 0 26px">
              {#if hop.date}<li>Waktu {hop.date}</li>{/if}
              {#if hop.ip}<li>IP <code class="wf-conf">{hop.ip}</code> {#if hop.rdns}({hop.rdns}){/if}
                {#if hop.isPrivate} — <b class="tb-err" style="display:inline">alamat privat</b>{/if}</li>{/if}
            </ul>
          </div>
        {/each}
        {#if report.originIp}
          <p class="tool-src">IP asal terendah yang terlihat: <a href="https://www.abuseipdb.com/check/{report.originIp}" target="_blank" rel="noopener noreferrer">{report.originIp}</a>
            · <a href="https://greynoise.io/search?term={report.originIp}" target="_blank" rel="noopener noreferrer">GreyNoise</a></p>
        {/if}
      {/if}

      {#if report.auth.length}
        <h3 class="tool-modal-h">Verifikasi autentikasi</h3>
        {#each report.auth as a}
          <div class="auth-row">
            <span class="badge {a.verdict === 'pass' ? 'info' : (a.verdict === 'fail' || a.verdict === 'permerror' || a.verdict === 'temperror' ? 'high' : '')}">{a.mech}={a.verdict || '—'}</span>
            {#if a.detail}<span class="tool-src">· {a.detail}</span>{/if}
          </div>
        {/each}
        {#if !report.auth.some((a) => a.mech === 'dmarc')}
          <p class="tb-err">Tidak ditemukan baris dmarc= — domain pengirim mungkin
            tidak mem-publish DMARC atau relay tidak menambahkannya.</p>
        {/if}
      {/if}
    </div>
  {/if}
</div>
