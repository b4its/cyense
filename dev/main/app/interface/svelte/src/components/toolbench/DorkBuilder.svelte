<script>
  // Local dork builder — composes search-operator strings client-side
  // (OSINT Radar Toolbench parity: no accounts, no uploads, no logging).
  let site = ''
  let keyword = ''
  let phrase = ''
  let filetype = ''
  let intitle = ''
  let inurl = ''
  let intext = ''
  let exclude = ''

  $: tokens = [
    site && `site:${site.trim()}`,
    keyword && `"${keyword.trim()}"`,
    phrase && `"${phrase.trim()}"`,
    filetype && `filetype:${filetype}`,
    intitle && `intitle:"${intitle.trim()}"`,
    inurl && `inurl:${inurl.trim()}`,
    intext && `intext:"${intext.trim()}"`,
    ...exclude.split(/[,;]/).map((s) => s.trim()).filter(Boolean).map((t) => `-${t}`),
  ].filter(Boolean)
  $: dork = tokens.join(' ')

  let copied = false
  async function copy() {
    if (!dork) return
    await navigator.clipboard.writeText(dork)
    copied = true
    setTimeout(() => (copied = false), 1500)
  }
</script>

<div class="tb-panel">
  <p class="tool-modal-desc">Susun operator pencarian (<code class="wf-conf">site:</code>
    <code class="wf-conf">filetype:</code> <code class="wf-conf">intitle:</code> …) tanpa
    memanggil mesin pencari — dibangun sepenuhnya di browser.</p>

  <div class="tb-form">
    <div class="field"><label for="tb-site">Domain / situs (site:)</label>
      <input id="tb-site" type="text" placeholder="example.com" bind:value={site} /></div>
    <div class="field"><label for="tb-kw">Kata kunci tepat (…)</label>
      <input id="tb-kw" type="text" placeholder="password" bind:value={keyword} /></div>
    <div class="field"><label for="tb-phrase">Frasa eksak</label>
      <input id="tb-phrase" type="text" placeholder="login panel" bind:value={phrase} /></div>
    <div class="field"><label for="tb-ft">Tipe file (filetype:)</label>
      <select id="tb-ft" bind:value={filetype}>
        <option value="">— tanpa —</option>
        {#each ['pdf','doc','docx','xls','xlsx','ppt','txt','env','sql','bak','json','log','xml','conf','yml'] as ft}
          <option value={ft}>{ft}</option>
        {/each}
      </select></div>
    <div class="field"><label for="tb-intitle">Judul mengandung (intitle:)</label>
      <input id="tb-intitle" type="text" placeholder="index of" bind:value={intitle} /></div>
    <div class="field"><label for="tb-inurl">URL mengandung (inurl:)</label>
      <input id="tb-inurl" type="text" placeholder="admin" bind:value={inurl} /></div>
    <div class="field"><label for="tb-intext">Teks mengandung (intext:)</label>
      <input id="tb-intext" type="text" placeholder="confidential" bind:value={intext} /></div>
    <div class="field"><label for="tb-ex">Kecualikan (pisahkan koma)</label>
      <input id="tb-ex" type="text" placeholder="site, blog" bind:value={exclude} /></div>
  </div>

  <div class="tb-output">
    <div class="field-label">Query siap-tempel</div>
    <div class="usage-row">
      <code class="tb-code">{dork || '(lengkapi field di atas)'}</code>
      <button class="btn sm" onclick={copy} disabled={!dork}>{copied ? '✓ disalin' : 'salin'}</button>
    </div>
    {#if site}
      <p class="tool-src">Uji di mesin pencari eksternal — hasil cepat berubah, arsipkan
        bersama timestamp sebelum dikutip sebagai temuan.</p>
    {/if}
  </div>
</div>
