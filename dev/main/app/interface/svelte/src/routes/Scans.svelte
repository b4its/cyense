<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import ScanCard from '../components/ScanCard.svelte'

  let scans = []
  let loading = true
  let error = ''
  let url = ''
  let mode = 'website'
  let submitting = false
  let msg = ''

  onMount(async () => { try { scans = await api.listScans() || [] } catch (e) { error = String(e) } loading = false })

  async function submit() {
    submitting = true; msg = ''
    try {
      const payload = { mode, i_have_permission: true }
      if (mode === 'website' || mode === 'link') {
        if (!url) throw new Error('URL/domain target wajib diisi')
        payload.url = url
      }
      if (mode === 'domain') {
        if (!url) throw new Error('Domain wajib diisi')
        payload.domain = url; delete payload.url
      }
      if (mode === 'program') { payload.source_type = 'sample'; delete payload.url }
      if (mode === 'github') {
        if (!url) throw new Error('Repo URL wajib diisi')
        payload.repo_url = url
      }
      const r = await api.submitScan(payload)
      msg = `Scan diajukan: ${r.scan_id}`
      setTimeout(async () => { scans = await api.listScans() || [] }, 1500)
    } catch (e) { msg = String(e) }
    submitting = false
  }
</script>

<section class="hero" style="padding-bottom:24px">
  <div class="wrap">
    <div class="kicker">Scan Library</div>
    <h1>Daftar scan dengan progres.</h1>
    <p class="lead">Kirim scan baru (sama dengan <code class="inline">cyense scan …</code>) atau telusuri hasil sebelumnya.</p>
    <form onsubmit={(e) => { e.preventDefault(); submit() }} style="display:flex;gap:10px;flex-wrap:wrap;align-items:end">
      <div class="field" style="flex:1;min-width:240px">
        <label for="target-url">URL / domain target</label>
        <input id="target-url" bind:value={url} placeholder="http://example.com" />
      </div>
      <div class="field">
        <label for="scan-mode">Mode</label>
      <select id="scan-mode" bind:value={mode}>
        <option value="website">website</option>
        <option value="domain">domain</option>
        <option value="link">link</option>
        <option value="program">program (sample)</option>
        <option value="github">github</option>
      </select>
      </div>
      <button class="btn primary" disabled={submitting}>{submitting ? '…' : 'Scan'}</button>
    </form>
    {#if msg}<p class="mono" style="font-size:13px;color:var(--ink-soft)">{msg}</p>{/if}
  </div>
</section>

<section class="block">
  <div class="wrap">
    {#if loading}<div class="skeleton" style="height:240px"></div>
    {:else if error}<p style="color:var(--err)">{error}</p>
    {:else if scans.length}
      <div class="grid">
        {#each scans as s}<ScanCard {s} />{/each}
      </div>
    {:else}<p class="muted">Belum ada scan.</p>{/if}
  </div>
</section>
