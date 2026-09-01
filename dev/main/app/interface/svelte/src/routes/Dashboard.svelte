<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import Hero from '../components/Hero.svelte'
  import ScanCard from '../components/ScanCard.svelte'

  let scans = []
  let rules = null
  let loading = true
  let error = ''

  onMount(async () => {
    try {
      const [s, r] = await Promise.all([api.listScans(), api.rules()])
      scans = s || []
      rules = r
    } catch (e) { error = String(e) }
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

{#if loading}
  <section class="block"><div class="wrap"><div class="skeleton" style="height:200px"></div></div></section>
{:else if error}
  <section class="block"><div class="wrap"><p style="color:var(--err)">{error}</p></div></section>
{:else}
  <!-- Featured series / featured scan -->
  <section class="block">
    <div class="wrap">
      <h2>{featured ? 'Scan Terbaru' : 'Mulai Scan'}</h2>
      <p class="sub">Pilih target di Scan Library, atau mulai dari dashboard.</p>
      <div style="display:flex;gap:12px;flex-wrap:wrap">
        <a class="btn primary" href="#/scans">→ Scan Library</a>
        <a class="btn" href="#/rules">Lihat Rules</a>
      </div>
    </div>
  </section>

  <!-- Series Library → Scan library grid with completion -->
  <section class="block">
    <div class="wrap">
      <h2>Scan Terkini</h2>
      <p class="sub">Setiap kartu = satu scan dengan persentase progres.</p>
      {#if recent.length}
        <div class="grid">
          {#each recent as s}<ScanCard {s} />{/each}
        </div>
      {:else}
        <p class="muted">Belum ada scan. Gunakan CLI <code class="inline">cyense scan website URL --i-have-permission</code> atau API.</p>
      {/if}
    </div>
  </section>
{/if}
