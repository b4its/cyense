<script>
  // Toolbench — the only real *execution* layer of OSINT Radar, rebuilt
  // client-side: "local · no account · offline-capable" (IP Lookup is the
  // documented network exception). No state leaves the browser except that
  // one geolocation query. Coordinate Converter is a §4.2-recommended
  // extension (flagged with an "ext" badge, not one of the site's 7).
  import DorkBuilder from './toolbench/DorkBuilder.svelte'
  import IpLookup from './toolbench/IpLookup.svelte'
  import TimestampDecoder from './toolbench/TimestampDecoder.svelte'
  import EmailHeaderAnalyzer from './toolbench/EmailHeaderAnalyzer.svelte'
  import ImageMetadata from './toolbench/ImageMetadata.svelte'
  import UsernameSweep from './toolbench/UsernameSweep.svelte'
  import HashIdentifier from './toolbench/HashIdentifier.svelte'
  import CoordinateConverter from './toolbench/CoordinateConverter.svelte'

  const TOOLS = [
    { id: 'dork-builder', name: 'Dork Builder', emoji: '🔩', comp: DorkBuilder },
    { id: 'ip-lookup', name: 'IP Lookup', emoji: '🌐', comp: IpLookup, net: true },
    { id: 'timestamp-decoder', name: 'Timestamp Decoder', emoji: '🕐', comp: TimestampDecoder },
    { id: 'email-header-analyzer', name: 'Email Header Analyzer', emoji: '📧', comp: EmailHeaderAnalyzer },
    { id: 'image-metadata-exif', name: 'Image Metadata / EXIF', emoji: '🖼️', comp: ImageMetadata },
    { id: 'username-sweep', name: 'Username Sweep', emoji: '🧹', comp: UsernameSweep },
    { id: 'hash-identifier', name: 'Hash Identifier', emoji: '🔐', comp: HashIdentifier },
    // §4.2 low-priority proposal by the analysis (not one of the site's 7)
    { id: 'coordinate-converter', name: 'Coordinate Converter', emoji: '🗺️', comp: CoordinateConverter, ext: true },
  ]

  let active = TOOLS[0].id
</script>

<div class="tb-wrap">
  <aside class="tb-nav" aria-label="Pilih utilitas Toolbench">
    {#each TOOLS as t}
      <button class="tb-tool" class:active={active === t.id} onclick={() => active = t.id}>
        {t.emoji} {t.name}
        {#if t.net}<span class="badge" title="memerlukan jaringan">net</span>{/if}
        {#if t.ext}<span class="badge info" title="Ekspansi §4.2 — bukan dari 7 asli platform">ext</span>{/if}
      </button>
    {/each}
    <p class="tb-privacy">Janji Toolbench (OSINT Radar): <b>local</b>, tanpa akun,
      tanpa unggah, tanpa logging — data investigasi tidak pernah meninggalkan mesin.</p>
  </aside>
  <div class="tb-main">
    {#each TOOLS as t}
      {#if active === t.id}
        <h3 class="tool-modal-h" style="margin-top:0">{t.emoji} {t.name}</h3>
        {@const Comp = t.comp}
        <Comp />
      {/if}
    {/each}
  </div>
</div>
