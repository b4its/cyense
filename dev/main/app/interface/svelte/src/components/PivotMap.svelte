<script>
  // Interactive Pivot Map – user-guided typed graph (§4.1): identifier →
  // tools that accept it → their output artefacts → identifier types handed
  // to the next lookup. Two renderings, same state: text list or an SVG
  // node-link graph (§3.3.5 "visualisasikan graf pivot secara interaktif").
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'

  export let onOpenTool = () => {}
  export let catalog = null

  let pivotTypes = []
  let artefactTypes = {}
  let flatTools = []
  let trail = []
  let focus = null
  let showGraph = false

  onMount(async () => {
    const src = catalog || await api.tools()
    pivotTypes = src.pivot_types || []
    artefactTypes = src.artefact_types || {}
    flatTools = src.tools || []
  })

  const haveLabel = (c) => pivotTypes.find((p) => p.code === c)?.label || c

  function accepting(code) {
    return flatTools.filter(
      (t) => (t.you_have || []).includes(code) &&
        (t.tool_status || 'Operational') === 'Operational',
    )
  }

  function artifactHops(tool) {
    const out = []
    for (const a of (tool.you_get || [])) {
      const codes = [...new Set(artefactTypes[a] || [])]
      if (codes.length) out.push({ artefact: a, codes })
    }
    return out
  }

  function startFrom(code) { trail = []; focus = { kind: 'type', code, label: haveLabel(code) } }
  function pickTool(tool) {
    if (focus?.kind === 'type') trail = [...trail, { kind: 'type', label: focus.label }]
    else if (focus?.kind === 'tool') trail = [...trail, { kind: 'tool', tool: focus.tool }]
    focus = { kind: 'tool', tool }
  }
  function fromArtefact(code) {
    trail = [...trail, { kind: 'tool', tool: focus.tool || (focus?.kind === 'artefact' && focus.tool) }]
    focus = { kind: 'type', code, label: haveLabel(code) }
  }
  function reset() { trail = []; focus = null; showGraph = false }

  // ── graph geometry ───────────────────────────────────────────────────────
  const COL = { l: 88, m: 300, r: 520 }, GAP = 40
  const wOf = (label, kind) =>
    kind === 'tool' ? Math.min(150, Math.max(64, label.length * 6.6))
      : Math.min(150, Math.max(56, label.length * 6.6))

  /** build {nodes, edges, byId} for `f`'s current focus (capped). Args carry
   *  reactivity: Svelte tracks $: deps syntactically, so focus/flatTools must
   *  appear in the call expression below. */
  function buildGraph(f, tools) {
    if (!tools || !f || f.kind === 'artefact') return null
    const nodes = [], edges = []

    if (f.kind === 'type') {
      const tl = accepting(f.code).slice(0, 14)
      nodes.push({ id: 'T:' + f.code, kind: 'type', label: f.label, cx: COL.l, cy: 30 + tl.length * GAP / 2, code: f.code })
      tl.forEach((t, i) => {
        const cy = 30 + i * GAP
        nodes.push({ id: 'K:' + t.name, kind: 'tool', label: t.name, cx: COL.m, cy, tool: t })
        edges.push({ from: 'T:' + f.code, to: 'K:' + t.name })
        const codes = [...new Set(artifactHops(t).flatMap((h) => h.codes))].slice(0, 4)
        if (codes.length) {
          nodes.push({ id: 'A:' + t.name, kind: 'art', label: codes.map(haveLabel).join(' · '), cx: COL.r, cy, codes, from: t.name })
          edges.push({ from: 'K:' + t.name, to: 'A:' + t.name })
        }
      })
    } else if (f.kind === 'tool') {
      const t = f.tool
      const ins = [...new Set(t.you_have || [])].slice(0, 10)
      const hops = artifactHops(t).slice(0, 10)
      nodes.push({ id: 'K:' + t.name, kind: 'tool', label: t.name, cx: COL.m, cy: 30 + Math.max(ins.length, hops.length) * GAP / 2, tool: t })
      ins.forEach((c, i) => {
        nodes.push({ id: 'I:' + c, kind: 'type', label: haveLabel(c), cx: COL.l, cy: 30 + i * GAP, code: c })
        edges.push({ from: 'I:' + c, to: 'K:' + t.name })
      })
      hops.forEach((h, i) => {
        nodes.push({ id: 'A:' + h.artefact, kind: 'art', label: `${h.artefact} → ${h.codes.slice(0, 2).map(haveLabel).join('·')}`, cx: COL.r, cy: 30 + i * GAP, codes: h.codes, artefact: h.artefact, from: t.name })
        edges.push({ from: 'K:' + t.name, to: 'A:' + h.artefact })
      })
    }
    return { nodes, edges, byId: Object.fromEntries(nodes.map((n) => [n.id, n])) }
  }

  function edgePath(e, g) {
    const a = g.byId[e.from], b = g.byId[e.to]
    if (!a || !b) return 'M0 0'
    const aw = wOf(a.label, a.kind), bw = wOf(b.label, b.kind)
    const x1 = a.cx + aw / 2, x2 = b.cx - bw / 2
    const dx = Math.max(24, (x2 - x1) / 2)
    return `M ${x1} ${a.cy + 14} C ${x1 + dx} ${a.cy + 14}, ${x2 - dx} ${b.cy + 14}, ${x2} ${b.cy + 14}`
  }

  $: graph = buildGraph(focus, flatTools)
  $: graphH = graph ? 40 + Math.max(graph.nodes.length * 1, ...graph.nodes.map((n) => n.cy)) + 30 : 100
  $: SVG_W = 640
</script>

<div class="pm-wrap">
  <div class="pm-start">
    <h3 class="tool-modal-h" style="margin:0 0 10px">🧭 Pivot Map</h3>
    <p class="tool-modal-desc" style="margin:0 0 14px">
      Setiap tool adalah fungsi bertipe: <b>you have → you get</b>. Pilih identifier
      yang Anda pegang, lalu telusuri hop demi hop — pilihan manual, tanpa saran otomatis.
    </p>
    <div class="pivot-filter">
      <span class="pivot-label">Saya punya:</span>
      {#each pivotTypes as p}
        <button class="pivot-chip" class:active={focus?.kind === 'type' && focus.code === p.code}
                onclick={() => { startFrom(p.code); showGraph = true }}>{p.label}</button>
      {/each}
    </div>
  </div>

  {#if trail.length || focus}
    <div class="pm-trail">
      {#each trail as hop}
        <span class="pm-node">{hop.tool?.name || hop.label}</span>
        <span class="pm-arrow">→</span>
      {/each}
      {#if focus?.kind === 'type'}
        <span class="pm-node pm-active">{focus.label}</span>
      {:else if focus?.kind === 'tool'}
        <span class="pm-node pm-active">{focus.tool.name}</span>
      {:else if focus?.kind === 'artefact'}
        <span class="pm-node pm-active">{focus.artefact}</span>
      {/if}
      <button class="pivot-chip clear" style="margin-left:auto" onclick={reset} aria-label="Mulai ulang jelajah">↺ ulang</button>
      <button class="pivot-chip" onclick={() => showGraph = !showGraph} aria-pressed={showGraph}>
        {showGraph ? '📃 List' : '🕸 Graf'}</button>
    </div>
  {/if}

  {#if showGraph && graph}
    <svg class="pm-graph" viewBox="0 0 {SVG_W} {graphH}" role="img"
         aria-label="Graf pivot identifier–tool–artefak dari fokus saat ini"
         xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet">
      <defs>
        <marker id="pm-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
          <path d="M0 0 L10 5 L0 10 z" fill="var(--ink-mute,#8a93a6)" />
        </marker>
      </defs>
      {#each graph.edges as e}
        <path d={edgePath(e, graph)} stroke="var(--ink-mute,#8a93a6)" stroke-width="1.2" fill="none" opacity="0.5" marker-end="url(#pm-arrow)" />
      {/each}
      {#each graph.nodes as n}
        {@const w = wOf(n.label, n.kind)}
        <g class="pm-gnode pm-{n.kind}"
           onclick={() => {
             if (n.kind === 'tool') pickTool(n.tool)
             else if (n.kind === 'type') startFrom(n.code)
             else if (n.kind === 'art' && n.codes?.[0]) fromArtefact(n.codes[0])
           }}
           onkeydown={(ev) => ev.key === 'Enter' && (n.kind === 'tool' ? pickTool(n.tool) : n.kind === 'type' ? startFrom(n.code) : n.codes?.[0] && fromArtefact(n.codes[0]))}
           role="button" tabindex="0"
           transform="translate({n.cx - w / 2} {n.cy})">
          <rect width={w} height="28" rx="13" />
          <text x={w / 2} y="18">{n.label.slice(0, 20)}{n.label.length > 20 ? '…' : ''}</text>
          {#if n.kind === 'art'}<title>{n.from} → {n.artefact || n.codes.map(haveLabel).join(', ')} — klik: lanjut ke {haveLabel(n.codes[0])}</title>{/if}
          {#if n.kind === 'tool'}<title>klik: lihat {n.label} sebagai simpul output</title>{/if}
        </g>
      {/each}
    </svg>
    <p class="tool-src">Tombol Graf/List mengubah render yang sama — node biru=identifier, kotak=tool, dashed=artefak→identifier berikutnya. Layout kolom adalah visualisasi hop aktif, bukan posisi koordinat.</p>
  {:else if !showGraph && (focus || trail.length)}
    <section class="pm-panel">
      {#if focus?.kind === 'type'}
        {@const list = accepting(focus.code)}
        <h4>Tool yang menerima <b>{focus.label}</b> — {list.length} (Operational)</h4>
        <div class="pm-tools">
          {#each list.slice(0, 48) as t}
            <button class="pm-tool" onclick={() => pickTool(t)}>
              <div class="tool-name" style="font-size:13px">{t.name}</div>
              <div class="muted" style="font-size:11.5px">{t.category || ''}</div>
            </button>
          {/each}
        </div>
      {:else if focus?.kind === 'tool'}
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
          <h4 style="margin:0">{focus.tool.name}</h4>
          <button class="badge related" onclick={() => onOpenTool(focus.tool)}>buka detail →</button>
        </div>
        <div class="tool-pivot">
          <div><span class="pivot-label">You have</span>
            {#each focus.tool.you_have || [] as v}<span class="tag-chip-ui">{v}</span>{/each}
          </div>
          <span>→</span>
          <div><span class="pivot-label">You get</span>
            {#each focus.tool.you_get || [] as v}<span class="tag-chip-ui out">{v}</span>{/each}
          </div>
        </div>
        <h4 style="margin:14px 0 6px">Lanjutkan dari artefak…</h4>
        {#each artifactHops(focus.tool) as ah}
          <div class="pm-artefact">
            <span class="tag-chip-ui out">{ah.artefact}</span>
            <span class="pm-arrow">→</span>
            {#each ah.codes as c}
              <button class="pivot-chip" onclick={() => fromArtefact(c)}>{haveLabel(c)} ({accepting(c).length})</button>
            {/each}
          </div>
        {/each}
        {#if !artifactHops(focus.tool).length}
          <p class="muted">Artefak output tool ini terminal (panduan/bukti) — titik berhenti yang sehat.</p>
        {/if}
      {:else if focus?.kind === 'artefact'}
        <h4>Artefak <b>{focus.artefact}</b> dari {focus.tool.name}</h4>
        {#each artefactTypes[focus.artefact] || [] as c}
          <button class="pivot-chip" onclick={() => fromArtefact(c)}>→ {haveLabel(c)} ({accepting(c).length})</button>
        {/each}
      {/if}
    </section>
  {/if}

  {#if !focus}
    <p class="cat-note" style="margin-top:14px">
      Contoh rantai (dari dokumen analisis): <code>username</code> → enumerasi →
      <code>email</code> → breach check → <code>domain</code> → infra. Setiap panah di sini
      adalah pilihan eksplisit Anda, jadi tidak ada lompatan tak logis seperti yang terjadi
      pada saran otomatis osintradar (mis. AlgoVPN dari hasil breach email).
    </p>
  {/if}
</div>

<style>
  .pm-graph { width: 100%; height: auto; background: var(--bg-elev); border: 1px solid var(--line); border-radius: 12px; margin-top: 12px; }
  .pm-gnode { cursor: pointer; }
  .pm-gnode rect { transition: filter .12s; }
  .pm-gnode:hover rect { filter: brightness(1.18); }
  .pm-gnode:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  .pm-type rect { fill: color-mix(in srgb, var(--accent) 12%, transparent); stroke: var(--accent); stroke-width: 1; }
  .pm-type text { fill: var(--accent-strong); font-family: var(--mono, monospace); font-size: 12px; }
  .pm-tool rect { fill: var(--surface-2, rgba(127,127,127,.1)); stroke: var(--ink-soft); stroke-width: 1; }
  .pm-tool text { fill: var(--ink); font-family: var(--mono, monospace); font-size: 11.5px; }
  .pm-art rect { fill: transparent; stroke: var(--ink-mute, #8a93a6); stroke-width: 1; stroke-dasharray: 4 2; }
  .pm-art text { fill: var(--ink-soft); font-family: var(--mono, monospace); font-size: 10.5px; }
</style>
