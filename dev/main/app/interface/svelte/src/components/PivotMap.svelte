<script>
  // Interactive Pivot Map — the analysis' "greatest conceptual value" (§4.1):
  // each tool is a typed function you_have → you_get, so an investigation
  // advances by handing the identifier you now hold to the next tool. This is
  // USER-GUIDED (no auto-ranked suggestions — the analysis flags those as
  // occasionally illogical), so every hop is an explicit choice.
  //   identifier ─▶ tools that accept it ─▶ pick tool ─▶ its outputs ─▶
  //   pick an output → the identifier type(s) it hands off → next tool…
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'

  export let onOpenTool = () => {}
  export let catalog = null

  let pivotTypes = []
  let artefactTypes = {}
  let flatTools = []

  onMount(async () => {
    const src = catalog || await api.tools()
    pivotTypes = src.pivot_types || []
    artefactTypes = src.artefact_types || {}
    flatTools = src.tools || []
  })

  // --- exploration state ---------------------------------------------------
  // trail = list of hop records, each either {kind:'type',code,label, tools}
  // or {kind:'tool', tool, outputs:[..]} for display as a breadcrumb graph.
  let trail = []
  // current focus: {kind:'type', code} | {kind:'tool', name} | null
  let focus = null
  let err = ''

  $: haveLabel = (c) => pivotTypes.find((p) => p.code === c)?.label || c
  $: artifactTypesLabel = (c) => haveLabel(c)

  // Tools accepting a given identifier (Operational only — dead tools don't
  // make good next steps).
  function accepting(code) {
    return flatTools.filter(
      (t) => (t.you_have || []).includes(code) &&
        (t.tool_status || 'Operational') === 'Operational',
    )
  }

  function startFrom(code) {
    trail = []
    focus = { kind: 'type', code, label: haveLabel(code) }
  }

  function pickTool(tool) {
    focus = { kind: 'tool', tool }
  }

  function artifactHops(tool) {
    // For each you_get artefact, what identifier types does it feed onward?
    const out = []
    for (const a of tool.you_get || []) {
      const codes = artefactTypes[a] || []
      if (codes.length) out.push({ artefact: a, codes })
    }
    return out
  }

  function pivotFrom(artefact) {
    // push current trail marker then focus first identifier of artefact
    // user chose to continue from a specific output artefact.
    focus = { kind: 'artefact', tool: focus.tool, artefact }
  }

  function pickIdentifier(code) {
    // when viewing an artefact, choosing one of its identifier types moves on
    focus = { kind: 'type', code, label: haveLabel(code) }
    trail = [...trail, { kind: 'tool', tool: focus && focus.tool }]
  }

  function reset() { trail = []; focus = null }
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
                onclick={() => startFrom(p.code)}>{p.label}</button>
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
    </div>
  {/if}

  {#if focus?.kind === 'type'}
    {@const list = accepting(focus.code)}
    <section class="pm-panel">
      <h4>Tool yang menerima <b>{focus.label}</b> — {list.length} (Operational)</h4>
      {#if !list.length}
        <p class="muted">Tidak ada tool aktif yang menerima identifier ini.</p>
      {:else}
        <div class="pm-tools">
          {#each list as t}
            <button class="pm-tool" onclick={() => pickTool(t)}>
              <div class="tool-name" style="font-size:13px">{t.name}</div>
              <div class="muted" style="font-size:11.5px">{t.category || ''}</div>
            </button>
          {/each}
        </div>
      {/if}
    </section>

  {:else if focus?.kind === 'tool'}
    <section class="pm-panel">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <h4 style="margin:0">{focus.tool.name}</h4>
        <button class="badge related" onclick={() => onOpenTool(focus.tool)}>buka detail →</button>
        <button class="pivot-chip clear" onclick={reset}>↺ mulai ulang</button>
      </div>
      <div class="tool-pivot" style="margin-top:8px">
        <div><span class="pivot-label">You have</span>
          {#each focus.tool.you_have || [] as v}<span class="tag-chip-ui">{v}</span>{/each}
        </div>
        <span>→</span>
        <div><span class="pivot-label">You get</span>
          {#each focus.tool.you_get || [] as v}<span class="tag-chip-ui out">{v}</span>{/each}
        </div>
      </div>

      <h4 style="margin:14px 0 6px">Lanjutkan dari artefak ini…</h4>
      {#each artifactHops(focus.tool) as ah}
        <div class="pm-artefact">
          <span class="tag-chip-ui out">{ah.artefact}</span>
          <span class="pm-arrow">→ menghasilkan identifier:</span>
          {#each ah.codes as c}
            <button class="pivot-chip" onclick={() => { focus = { kind: 'type', code: c, label: haveLabel(c) }; trail = [...trail, { kind: 'tool', tool: focus.tool }] }}>
              {haveLabel(c)} ({accepting(c).length} tool)
            </button>
          {/each}
        </div>
      {/each}
      {#if !artifactHops(focus.tool).length}
        <p class="muted">Artefak output tool ini bersifat terminal — tidak ada hop lanjutan
          yang jelas (mis. panduan/bukti). Ini titik berhenti yang sehat.</p>
      {/if}
    </section>

  {:else if focus?.kind === 'artefact'}
    <section class="pm-panel">
      <h4>Artefak <b>{focus.artefact}</b> dari {focus.tool.name}</h4>
      {#each artefactTypes[focus.artefact] || [] as c}
        <button class="pivot-chip" onclick={() => { focus = { kind: 'type', code: c, label: haveLabel(c) }; trail = [...trail, { kind: 'tool', tool: focus.tool }] }}>
          → {haveLabel(c)} ({accepting(c).length} tool)
        </button>
      {/each}
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
