<script>
  export let items = []       // [{id, label}]
  export let activeId = ''
  export let onjump = null     // optional async jump helper (handles cross-page anchors)

  async function jump(it, e) {
    e.preventDefault()
    if (onjump) { await onjump(it.id); return }
    document.getElementById(it.id)?.scrollIntoView({ behavior: 'smooth' })
  }
</script>

<div class="toc">
  <div class="card" style="padding:12px 8px">
    <div style="font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--ink-faint);padding:0 10px 8px">Daftar Temuan</div>
    <ul>
      {#each items as it}
        <li><a href="#/{it.id}" class:active={activeId === it.id} onclick={(e) => jump(it, e)}>{it.label}</a></li>
      {/each}
    </ul>
  </div>
</div>
