<script>
  export let stages = []   // [{name, status: 'done'|'active'|'pending'}]
</script>

<div class="stage-graph">
  {#each stages as s, i}
    <div class="stage-node {s.status}">
      <div class="dot">{s.status === 'done' ? '✓' : s.status === 'active' ? '●' : '·'}</div>
      <div class="lbl">{s.name}</div>
    </div>
    {#if i < stages.length - 1}
      <div class="stage-link {s.status === 'done' ? 'done' : ''}"></div>
    {/if}
  {/each}
</div>
