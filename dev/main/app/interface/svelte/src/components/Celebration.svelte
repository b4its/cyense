<script>
  import { playChime } from '../lib/chime.js'
  export let message = 'Scan selesai'
  export let onClose = () => {}
  import { onMount } from 'svelte'
  onMount(() => playChime())
</script>

<div class="celebration">
  <div class="card">
    <div class="gold-tick">✔</div>
    <h2 style="font-family:var(--serif);font-weight:600;margin:10px 0 4px">{message}</h2>
    <p class="muted" style="margin:0 0 16px">Semua stage selesai.</p>
    <button class="btn primary" onclick={onClose}>Tutup</button>
  </div>
</div>
