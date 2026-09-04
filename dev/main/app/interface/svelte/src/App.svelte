<script>
  import Header from './components/Header.svelte'
  import Dashboard from './routes/Dashboard.svelte'
  import Scans from './routes/Scans.svelte'
  import ScanDetail from './routes/ScanDetail.svelte'
  import Websites from './routes/Websites.svelte'
  import Rules from './routes/Rules.svelte'
  import { onMount } from 'svelte'

  let route = '/'

  onMount(() => {
    const sync = () => { route = (location.hash || '#/').replace('#', '') || '/' }
    sync()
    window.addEventListener('hashchange', sync)
  })

  // Extract /scan/:id
  $: scanMatch = route.match(/^\/scan\/([^/]+)/)
  $: scanId = scanMatch ? decodeURIComponent(scanMatch[1]) : null
</script>

<Header />

<main>
  {#if scanId}
    <ScanDetail scanId={scanId} />
  {:else if route.startsWith('/websites')}
    <Websites />
  {:else if route.startsWith('/scans')}
    <Scans />
  {:else if route.startsWith('/rules')}
    <Rules />
  {:else}
    <Dashboard />
  {/if}
</main>

<footer class="site">
  <div class="wrap">Cyense — Agentic IDOR &amp; XSS vulnerability scanner. Read-only, deterministic, $0. Only scan targets you are authorized to test.</div>
</footer>
