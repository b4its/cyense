<script>
  import { toggleTheme, theme } from '../lib/theme.js'
  import { onMount } from 'svelte'

  let route = ''
  onMount(() => {
    const sync = () => { route = (location.hash || '#/').replace('#', '') }
    sync()
    window.addEventListener('hashchange', sync)
  })

  $: href = (p) => `#${p}`
  $: active = (p) => route.startsWith(p)
</script>

<header class="site">
  <div class="wrap">
    <a class="brand" href="#/">cyense<span class="dot">.</span>insight</a>
    <nav class="site">
      <a href="#/" class:active={active('/')}>Dashboard</a>
      <a href="#/scans" class:active={active('/scans')}>Scan Library</a>
      <a href="#/rules" class:active={active('/rules')}>Rules</a>
    </nav>
    <button class="theme-toggle" onclick={toggleTheme}>
      {#if $theme === 'light'}☾ dim{/if}
      {#if $theme === 'dim'}☀ light{/if}
    </button>
  </div>
</header>
