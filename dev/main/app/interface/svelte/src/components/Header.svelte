<script>
  import { toggleTheme, theme } from '../lib/theme.js'
  import { onMount } from 'svelte'

  let route = ''
  let open = false

  onMount(() => {
    const sync = () => { route = (location.hash || '#/').replace('#', '') }
    sync()
    window.addEventListener('hashchange', sync)
  })

  $: href = (p) => `#${p}`
  // Root "/" must be an exact match — startsWith("/") would mark Dashboard
  // active on every page (/websites, /scans, …).
  $: active = (p) => (p === '/' ? route === '/' : route.startsWith(p))

  function nav() { open = false }
</script>

<header class="site">
  <div class="wrap">
    <a class="brand" href="#/" onclick={nav}>cyense<span class="dot">.</span>insight</a>

    <nav class="site" class:open>
      <a href="#/" class:active={active('/')} onclick={nav}>Dashboard</a>
      <a href="#/websites" class:active={active('/websites')} onclick={nav}>Websites</a>
      <a href="#/scans" class:active={active('/scans')} onclick={nav}>Scan Library</a>
      <a href="#/rules" class:active={active('/rules')} onclick={nav}>Rules</a>
    </nav>

    <div class="header-right">
      <button class="theme-toggle" onclick={toggleTheme} aria-label="Ganti tema">
        {#if $theme === 'light'}☾ dim{/if}
        {#if $theme === 'dim'}☀ light{/if}
      </button>
      <button class="nav-toggle" class:open onclick={() => (open = !open)} aria-label="Menu" aria-expanded={open}>
        <span></span><span></span><span></span>
      </button>
    </div>
  </div>
</header>