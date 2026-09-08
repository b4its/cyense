<script>
  // Username sweep — generates profile-URL pivots across platforms WITHOUT
  // sending any requests (OSINT Radar's design: URL list to check manually,
  // never account existence confirmation). Fully offline.
  let username = ''

  const PLATFORMS = [
    { cat: 'Sosial', name: 'X/Twitter', url: 'https://x.com/{u}' },
    { cat: 'Sosial', name: 'Instagram', url: 'https://www.instagram.com/{u}/' },
    { cat: 'Sosial', name: 'TikTok', url: 'https://www.tiktok.com/@{u}' },
    { cat: 'Sosial', name: 'Facebook', url: 'https://www.facebook.com/{u}' },
    { cat: 'Sosial', name: 'Reddit', url: 'https://www.reddit.com/user/{u}' },
    { cat: 'Sosial', name: 'LinkedIn', url: 'https://www.linkedin.com/in/{u}' },
    { cat: 'Sosial', name: 'Threads', url: 'https://www.threads.net/@{u}' },
    { cat: 'Sosial', name: 'Mastodon', url: 'https://mastodon.social/@{u}' },
    { cat: 'Dev', name: 'GitHub', url: 'https://github.com/{u}' },
    { cat: 'Dev', name: 'GitLab', url: 'https://gitlab.com/{u}' },
    { cat: 'Dev', name: 'Bitbucket', url: 'https://bitbucket.org/{u}/' },
    { cat: 'Dev', name: 'StackOverflow', url: 'https://stackoverflow.com/users/?username={u}' },
    { cat: 'Dev', name: 'npm', url: 'https://www.npmjs.com/~{u}' },
    { cat: 'Dev', name: 'PyPI', url: 'https://pypi.org/user/{u}/' },
    { cat: 'Dev', name: 'Hugging Face', url: 'https://huggingface.co/{u}' },
    { cat: 'Komunitas', name: 'Medium', url: 'https://medium.com/@{u}' },
    { cat: 'Komunitas', name: 'Pinterest', url: 'https://www.pinterest.com/{u}/' },
    { cat: 'Komunitas', name: 'Tumblr', url: 'https://{u}.tumblr.com' },
    { cat: 'Komunitas', name: 'Twitch', url: 'https://www.twitch.tv/{u}' },
    { cat: 'Komunitas', name: 'YouTube', url: 'https://www.youtube.com/@{u}' },
    { cat: 'Komunitas', name: 'Telegram', url: 'https://t.me/{u}' },
    { cat: 'Paste/DB', name: 'GitLeaks search', url: 'https://github.com/search?q={u}&type=user' },
    { cat: 'Paste/DB', name: 'HaveIBeenPwned', url: 'https://haveibeenpwned.com/unified_search/{u}' },
  ]

  $: clean = username.trim().toLowerCase()
  $: valid = /^[a-z0-9][a-z0-9._-]{0,38}$/.test(clean)
  $: grouped = () => {
    const out = {}
    for (const p of PLATFORMS) {
      if (clean && valid) {
        ;(out[p.cat] ||= []).push({ name: p.name, url: p.url.replace('{u}', clean) })
      }
    }
    return Object.keys(out).length ? out : null
  }
  let groups
  $: groups = grouped()
  $: total = groups ? Object.values(groups).reduce((n, l) => n + l.length, 0) : 0

  let copied = false
  async function copyAll() {
    const txt = Object.entries(groups)
      .map(([c, list]) => `## ${c}\n` + list.map((l) => `- ${l.name}: ${l.url}`).join('\n'))
      .join('\n\n')
    await navigator.clipboard.writeText(txt)
    copied = true
    setTimeout(() => (copied = false), 1500)
  }
</script>

<div class="tb-panel">
  <p class="tool-modal-desc">Hasilkan URL profil lintas platform dari satu handle.
    Tool ini TIDAK mengirim permintaan — hanya menyusun pivot URL untuk diperiksa
    manual. (Konsisten dengan desain offline OSINT Radar.)</p>
  <div class="field"><label for="tb-uname">Username</label>
    <input id="tb-uname" type="text" bind:value={username} autocomplete="off"
           placeholder="contoh: john_doe123" /></div>

  {#if username && !valid}
    <p class="tb-err">Username tampak tidak wajar (karakter/huruf besar/panjang).
      Percobaan tetap sah — beberapa platform mengizinkan karakter khusus.</p>
  {/if}
  {#if groups}
    <div class="tb-output">
      <div class="usage-row">
        <span class="field-label">{total} URL untuk {clean} — periksa manual</span>
        <button class="btn sm" onclick={copyAll}>{copied ? '✓ disalin' : 'salin semua'}</button>
      </div>
      {#each Object.entries(groups) as [cat, list]}
        <div class="wf-step">
          <div class="tool-name" style="font-size:14px">{cat}</div>
          <ul class="tool-modal-list">
            {#each list as p}
              <li><a href={p.url} target="_blank" rel="noopener noreferrer">{p.name}</a></li>
            {/each}
          </ul>
        </div>
      {/each}
      <p class="tool-src">Workflow OSINT Radar: treat results as leads, not confirmations
        — name collisions lazim; buka tiap URL, verifikasi foto/bio/pola posting.</p>
    </div>
  {/if}
</div>
