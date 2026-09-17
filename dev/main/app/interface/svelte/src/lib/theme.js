import { writable } from 'svelte/store'

// Theme store: 'dark' (default) or 'light'.
function getInitialTheme() {
  try {
    if (typeof localStorage !== 'undefined') {
      const stored = localStorage.getItem('cyense-theme')
      if (stored === 'light' || stored === 'dark') return stored
    }
  } catch (e) {}
  return 'dark'
}

export const theme = writable(getInitialTheme())

theme.subscribe((t) => {
  if (typeof document !== 'undefined') {
    document.documentElement.setAttribute('data-theme', t)
    try {
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem('cyense-theme', t)
      }
    } catch (e) {}
  }
})

if (typeof window !== 'undefined') {
  window.addEventListener('storage', (e) => {
    if (e.key === 'cyense-theme' && (e.newValue === 'light' || e.newValue === 'dark')) {
      theme.set(e.newValue)
    }
  })
}

export function toggleTheme() {
  theme.update((t) => (t === 'dark' ? 'light' : 'dark'))
}

export function setTheme(t) {
  theme.set(t === 'light' ? 'light' : 'dark')
}

