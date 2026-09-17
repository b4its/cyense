import { writable } from 'svelte/store'

// Theme store: 'dark' (default) or 'light'.
const stored = (typeof localStorage !== 'undefined' && localStorage.getItem('cyense-theme')) || 'dark'
export const theme = writable(stored === 'light' ? 'light' : 'dark')

theme.subscribe((t) => {
  if (typeof document !== 'undefined') {
    document.documentElement.setAttribute('data-theme', t)
    if (typeof localStorage !== 'undefined') localStorage.setItem('cyense-theme', t)
  }
})

export function toggleTheme() {
  theme.update((t) => (t === 'dark' ? 'light' : 'dark'))
}

export function setTheme(t) {
  theme.set(t === 'light' ? 'light' : 'dark')
}

