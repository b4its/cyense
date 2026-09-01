import { writable } from 'svelte/store'

// Theme store: 'light' (default) or 'dim'.
const stored = (typeof localStorage !== 'undefined' && localStorage.getItem('cyense-theme')) || 'light'
export const theme = writable(stored)

theme.subscribe((t) => {
  if (typeof document !== 'undefined') {
    document.documentElement.setAttribute('data-theme', t)
    if (typeof localStorage !== 'undefined') localStorage.setItem('cyense-theme', t)
  }
})

export function toggleTheme() {
  theme.update((t) => (t === 'light' ? 'dim' : 'light'))
}
