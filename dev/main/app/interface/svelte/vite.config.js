import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

export default defineConfig({
  base: '/ui/',
  plugins: [svelte()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      // In dev, proxy API calls to the local FastAPI backend.
      '/api': 'http://127.0.0.1:8000',
    },
  },
})
