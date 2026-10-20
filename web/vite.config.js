import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from '@tailwindcss/vite'

// `npm run dev` proxies the API to a locally running `mini-net-man -mock`.
export default defineConfig({
  plugins: [tailwindcss(), svelte()],
  server: { proxy: { '/api': 'http://127.0.0.1:8080' } },
  build: { outDir: 'dist', emptyOutDir: true },
})
