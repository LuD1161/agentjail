import path from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: '../static/dist',
    // Must stay false: emptying the dir deletes the tracked .gitkeep that keeps
    // `//go:embed all:static/dist` matching on a clean clone. `make ui` scrubs
    // stale assets instead, preserving the placeholder.
    emptyOutDir: false,
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:9101',
      '/events': 'http://127.0.0.1:9101',
    },
  },
})
