import process from 'node:process'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  // GitHub Pages serves the site under /<repo-name>/, so the deploy
  // workflow sets VITE_BASE_PATH=/mini-soc/. Local dev stays at /.
  base: process.env.VITE_BASE_PATH || '/',
  plugins: [
    react(),
    tailwindcss(),
  ],
  server: {
    host: '0.0.0.0', // allow access from Docker host
    port: 5173
  }
})
