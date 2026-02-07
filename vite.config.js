import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: true,
    allowedHosts: [
      'ipaq-medicare-theories-softball.trycloudflare.com',
    ],
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
})
