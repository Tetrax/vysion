import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

const versionPath = resolve(dirname(fileURLToPath(import.meta.url)), '../VERSION')
const version = readFileSync(versionPath, 'utf-8').trim()
const revision = process.env.VITE_VYSION_REVISION ?? 'unknown'

export default defineConfig({
  plugins: [react()],
  define: {
    'import.meta.env.VITE_VYSION_VERSION': JSON.stringify(version),
    'import.meta.env.VITE_VYSION_REVISION': JSON.stringify(revision),
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/setupTests.ts',
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
