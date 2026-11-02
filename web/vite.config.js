// The agent-vault control page, built into src/ui/dist and committed.
//
// The build has to be reproducible byte for byte, because a test rebuilds it
// into a temp dir and compares it with the committed dist (contract U8). So:
// exact devDependency versions, no sourcemaps, no timestamps, Tailwind told
// exactly which files to scan (see styles/theme.css), and no inline script or
// style in index.html, so the server's CSP needs no 'unsafe-inline' (U2).

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { availableParallelism } from 'node:os'

const HERE = dirname(fileURLToPath(import.meta.url))

export default defineConfig(() => ({
  root: HERE,
  base: '/',
  plugins: [react(), tailwindcss()],
  // Escapes stay escapes. Printed as UTF-8, the \u2028 and bidi ranges in
  // lib/text.js became literal characters inside a regex literal, which is a
  // syntax error, and raw bidi controls in a shipped bundle are their own
  // hazard to anyone reading it.
  esbuild: { charset: 'ascii' },
  // Nothing from the environment reaches the bundle.
  envPrefix: 'AV_UI_NEVER_',
  build: {
    outDir: process.env.AV_UI_OUT_DIR ? resolve(process.env.AV_UI_OUT_DIR) : resolve(HERE, '../src/ui/dist'),
    emptyOutDir: true,
    assetsDir: 'assets',
    sourcemap: false,
    manifest: 'manifest.json',
    // Every asset is a file the server can allowlist; nothing becomes a data:
    // URL that would need a looser CSP.
    assetsInlineLimit: 0,
    // The preload polyfill is an inline helper; one entry chunk needs none.
    modulePreload: { polyfill: false },
    cssCodeSplit: false,
    reportCompressedSize: false,
    target: 'es2022',
  },
  server: {
    // npm run dev:ui: the page from Vite, /api from a running `agent-vault ui`
    // (AV_UI_PROXY, default the daemon's UI port 7412). Open the launch link
    // `agent-vault ui` prints first: its av_ui cookie is set for localhost,
    // which Vite's localhost origin shares, so the proxy carries it along
    // (see web/README.md).
    proxy: {
      '/api': {
        target: process.env.AV_UI_PROXY || 'http://localhost:7412',
        changeOrigin: true,
        // The UI server refuses a foreign Origin; present its own.
        configure: (proxy) => {
          proxy.on('proxyReq', (req) => {
            const target = new URL(process.env.AV_UI_PROXY || 'http://localhost:7412')
            req.setHeader('origin', target.origin.replace('127.0.0.1', 'localhost'))
          })
        },
      },
    },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{js,jsx}'],
    setupFiles: ['./test/vitest.setup.js'],
    restoreMocks: true,
    // npm test runs this right after the node suite, and CI and busy laptops
    // run it beside other work. The defaults (5 s per test, one worker per
    // core) gave timeouts under load that passed when run alone, so: a
    // generous per-test budget (a hang still fails, just later), and a capped
    // number of jsdom workers so the suite does not starve itself. The
    // Testing Library wait budget is set in test/vitest.setup.js.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    teardownTimeout: 30_000,
    maxWorkers: Math.max(1, Math.min(4, Math.floor(availableParallelism() / 2))),
  },
}))
