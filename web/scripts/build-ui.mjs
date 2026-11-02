// Build the page into a directory, by running Vite in a child process. Used
// by check-dist.mjs and by the drift test, which both build somewhere other
// than src/ui/dist so that nothing but `npm run build:ui` ever writes there.

import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')

/** Build into `outDir`; throws with Vite's output when the build fails. */
export function buildUi(outDir) {
  const vite = join(ROOT, 'node_modules', 'vite', 'bin', 'vite.js')
  const r = spawnSync(process.execPath, [vite, 'build', '--config', join(ROOT, 'web', 'vite.config.js'), '--logLevel', 'error'], {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env, AV_UI_OUT_DIR: outDir, NODE_ENV: 'production' },
  })
  if (r.error) throw new Error(`could not run vite: ${r.error.message}. Run npm ci first.`)
  if (r.status !== 0) throw new Error(`the UI build failed:\n${r.stdout}\n${r.stderr}`)
  return outDir
}
