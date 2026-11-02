// vitest + jsdom: unmount between tests, and the few browser APIs jsdom lacks.
import { afterEach } from 'vitest'
import { cleanup, configure } from '@testing-library/react'

// waitFor and findBy* give up after 1 s by default. A loaded machine can take
// longer than that to run a fake server round trip and a React commit, so the
// budget is 10 s; a test that waits for something that never comes still
// fails, inside vitest's own 30 s test budget (vite.config.js).
configure({ asyncUtilTimeout: 10_000 })

afterEach(() => {
  cleanup()
  try { globalThis.localStorage?.clear() } catch { /* nothing stored */ }
  globalThis.location.hash = ''
})

if (!globalThis.ResizeObserver) {
  globalThis.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} }
}
if (!globalThis.matchMedia) {
  globalThis.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} })
}
if (!globalThis.Element.prototype.scrollIntoView) globalThis.Element.prototype.scrollIntoView = () => {}
