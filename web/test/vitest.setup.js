// vitest + jsdom: unmount between tests, and the few browser APIs jsdom lacks.
import { afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'

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
