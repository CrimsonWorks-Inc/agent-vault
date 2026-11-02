import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import { render } from '@testing-library/react'
import { fakeServer } from './test/harness.jsx'
import { overviewRoutes } from './test/fixtures.js'
import { App } from './App.jsx'
import { PAGES } from './lib/router.js'
import { act, fireEvent } from '@testing-library/react'
import { PAGE_COMPONENTS } from './pages/index.js'
import { GatedButton } from './components/ui/GatedButton.jsx'
import { useApi } from './hooks/useApi.js'
import { usePresence } from './hooks/usePresence.js'
import { queryBound } from './lib/presence.js'
import { fakeAuthenticator } from './test/harness.jsx'

/** A page with a gated button, standing in for a ported page on a deep link. */
function RevokePage() {
  const api = useApi()
  const presence = usePresence()
  const r = queryBound('DELETE sessions', { sid: 's_42' })
  return (
    <>
      <p>{presence.known ? (presence.enrolled ? 'authenticator: enrolled' : 'authenticator: none') : 'authenticator: unknown'}</p>
      <GatedButton operation={r.operation} label="revoke session s_42" send={(proof) => api.del(r.path, r.query, { presence: proof })}>Revoke</GatedButton>
    </>
  )
}

describe('App shell', () => {
  it('the sidebar lists every page, and the header shows lock state and what is waiting', async () => {
    const server = fakeServer(overviewRoutes({ 'GET pending': [{ id: 'r1', kind: 'request' }, { id: 'r2', kind: 'session' }] }))
    render(<App fetch={server.fetch} />)
    const nav = (await screen.findAllByRole('navigation', { name: 'Pages' }))[0]
    for (const p of PAGES) expect(within(nav).getByRole('link', { name: new RegExp(p.label) })).toBeTruthy()
    expect(within(nav).getByRole('link', { name: /Overview/ }).getAttribute('aria-current')).toBe('page')
    await waitFor(() => expect(screen.getByText((_, el) => el?.textContent === 'Vault unlocked' && el.tagName === 'SPAN' && el.className.includes('rounded-pill'))).toBeTruthy())
    expect(within(nav).getByRole('link', { name: /Approvals/ }).textContent).toContain('2')
    expect(screen.getByRole('link', { name: /^2 waiting/ })).toBeTruthy()
  })

  // Was "a page not yet ported says so"; Credentials is ported now (pages-a).
  it('the hash opens that page, which asks for its list paged', async () => {
    location.hash = '#credentials'
    const server = fakeServer(overviewRoutes())
    render(<App fetch={server.fetch} />)
    expect(await screen.findByRole('heading', { name: 'Credentials', level: 1 })).toBeTruthy()
    await waitFor(() => expect(server.calls.some((c) => c.path === 'credentials' && c.query.paged === '1')).toBe(true))
  })

  it('a lost session shows "No session", and the page stops asking', async () => {
    const server = fakeServer({ ...overviewRoutes(), 'GET status': { __status: 401, body: { error: 'not authenticated' } } })
    render(<App fetch={server.fetch} />)
    expect(await screen.findByRole('heading', { name: 'No session' })).toBeTruthy()
  })

  it('an unreachable daemon shows "Cannot reach the daemon" with a way to retry', async () => {
    const server = fakeServer({ ...overviewRoutes(), 'GET status': { __status: 503, body: { error: 'connect ENOENT /tmp/av/control.sock' } } })
    render(<App fetch={server.fetch} />)
    expect(await screen.findByRole('heading', { name: 'Cannot reach the daemon' })).toBeTruthy()
    expect(screen.getByText('connect ENOENT /tmp/av/control.sock')).toBeTruthy()
    expect(screen.getByRole('button', { name: /Try again/ })).toBeTruthy()
  })

  it('a UI server that went away says so', async () => {
    const fetch = async () => { throw new TypeError('Failed to fetch') }
    render(<App fetch={fetch} />)
    expect(await screen.findByRole('heading', { name: 'Cannot reach the UI server' })).toBeTruthy()
  })

  it('a deep link to a page with a gated button sees the real enrolment, without visiting Overview', async () => {
    location.hash = '#sessions'
    const authenticator = fakeAuthenticator()
    Object.defineProperty(globalThis.navigator, 'credentials', { value: authenticator.credentials, configurable: true })
    try {
      const server = fakeServer({
        ...overviewRoutes(),
        'GET presence/state': { enrolled: true, credentialId: 'c1', rpId: 'localhost' },
        'POST presence/challenge': { challengeId: 'ch1', challenge: 'AAEC', allowCredentials: [{ id: 'Y3JlZDE' }], rpId: 'localhost' },
        'DELETE sessions': { ok: true },
      })
      render(<App fetch={server.fetch} pages={{ ...PAGE_COMPONENTS, sessions: RevokePage }} />)
      expect(await screen.findByText('authenticator: enrolled')).toBeTruthy()
      const button = screen.getByRole('button', { name: /Revoke/ })
      expect(button.disabled).toBe(false)
      await act(async () => { fireEvent.click(button) })
      await waitFor(() => expect(server.calls.some((c) => c.method === 'DELETE' && c.path === 'sessions')).toBe(true))
      expect(screen.queryByText(/No authenticator enrolled/)).toBeNull()
      expect(server.calls.find((c) => c.path === 'presence/challenge').body.operation).toEqual({ op: 'session.revoke', sid: 's_42' })
      expect(server.calls.some((c) => c.path === 'status')).toBe(false)
    } finally {
      delete globalThis.navigator.credentials
    }
  })

  it('a gated click that beats the first enrolment answer asks for it instead of refusing', async () => {
    location.hash = '#sessions'
    const authenticator = fakeAuthenticator()
    Object.defineProperty(globalThis.navigator, 'credentials', { value: authenticator.credentials, configurable: true })
    let release
    const gate = new Promise((r) => { release = r })
    let asked = 0
    try {
      const server = fakeServer({
        ...overviewRoutes(),
        // The first answer (the shell's, on mount) is held back until after the click.
        'GET presence/state': async () => { if (++asked === 1) await gate; return { enrolled: true, credentialId: 'c1', rpId: 'localhost' } },
        'POST presence/challenge': { challengeId: 'ch1', challenge: 'AAEC', allowCredentials: [{ id: 'Y3JlZDE' }], rpId: 'localhost' },
        'DELETE sessions': { ok: true },
      })
      render(<App fetch={server.fetch} pages={{ ...PAGE_COMPONENTS, sessions: RevokePage }} />)
      expect(await screen.findByText('authenticator: unknown')).toBeTruthy()
      await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Revoke/ })) })
      await waitFor(() => expect(server.calls.some((c) => c.method === 'DELETE' && c.path === 'sessions')).toBe(true))
      expect(screen.queryByText(/No authenticator enrolled/)).toBeNull()
      release()
    } finally {
      release?.()
      delete globalThis.navigator.credentials
    }
  })
})
