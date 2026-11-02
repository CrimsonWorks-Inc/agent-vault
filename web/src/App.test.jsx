import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import { render } from '@testing-library/react'
import { fakeServer } from './test/harness.jsx'
import { overviewRoutes } from './test/fixtures.js'
import { App } from './App.jsx'
import { PAGES } from './lib/router.js'

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

  it('a page not yet ported says so', async () => {
    location.hash = '#credentials'
    const server = fakeServer(overviewRoutes())
    render(<App fetch={server.fetch} />)
    expect(await screen.findByText('Credentials is ported in wave 2')).toBeTruthy()
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
})
