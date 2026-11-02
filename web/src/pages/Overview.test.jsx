import { describe, expect, it } from 'vitest'
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { fakeAuthenticator, fakeServer, renderWith } from '../test/harness.jsx'
import { overviewRoutes } from '../test/fixtures.js'
import { Overview } from './Overview.jsx'

const settle = (server) => waitFor(() => expect(server.calls.some((c) => c.path === 'notify')).toBe(true))

describe('Overview (parity with app.html)', () => {
  it('shows the daemon, the lock state and the four numbers', async () => {
    const server = fakeServer(overviewRoutes())
    renderWith(<Overview />, { server })
    await screen.findByRole('heading', { name: 'Overview' })
    await settle(server)
    expect(await screen.findByText('unlocked')).toBeTruthy()
    expect(screen.getByText('0.2.0')).toBeTruthy()
    expect(screen.getByText('7411')).toBeTruthy()
    const glance = screen.getByRole('region', { name: 'At a glance' })
    expect(within(glance).getByText('3', { selector: 'dd' })).toBeTruthy() // credentials
    expect(within(glance).getByText('2', { selector: 'dd' })).toBeTruthy() // active sessions
    expect(within(glance).getByText('214')).toBeTruthy()
  })

  it('asks every list with paged=1 and the largest page, so it counts all of it', async () => {
    const server = fakeServer(overviewRoutes())
    renderWith(<Overview />, { server })
    await settle(server)
    for (const path of ['credentials', 'sessions']) {
      const call = server.calls.find((c) => c.path === path)
      expect(call.query).toMatchObject({ paged: '1', limit: '200' })
      expect(call.headers['x-av-ui']).toBe('1')
    }
  })

  it('reads the paged envelope too, walking every page', async () => {
    const pages = {
      undefined: { items: [{ slug: 'a' }, { slug: 'b' }], next_cursor: 'n2', prev_cursor: null, total: 3 },
      n2: { items: [{ slug: 'c' }], next_cursor: null, prev_cursor: 'p', total: 3 },
    }
    const server = fakeServer(overviewRoutes({ 'GET credentials': ({ query }) => pages[query.cursor] }))
    renderWith(<Overview />, { server })
    await settle(server)
    const glance = await screen.findByRole('region', { name: 'At a glance' })
    await waitFor(() => expect(within(glance).getByText('3', { selector: 'dd' })).toBeTruthy())
  })

  it('names the expiring credentials and the waiting decisions', async () => {
    const server = fakeServer(overviewRoutes())
    renderWith(<Overview />, { server, vault: { pending: [{ id: 'r1', kind: 'session' }, { id: 'r2', kind: 'request' }], pendingCount: 2 } })
    await settle(server)
    expect(await screen.findByText('2 credentials expiring.')).toBeTruthy()
    expect(screen.getByText('2 decisions waiting for you.')).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Open Approvals' }).getAttribute('href')).toBe('#approvals')
  })

  it('shows the access review, labels cleaned of bidi controls', async () => {
    const server = fakeServer(overviewRoutes())
    renderWith(<Overview />, { server })
    await settle(server)
    await screen.findByText('Access review')
    expect(screen.getByText('deploy bot evil')).toBeTruthy()
    expect(document.body.textContent).not.toMatch(/\u202e/)
    expect(screen.getByText('never used: DELETE, PUT')).toBeTruthy()
    expect(screen.getByText('quarantined')).toBeTruthy()
  })

  it('a long review shows the first few and the rest on request', async () => {
    const sessions = Array.from({ length: 20 }, (_, i) => ({ id: `s_${i}`, label: `bot ${i}`, unused_methods: ['GET'] }))
    const server = fakeServer(overviewRoutes({ 'GET report/access': { complete: true, sessions, credentials: [] } }))
    renderWith(<Overview />, { server })
    await settle(server)
    await screen.findByText('bot 0')
    expect(screen.queryByText('bot 19')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Show all 20' }))
    expect(screen.getByText('bot 19')).toBeTruthy()
  })

  it('verifies the audit chain on demand', async () => {
    const server = fakeServer(overviewRoutes())
    renderWith(<Overview />, { server })
    await settle(server)
    fireEvent.click(await screen.findByRole('button', { name: /Verify chain/ }))
    expect(await screen.findByText('Chain intact across 214 records')).toBeTruthy()
  })

  it('a locked vault: the banner offers the passphrase, and the 7-day reads are skipped', async () => {
    const server = fakeServer(overviewRoutes({
      'GET status': { locked: true, daemon_version: '0.2.0', gateway_port: 7411, placeholders_live: 0, audit_records: null },
      'GET unlock/state': { locked: true, has_passphrase: true, has_touchid: false },
    }))
    renderWith(<Overview />, { server })
    await settle(server)
    expect(await screen.findByText('The vault is locked.')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Use passphrase' })).toBeTruthy()
    expect(screen.getByText('unavailable while locked')).toBeTruthy()
    expect(server.calls.some((c) => c.path === 'report/access')).toBe(false)
    expect(server.calls.some((c) => c.path === 'audit')).toBe(false)
  })

  it('no authenticator: the page says changes need confirmation and offers to set it up', async () => {
    const server = fakeServer(overviewRoutes({ 'GET presence/state': { enrolled: false } }))
    renderWith(<Overview />, { server })
    expect(await screen.findByText('Changes need confirmation.')).toBeTruthy()
    expect(screen.getByRole('button', { name: /Set up change confirmation/ })).toBeTruthy()
  })

  it('turning tripwires on with no stored rules signs and stores the defaults', async () => {
    const server = fakeServer(overviewRoutes())
    const authenticator = fakeAuthenticator()
    renderWith(<Overview />, { server, authenticator })
    await settle(server)
    await act(async () => { fireEvent.click(await screen.findByRole('button', { name: /Turn on/ })) })
    await waitFor(() => expect(server.calls.some((c) => c.method === 'POST' && c.path === 'tripwires')).toBe(true))
    const challenge = server.calls.find((c) => c.path === 'presence/challenge')
    expect(challenge.body.operation).toEqual({ op: 'tripwires.set', enabled: true, rules: 'defaults' })
    const post = server.calls.find((c) => c.method === 'POST' && c.path === 'tripwires')
    expect(post.body).toMatchObject({ enabled: true, rules: 'defaults', presence: { challengeId: 'ch1' } })
    expect(await screen.findByText('Tripwires on')).toBeTruthy()
  })

  it('panic is confirmed in a page dialog, needs no fingerprint, and reports what it did', async () => {
    const server = fakeServer(overviewRoutes())
    const authenticator = fakeAuthenticator()
    renderWith(<Overview />, { server, authenticator })
    await settle(server)
    fireEvent.click(await screen.findByRole('button', { name: 'Panic' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByLabelText('Lock the vault too'))
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'leaked key' } })
    await act(async () => { fireEvent.click(within(dialog).getByRole('button', { name: 'Panic now' })) })
    await waitFor(() => expect(server.calls.some((c) => c.path === 'panic')).toBe(true))
    expect(server.calls.find((c) => c.path === 'panic').body).toEqual({ lock: true, reason: 'leaked key' })
    expect(authenticator.asked).toHaveLength(0)
    expect(await screen.findByText(/Panic: 2 sessions revoked/)).toBeTruthy()
  })

  it('the webhook is read-only, set from the command line', async () => {
    const server = fakeServer(overviewRoutes())
    renderWith(<Overview />, { server })
    await settle(server)
    expect(await screen.findByText('agent-vault notify set')).toBeTruthy()
  })
})
