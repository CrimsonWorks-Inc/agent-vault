import { describe, expect, it } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { fakeServer, renderWith } from '../test/harness.jsx'
import { Containment } from './Containment.jsx'

const CHALLENGE = { challengeId: 'ch1', challenge: 'AAEC', allowCredentials: [{ id: 'Y3JlZDE' }], rpId: 'localhost' }
const AN_HOUR_AGO = new Date(Date.now() - 3600e3).toISOString()
const RULES = [
  { id: 'replay', codes: ['AV_PH_REPLAY'], threshold: 1, window_s: 600, action: 'revoke_session' },
  { id: 'bad_location', codes: ['AV_BAD_LOCATION'], threshold: 3, window_s: 600, action: 'revoke_session' },
  { id: 'cross_session', codes: ['AV_PH_CROSS_SESSION'], threshold: 3, window_s: 600, action: 'revoke_session' },
  { id: 'deny_paths', rule_prefix: 'deny_paths:', threshold: 5, window_s: 600, action: 'revoke_session' },
]

function routes(over = {}) {
  return {
    'GET presence/state': { enrolled: true, rpId: 'localhost' },
    'POST presence/challenge': CHALLENGE,
    // The U3 envelope: the rules are the items, over three cursor pages, with
    // enabled / rules_saved / defaults beside each page.
    'GET tripwires': ({ query }) => {
      const pages = { undefined: [RULES[0], RULES[1]], t2: [RULES[2]], t3: [RULES[3]] }
      const next = { undefined: 't2', t2: 't3', t3: null }
      return { items: pages[query.cursor], next_cursor: next[query.cursor], prev_cursor: null, total: RULES.length, enabled: true, rules_saved: true, defaults: [] }
    },
    'GET audit': () => ({ items: [{ seq: 90, kind: 'tripwire.fired', rule_id: 'replay', session_id: 's_9', credential_slug: 'gh-work', count: 1, window_s: 600, action: 'revoke_session', ts: AN_HOUR_AGO }], next_cursor: 'f2', prev_cursor: null, total: null }),
    'GET credentials': {
      items: [
        { slug: 'gh-work', kind: 'github' },
        { slug: 'internal-api', kind: 'http', quarantine: { since: AN_HOUR_AGO, by: 'control', reason_untrusted: 'rotating\u202e after a leak <i>now</i>' } },
      ],
      next_cursor: null, prev_cursor: null, total: 2,
    },
    'POST credentials/quarantine': { quarantined: true, denied_approvals: 2 },
    'POST credentials/release': { released: true },
    'POST panic': { revoked_sessions: 3, denied_approvals: 1, denied_session_requests: 0, locked: true },
    'POST tripwires': { enabled: false },
    ...over,
  }
}

const creds = () => screen.getByRole('table', { name: 'Credentials and their quarantine' })

describe('Containment', () => {
  it('has Panic, the tripwires with their rules, and the recent firings', async () => {
    const server = fakeServer(routes())
    renderWith(<Containment />, { server })
    expect(screen.getByRole('button', { name: 'Panic' })).toBeTruthy()
    expect(await screen.findByText(/A session that trips one of these is revoked/)).toBeTruthy()
    expect(screen.getAllByText('replay').length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: /Turn off/ })).toBeTruthy()
    expect(screen.getByText(/Fired recently/)).toBeTruthy()
    const recent = server.calls.find((c) => c.path === 'audit' && c.query.limit === '5')
    expect(recent.query).toMatchObject({ paged: '1', kind: 'tripwire.fired' })
  })

  it('reads the tripwires paged, walking every cursor page, and keeps every rule in the shape the card reads', async () => {
    const server = fakeServer(routes())
    renderWith(<Containment />, { server })
    expect(await screen.findByText('deny_paths')).toBeTruthy()
    for (const id of ['replay', 'bad_location', 'cross_session', 'deny_paths']) expect(screen.getAllByText(id).length).toBeGreaterThan(0)
    const reads = server.calls.filter((c) => c.method === 'GET' && c.path === 'tripwires')
    expect(reads.map((c) => c.query.cursor)).toEqual([undefined, 't2', 't3'])
    for (const c of reads) expect(c.query).toMatchObject({ paged: '1' })
    fireEvent.click(screen.getByRole('button', { name: /Edit rules/ }))
    const editor = await screen.findByRole('textbox', { name: /Rules \(JSON\)/ })
    expect(JSON.parse(editor.value).map((r) => r.id)).toEqual(RULES.map((r) => r.id))
  })

  it('Panic is confirmed in a page-drawn dialog and sent unsigned', async () => {
    const server = fakeServer(routes())
    renderWith(<Containment />, { server })
    fireEvent.click(screen.getByRole('button', { name: 'Panic' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('checkbox', { name: 'Lock the vault too' }))
    fireEvent.change(within(dialog).getByRole('textbox'), { target: { value: 'agent went off script' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Panic now' }))
    await waitFor(() => expect(server.calls.some((c) => c.path === 'panic')).toBe(true))
    expect(server.calls.find((c) => c.path === 'panic').body).toEqual({ lock: true, reason: 'agent went off script' })
    expect(server.calls.some((c) => c.path === 'presence/challenge')).toBe(false)
    expect(await screen.findByText(/3 sessions revoked · 1 held requests denied · 0 session requests denied · vault locked/)).toBeTruthy()
  })

  it('turning tripwires off is signed over exactly { enabled: false }', async () => {
    const server = fakeServer(routes())
    renderWith(<Containment />, { server })
    fireEvent.click(await screen.findByRole('button', { name: /Turn off/ }))
    await waitFor(() => expect(server.calls.some((c) => c.method === 'POST' && c.path === 'tripwires')).toBe(true))
    expect(server.calls.find((c) => c.path === 'presence/challenge').body.operation).toEqual({ op: 'tripwires.set', enabled: false })
  })

  it('lists credentials paged, with the quarantine reason shown as agent-writable text', async () => {
    const server = fakeServer(routes())
    const { container } = renderWith(<Containment />, { server })
    const t = within(creds())
    expect((await t.findAllByText('internal-api')).length).toBeGreaterThan(0)
    expect(t.getByText('in use')).toBeTruthy()
    expect(t.getByText('quarantined')).toBeTruthy()
    const reason = t.getByText(/rotating/)
    expect(reason.textContent).toBe('rotating after a leak <i>now</i>')
    expect(reason.closest('[data-untrusted]')).toBeTruthy()
    expect(container.querySelector('i')).toBeNull()
    expect(server.calls.find((c) => c.path === 'credentials').query).toMatchObject({ paged: '1', limit: '25' })
  })

  it('quarantine asks for a reason in the page and is sent unsigned', async () => {
    const server = fakeServer(routes())
    renderWith(<Containment />, { server })
    const t = within(creds())
    fireEvent.click(await t.findByRole('button', { name: 'Quarantine gh-work' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByRole('textbox'), { target: { value: 'odd traffic' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Quarantine' }))
    await waitFor(() => expect(server.calls.some((c) => c.path === 'credentials/quarantine')).toBe(true))
    expect(server.calls.find((c) => c.path === 'credentials/quarantine').body).toEqual({ slug: 'gh-work', reason: 'odd traffic' })
    expect(server.calls.some((c) => c.path === 'presence/challenge')).toBe(false)
    expect(await screen.findByText('Quarantined gh-work; 2 held requests denied')).toBeTruthy()
  })

  it('release is signed over exactly { op: cred.release, slug }', async () => {
    const server = fakeServer(routes())
    renderWith(<Containment />, { server })
    const t = within(creds())
    fireEvent.click(await t.findByRole('button', { name: /Release internal-api/ }))
    await waitFor(() => expect(server.calls.some((c) => c.path === 'credentials/release')).toBe(true))
    expect(server.calls.find((c) => c.path === 'presence/challenge').body.operation).toEqual({ op: 'cred.release', slug: 'internal-api' })
    expect(server.calls.find((c) => c.path === 'credentials/release').body).toMatchObject({ slug: 'internal-api' })
    expect(await screen.findByText('Released internal-api')).toBeTruthy()
  })

  it('the whole history of fired tripwires pages through the audit log by kind', async () => {
    const server = fakeServer(routes())
    renderWith(<Containment />, { server })
    const fired = await screen.findByRole('table', { name: 'Tripwires that fired, newest first' })
    expect(await within(fired).findByText('s_9')).toBeTruthy()
    expect(within(fired).getByText('1 in 10m')).toBeTruthy()
    const call = server.calls.find((c) => c.path === 'audit' && c.query.limit === '25')
    expect(call.query).toMatchObject({ kind: 'tripwire.fired', limit: '25' })
    fireEvent.click(screen.getAllByRole('button', { name: 'Next page' }).at(-1))
    await waitFor(() => expect(server.calls.some((c) => c.path === 'audit' && c.query.cursor === 'f2')).toBe(true))
  })

  it('locked: Panic and quarantine stay, the audit history waits for an unlock', async () => {
    const server = fakeServer(routes())
    renderWith(<Containment />, { server, vault: { locked: true } })
    expect(screen.getByRole('button', { name: 'Panic' })).toBeTruthy()
    expect(screen.getByText('Unlock to read the audit log.')).toBeTruthy()
    await within(creds()).findAllByText('internal-api')
    expect(server.calls.some((c) => c.path === 'audit')).toBe(false)
  })
})
