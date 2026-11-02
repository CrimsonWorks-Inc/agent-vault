import { describe, expect, it } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { fakeAuthenticator, fakeServer, renderWith } from '../test/harness.jsx'
import { operationFor } from '../lib/presence.js'
import { parseOverrides } from '../../../src/pending.js'
import { Approvals } from './Approvals.jsx'

const CHALLENGE = { challengeId: 'ch1', challenge: 'AAEC', allowCredentials: [{ id: 'Y3JlZDE' }], rpId: 'localhost' }
const NOW = new Date().toISOString()

const SESSION_ITEM = {
  id: 'sr_1', kind: 'session', headline: 'gh-work GET /repos/acme/app/** for 60m', created_at: NOW,
  claim: 'Need to open a PR\u202e and nothing else. <b>Approve</b>',
  caution: 'This grants hours of access, not one call.',
  narrowable: ['methods', 'paths', 'budget', 'uses', 'ttl_minutes'],
  owner_settable: ['approval', 'infinite'],
  proposal: { methods: ['GET'], paths: ['/repos/acme/app/**'], template: 'gh-read', template_version: 3 },
}
const REQUEST_ITEM = {
  id: 'ap_2', kind: 'request', headline: 'POST api.github.com/repos/acme/app/issues', created_at: NOW,
  narrowable: [], owner_settable: [], proposal: {},
  preview: {
    method: 'POST', host: 'api.github.com', path: '/repos/acme/app/issues', content_type: 'application/json',
    body: { text: '{"title":"<img src=x onerror=alert(1)>\u202egnp.exe"}', bytes: 52 },
    query: [['state', 'open']], headers: [['x-trace', 'abc']],
    placeholders: [{ label: 'gh-work', location: 'header:authorization' }],
  },
}

function routes(over = {}) {
  return {
    'GET presence/state': { enrolled: true, rpId: 'localhost' },
    'POST presence/challenge': CHALLENGE,
    'GET pending': { items: [SESSION_ITEM, REQUEST_ITEM], next_cursor: null, prev_cursor: null, total: 2 },
    'POST session-requests/decide': { state: 'approved', recorded: null },
    'POST approvals': { ok: true },
    'POST pending/decide-many': { decided: [{ id: 'sr_1', outcome: 'decided' }, { id: 'ap_2', outcome: 'skipped' }] },
    ...over,
  }
}

const challenges = (server) => server.calls.filter((c) => c.path === 'presence/challenge')
const table = () => screen.getByRole('table', { name: 'Waiting decisions' })
const loaded = () => waitFor(() => expect(within(table()).getAllByText('gh-work GET /repos/acme/app/** for 60m').length).toBeGreaterThan(0))

describe('Approvals (parity with app.html)', () => {
  it('asks GET pending with paged=1 and shows the empty state when nothing waits', async () => {
    const server = fakeServer(routes({ 'GET pending': { items: [], next_cursor: null, prev_cursor: null, total: 0 } }))
    renderWith(<Approvals />, { server, vault: { pendingCount: 0 } })
    expect(await screen.findByText('Nothing waiting.')).toBeTruthy()
    expect(screen.getByText('Requests an agent cannot make without you.')).toBeTruthy()
    const call = server.calls.find((c) => c.path === 'pending')
    expect(call.query).toMatchObject({ paged: '1', limit: '25' })
  })

  it('shows a loading state, then each item with its kind, id, headline, template and caution', async () => {
    const server = fakeServer(routes())
    renderWith(<Approvals />, { server, vault: { pendingCount: 2 } })
    expect(screen.getAllByText('Loading').length).toBeGreaterThan(0)
    await loaded()
    const t = within(table())
    expect(screen.getByText('2 waiting')).toBeTruthy()
    expect(t.getByText('session requested')).toBeTruthy()
    expect(t.getByText('held request')).toBeTruthy()
    expect(t.getByText('gh-read')).toBeTruthy()
    expect(t.getByText('This grants hours of access, not one call.')).toBeTruthy()
    expect(t.getByRole('button', { name: /Approve session/ })).toBeTruthy()
    expect(t.getByRole('button', { name: /Approve once/ })).toBeTruthy()
  })

  it('shows the agent\'s claim and the request body as text, marked, with bidi stripped and never as HTML', async () => {
    const server = fakeServer(routes())
    const { container } = renderWith(<Approvals />, { server })
    await loaded()
    const claim = within(table()).getByText(/Need to open a PR/)
    expect(claim.textContent).toBe('Need to open a PR and nothing else. <b>Approve</b>')
    expect(claim.closest('[data-untrusted]')).toBeTruthy()
    expect(container.querySelector('b')).toBeNull()
    fireEvent.click(within(table()).getByRole('button', { name: /What it sends/ }))
    const body = await within(table()).findByText(/onerror/)
    expect(body.textContent).not.toMatch(/\u202e/)
    expect(body.closest('[data-untrusted]')).toBeTruthy()
    expect(container.querySelector('img')).toBeNull()
    expect(within(table()).getByText(/gh-work @ header:authorization/)).toBeTruthy()
  })

  it('approves a session request with the narrowing typed, parsed by parseOverrides and signed as sent', async () => {
    const auth = fakeAuthenticator()
    const server = fakeServer(routes())
    renderWith(<Approvals />, { server, authenticator: auth })
    await loaded()
    const card = within(table()).getByRole('article', { name: 'Session requested sr_1' })
    fireEvent.click(within(card).getByRole('button', { name: /Narrow it before approving/ }))
    fireEvent.change(within(card).getByPlaceholderText('GET'), { target: { value: 'get' } })
    fireEvent.change(within(card).getByPlaceholderText('/repos/acme/app/**'), { target: { value: '/repos/acme/app/pulls/**' } })
    expect(within(card).getByRole('button', { name: /Narrow it before approving \(2 narrowed\)/ })).toBeTruthy()
    fireEvent.click(within(card).getByRole('button', { name: /Approve session/ }))
    await waitFor(() => expect(server.calls.some((c) => c.path === 'session-requests/decide')).toBe(true))

    const overrides = parseOverrides({ methods: 'get', paths: '/repos/acme/app/pulls/**', approval: '' })
    expect(challenges(server)[0].body.operation).toEqual(await operationFor('session_request.decide', { id: 'sr_1', granted: true, ...overrides }))
    const sent = server.calls.find((c) => c.path === 'session-requests/decide').body
    expect(sent).toMatchObject({ id: 'sr_1', granted: true, overrides })
    expect(sent.presence.challengeId).toBe('ch1')
    expect(auth.asked).toHaveLength(1)
    expect(await screen.findByText('Approved')).toBeTruthy()
  })

  it('names the decision on the page before the platform dialog opens', async () => {
    let shown = null
    const auth = fakeAuthenticator({ onGet: () => { shown = document.body.textContent } })
    const server = fakeServer(routes())
    renderWith(<Approvals />, { server, authenticator: auth })
    await loaded()
    const card = within(table()).getByRole('article', { name: 'Held request ap_2' })
    fireEvent.click(within(card).getByRole('button', { name: /Deny/ }))
    await waitFor(() => expect(auth.asked).toHaveLength(1))
    expect(shown).toContain('deny request ap_2')
  })

  it('denies a held request with exactly app.html\'s operation and body', async () => {
    const server = fakeServer(routes())
    renderWith(<Approvals />, { server })
    await loaded()
    const card = within(table()).getByRole('article', { name: 'Held request ap_2' })
    fireEvent.click(within(card).getByRole('button', { name: /Deny/ }))
    await waitFor(() => expect(server.calls.some((c) => c.path === 'approvals')).toBe(true))
    expect(challenges(server)[0].body.operation).toEqual({ op: 'approval.deny', granted: false, id: 'ap_2' })
    const sent = server.calls.find((c) => c.path === 'approvals').body
    expect(Object.keys(sent).sort()).toEqual(['granted', 'id', 'presence'])
    expect(sent).toMatchObject({ id: 'ap_2', granted: false })
  })

  it('sends the owner options as chosen: approval and no expiry', async () => {
    const server = fakeServer(routes())
    renderWith(<Approvals />, { server })
    await loaded()
    const card = within(table()).getByRole('article', { name: 'Session requested sr_1' })
    fireEvent.click(within(card).getByRole('checkbox', { name: 'No expiry' }))
    fireEvent.click(within(card).getByRole('button', { name: /Approve session/ }))
    await waitFor(() => expect(server.calls.some((c) => c.path === 'session-requests/decide')).toBe(true))
    expect(server.calls.find((c) => c.path === 'session-requests/decide').body.overrides).toEqual({ infinite: true })
    expect(challenges(server)[0].body.operation).toEqual({ op: 'session_request.decide', granted: true, id: 'sr_1', infinite: true })
  })

  it('a narrowing that does not parse sends nothing and asks for no signature', async () => {
    const server = fakeServer(routes())
    renderWith(<Approvals />, { server })
    await loaded()
    const card = within(table()).getByRole('article', { name: 'Session requested sr_1' })
    fireEvent.click(within(card).getByRole('button', { name: /Narrow it before approving/ }))
    fireEvent.change(within(card).getAllByRole('textbox')[2], { target: { value: 'lots' } }) // budget
    fireEvent.click(within(card).getByRole('button', { name: /Approve session/ }))
    expect(await screen.findByText(/That narrowing does not parse, so nothing was sent/)).toBeTruthy()
    expect(challenges(server)).toHaveLength(0)
    expect(server.calls.some((c) => c.path === 'session-requests/decide')).toBe(false)
  })

  it('decides the ticked items, and only those, under one signature', async () => {
    const server = fakeServer(routes())
    renderWith(<Approvals />, { server })
    await loaded()
    expect(screen.queryByRole('region', { name: 'Decide the selected' })).toBeNull()
    fireEvent.click(within(table()).getAllByRole('checkbox', { name: 'Select sr_1' })[0])
    fireEvent.click(within(table()).getAllByRole('checkbox', { name: 'Select ap_2' })[0])
    const bar = screen.getByRole('region', { name: 'Decide the selected' })
    expect(within(bar).getByTestId('bulk-count').textContent).toBe('2')
    fireEvent.click(within(bar).getByRole('button', { name: /Approve selected/ }))
    await waitFor(() => expect(server.calls.some((c) => c.path === 'pending/decide-many')).toBe(true))
    const decisions = [{ id: 'sr_1', kind: 'session', granted: true }, { id: 'ap_2', kind: 'request', granted: true }]
    expect(challenges(server)[0].body.operation).toEqual(await operationFor('pending.decide_many', { decisions }))
    expect(server.calls.find((c) => c.path === 'pending/decide-many').body.decisions).toEqual(decisions)
    expect(await screen.findByText('1 approved, 1 no longer pending')).toBeTruthy()
  })

  it('Clear empties the selection and hides the bar', async () => {
    const server = fakeServer(routes())
    renderWith(<Approvals />, { server })
    await loaded()
    fireEvent.click(within(table()).getAllByRole('checkbox', { name: 'Select sr_1' })[0])
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }))
    expect(screen.queryByRole('region', { name: 'Decide the selected' })).toBeNull()
  })

  it('pages with the server\'s cursor and searches with q', async () => {
    const pages = {
      undefined: { items: [SESSION_ITEM], next_cursor: 'c2', prev_cursor: null, total: 2 },
      c2: { items: [REQUEST_ITEM], next_cursor: null, prev_cursor: 'c1', total: 2 },
    }
    const server = fakeServer(routes({ 'GET pending': ({ query }) => pages[query.cursor] }))
    renderWith(<Approvals />, { server })
    await loaded()
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
    await waitFor(() => expect(server.calls.some((c) => c.path === 'pending' && c.query.cursor === 'c2')).toBe(true))
    expect(await within(table()).findByText('held request')).toBeTruthy()
    fireEvent.change(screen.getByRole('searchbox', { name: 'Search waiting decisions' }), { target: { value: 'ap_2' } })
    await waitFor(() => expect(server.calls.some((c) => c.path === 'pending' && c.query.q === 'ap_2' && !c.query.cursor)).toBe(true))
  })

  it('opens on the deep-linked item by searching for its id', async () => {
    const server = fakeServer(routes())
    renderWith(<Approvals rest="ap_2" />, { server })
    expect(await screen.findByText('Showing ap_2')).toBeTruthy()
    await waitFor(() => expect(server.calls.some((c) => c.path === 'pending' && c.query.q === 'ap_2')).toBe(true))
  })

  it('says so when the list cannot be read', async () => {
    const server = fakeServer(routes({ 'GET pending': { __status: 500, body: { error: 'control socket hiccup' } } }))
    renderWith(<Approvals />, { server })
    expect(await screen.findByText('Could not read what is waiting.')).toBeTruthy()
    expect(screen.getByText('control socket hiccup')).toBeTruthy()
  })
})
