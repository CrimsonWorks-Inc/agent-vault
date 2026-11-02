import { describe, expect, it, vi } from 'vitest'
import { act, configure, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { fakeAuthenticator, fakeServer, renderWith } from '../test/harness.jsx'
import { operationFor } from '../lib/presence.js'
import { CREDS, callsTo, challengeOf, envelope, pagesRoutes } from './fixtures.pages-a.js'
import { Credentials } from './Credentials.jsx'

const loaded = () => screen.findAllByText('gh-work')
// Whole pages over a fake server: generous when the machine is busy.
vi.setConfig({ testTimeout: 30000 })
configure({ asyncUtilTimeout: 5000 })

const click = async (el) => { await act(async () => { fireEvent.click(el) }) }
const type = (el, value) => fireEvent.change(el, { target: { value } })
const enrolled = (server) => waitFor(() => expect(callsTo(server, 'GET', 'presence/state').length).toBeGreaterThan(0))

describe('Credentials: states', () => {
  it('shows a skeleton while loading, then every row with what to notice', async () => {
    let release
    const gate = new Promise((r) => { release = r })
    const server = fakeServer(pagesRoutes({ 'GET credentials': async (c) => { await gate; return envelope(CREDS)(c) } }))
    renderWith(<Credentials />, { server })
    expect(await screen.findByRole('heading', { name: 'Credentials', level: 1 })).toBeTruthy()
    expect(screen.getAllByText('Loading').length).toBeGreaterThan(0)
    await act(async () => { release() })
    await loaded()
    expect(screen.getAllByText('healthy').length).toBeGreaterThan(0)
    expect(screen.getAllByText('quarantined').length).toBeGreaterThan(0)
    expect(screen.getAllByText('expires in 3d').length).toBeGreaterThan(0)
    expect(screen.getAllByText('pinned: api.github.com (2)').length).toBeGreaterThan(0)
    expect(screen.getAllByText('quarantined 1h ago by tripwire (tripwire replay)').length).toBeGreaterThan(0)
    expect(screen.getByText('3 credentials')).toBeTruthy()
  })

  it('empty: says so and points at the form', async () => {
    const server = fakeServer(pagesRoutes({ 'GET credentials': envelope([]) }))
    renderWith(<Credentials />, { server })
    expect(await screen.findByText('No credentials yet')).toBeTruthy()
    expect(screen.getByText('Add one below.')).toBeTruthy()
    expect(screen.getByRole('heading', { name: 'Add a credential' })).toBeTruthy()
  })

  it('error: says what the server said, and asks again', async () => {
    let fail = true
    const server = fakeServer(pagesRoutes({ 'GET credentials': (c) => (fail ? { __status: 500, body: { error: 'daemon said no' } } : envelope(CREDS)(c)) }))
    renderWith(<Credentials />, { server })
    expect(await screen.findByText('Could not read the credentials.')).toBeTruthy()
    expect(screen.getByText('daemon said no')).toBeTruthy()
    fail = false
    await click(screen.getByRole('button', { name: 'Try again' }))
    await loaded()
  })

  it('the quarantine reason is agent text: stripped of bidi, never HTML', async () => {
    const server = fakeServer(pagesRoutes())
    const { container } = renderWith(<Credentials />, { server })
    await loaded()
    const reason = container.querySelector('[data-untrusted]')
    expect(reason.textContent).toContain('leaked evil <b>bold</b>')
    expect(reason.textContent).not.toMatch(/[\u202a-\u202e]/)
    expect(reason.querySelector('b')).toBeNull()
    expect(reason.textContent).toContain('Written by whoever quarantined it, not verified')
  })
})

describe('Credentials: paging (U3)', () => {
  const many = Array.from({ length: 60 }, (_, i) => ({ slug: `c-${String(i).padStart(2, '0')}`, kind: 'http', fields: [{}] }))

  it('asks with paged=1 and the page size, follows next_cursor, and resets on search', async () => {
    const server = fakeServer(pagesRoutes({ 'GET credentials': envelope(many) }))
    renderWith(<Credentials />, { server })
    await screen.findAllByText('c-00')
    const first = callsTo(server, 'GET', 'credentials')[0]
    expect(first.query).toEqual({ paged: '1', limit: '25' })
    expect(screen.getByText('Showing 1–25 of 60')).toBeTruthy()
    await click(screen.getByRole('button', { name: 'Next page' }))
    await screen.findAllByText('c-25')
    expect(callsTo(server, 'GET', 'credentials').at(-1).query).toEqual({ paged: '1', limit: '25', cursor: 'srv-25' })
    expect(screen.getByText('Showing 26–50 of 60')).toBeTruthy()
    type(screen.getByRole('searchbox', { name: 'Search credentials' }), 'c-4')
    await waitFor(() => expect(callsTo(server, 'GET', 'credentials').at(-1).query).toEqual({ paged: '1', limit: '25', q: 'c-4' }))
  })
})

describe('Credentials: every change is signed over exactly what is sent', () => {
  it('Store credential: cred.add with the value by digest, then the value is cleared', async () => {
    const server = fakeServer(pagesRoutes({ 'POST credentials': { slug: 'new-one' } }))
    renderWith(<Credentials />, { server })
    await loaded(); await enrolled(server)
    type(screen.getByPlaceholderText('gh-frozencrow'), 'new-one')
    const value = screen.getByPlaceholderText('paste the token; it is not echoed and never returned')
    type(value, 'sk-test-123')
    await click(screen.getByRole('button', { name: /Store credential/ }))
    const op = await challengeOf(server)
    expect(op).toEqual(await operationFor('cred.add', { slug: 'new-one', kind: 'github', value: 'sk-test-123' }))
    expect(JSON.stringify(op)).not.toContain('sk-test-123')
    await waitFor(() => expect(callsTo(server, 'POST', 'credentials')).toHaveLength(1))
    expect(callsTo(server, 'POST', 'credentials')[0].body).toMatchObject({ slug: 'new-one', kind: 'github', value: 'sk-test-123', presence: { challengeId: 'ch1' } })
    await screen.findByText('Stored new-one')
    expect(value.value).toBe('')
  })

  it('Store credential without a value asks for one and spends no tap', async () => {
    const authenticator = fakeAuthenticator()
    const server = fakeServer(pagesRoutes())
    renderWith(<Credentials />, { server, authenticator })
    await loaded(); await enrolled(server)
    type(screen.getByPlaceholderText('gh-frozencrow'), 'x')
    await click(screen.getByRole('button', { name: /Store credential/ }))
    expect(await screen.findByText('A name and a value are both required')).toBeTruthy()
    expect(authenticator.asked).toHaveLength(0)
  })

  it('Remove: a page-drawn confirm, then cred.remove and DELETE credentials?slug', async () => {
    const server = fakeServer(pagesRoutes({ 'DELETE credentials': { ok: true } }))
    renderWith(<Credentials />, { server })
    await loaded(); await enrolled(server)
    await click(screen.getAllByRole('button', { name: 'More actions for gh-work' })[0])
    await click(await screen.findByRole('menuitem', { name: 'Remove' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Every grant using it is revoked.')).toBeTruthy()
    await click(within(dialog).getByRole('button', { name: 'Remove with Touch ID' }))
    expect(await challengeOf(server)).toEqual({ op: 'cred.remove', slug: 'gh-work' })
    await waitFor(() => expect(callsTo(server, 'DELETE', 'credentials')).toHaveLength(1))
    const del = callsTo(server, 'DELETE', 'credentials')[0]
    expect(del.query).toEqual({ slug: 'gh-work' })
    expect(Object.keys(del.body)).toEqual(['presence'])
  })

  it('Release: cred.release, POST credentials/release {slug, presence}', async () => {
    const server = fakeServer(pagesRoutes({ 'POST credentials/release': { ok: true } }))
    renderWith(<Credentials />, { server })
    await loaded(); await enrolled(server)
    await click(screen.getAllByRole('button', { name: 'Release old-hook' })[0])
    expect(await challengeOf(server)).toEqual({ op: 'cred.release', slug: 'old-hook' })
    await waitFor(() => expect(callsTo(server, 'POST', 'credentials/release')[0]?.body).toMatchObject({ slug: 'old-hook', presence: { challengeId: 'ch1' } }))
    expect(await screen.findByText('Released old-hook')).toBeTruthy()
  })

  it('Quarantine is open (F16): asks a reason, sends no signature', async () => {
    const authenticator = fakeAuthenticator()
    const server = fakeServer(pagesRoutes({ 'POST credentials/quarantine': { denied_approvals: 2 } }))
    renderWith(<Credentials />, { server, authenticator })
    await loaded()
    await click(screen.getAllByRole('button', { name: 'More actions for gh-work' })[0])
    await click(await screen.findByRole('menuitem', { name: 'Quarantine' }))
    const dialog = await screen.findByRole('dialog')
    type(within(dialog).getByRole('textbox'), 'looks leaked')
    await click(within(dialog).getByRole('button', { name: 'Quarantine' }))
    await waitFor(() => expect(callsTo(server, 'POST', 'credentials/quarantine')[0]?.body).toEqual({ slug: 'gh-work', reason: 'looks leaked' }))
    expect(await screen.findByText('Quarantined gh-work; 2 held requests denied')).toBeTruthy()
    expect(authenticator.asked).toHaveLength(0)
  })

  it('Rotate: the value is typed, the exact operation is shown, and only "Sign it" signs', async () => {
    const authenticator = fakeAuthenticator()
    const server = fakeServer(pagesRoutes({ 'POST credentials/rotate': { rotated: { version: 3 }, invalidated_approvals: 1 } }))
    renderWith(<Credentials />, { server, authenticator })
    await loaded(); await enrolled(server)
    await click(screen.getAllByRole('button', { name: 'Rotate gh-work' })[0])
    let dialog = await screen.findByRole('dialog')
    await click(within(dialog).getByRole('button', { name: 'Next' }))
    expect(await screen.findByText('No value was typed. Nothing was changed.')).toBeTruthy()
    type(within(dialog).getByLabelText('New value for gh-work (not echoed)'), 'sk-test-new')
    await click(within(dialog).getByRole('button', { name: 'Next' }))
    dialog = await screen.findByRole('dialog')
    const shown = dialog.querySelector('[data-operation]').textContent
    const expected = await operationFor('cred.rotate', { slug: 'gh-work', value: 'sk-test-new', mode: 'keep', retire_hours: 24 })
    expect(JSON.parse(shown)).toEqual(expected)
    expect(shown).not.toContain('sk-test-new')
    expect(authenticator.asked).toHaveLength(0)
    await click(within(dialog).getByRole('button', { name: /Sign it/ }))
    expect(await challengeOf(server)).toEqual(expected)
    await waitFor(() => expect(callsTo(server, 'POST', 'credentials/rotate')[0]?.body).toMatchObject({ slug: 'gh-work', value: 'sk-test-new', mode: 'keep', retire_hours: 24 }))
    expect(await screen.findByText('Rotated gh-work to version 3; 1 held request denied')).toBeTruthy()
  })

  it('Scrub patterns: add (cred.scrub_add with the sample) and remove (cred.scrub_remove)', async () => {
    const server = fakeServer(pagesRoutes({
      'POST credentials/scrub': { id: 'sp_2', sample: { matches: 1, redacted: 'key=[redacted]' } },
      'DELETE credentials/scrub': { ok: true },
    }))
    renderWith(<Credentials />, { server })
    await loaded(); await enrolled(server)
    await click(screen.getAllByRole('button', { name: 'More actions for gh-work' })[0])
    await click(await screen.findByRole('menuitem', { name: 'Scrub patterns and expiry' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Scrub patterns (1)')).toBeTruthy()
    await click(within(dialog).getByRole('button', { name: /Add pattern/ }))
    expect(await screen.findByText('Type a pattern first')).toBeTruthy()
    type(within(dialog).getByLabelText('Pattern'), 'acme_[A-Za-z0-9]{20}')
    type(within(dialog).getByLabelText(/Try on text/), 'key=acme_aaaaaaaaaaaaaaaaaaaa')
    await click(within(dialog).getByRole('button', { name: /Add pattern/ }))
    expect(await challengeOf(server)).toEqual({ op: 'cred.scrub_add', slug: 'gh-work', pattern: 'acme_[A-Za-z0-9]{20}', sample: 'key=acme_aaaaaaaaaaaaaaaaaaaa' })
    expect(await screen.findByText('Added sp_2 to gh-work')).toBeTruthy()
    expect(await within(dialog).findByText('key=[redacted]')).toBeTruthy()
    await click(within(dialog).getByRole('button', { name: 'Remove pattern sp_1' }))
    expect(await challengeOf(server, 1)).toEqual({ op: 'cred.scrub_remove', slug: 'gh-work', id: 'sp_1' })
    await waitFor(() => expect(callsTo(server, 'DELETE', 'credentials/scrub')[0]?.query).toEqual({ slug: 'gh-work', id: 'sp_1' }))
  })

  it('Expiry: set (midnight UTC) and clear, both cred.expiry_set', async () => {
    const server = fakeServer(pagesRoutes({ 'POST credentials/expiry': { ok: true } }))
    renderWith(<Credentials />, { server })
    await loaded(); await enrolled(server)
    await click(screen.getAllByRole('button', { name: 'More actions for openai' })[0])
    await click(await screen.findByRole('menuitem', { name: 'Scrub patterns and expiry' }))
    const dialog = await screen.findByRole('dialog')
    type(within(dialog).getByLabelText('Expires on'), '2027-03-04')
    await click(within(dialog).getByRole('button', { name: /Set expiry/ }))
    expect(await challengeOf(server)).toEqual({ op: 'cred.expiry_set', slug: 'openai', expires_at: '2027-03-04T00:00:00.000Z' })
    expect(await screen.findByText('openai expires 2027-03-04')).toBeTruthy()
    await click(within(dialog).getByRole('button', { name: /Clear/ }))
    expect(await challengeOf(server, 1)).toEqual({ op: 'cred.expiry_set', slug: 'openai', expires_at: null })
    expect(await screen.findByText('Cleared the expiry on openai')).toBeTruthy()
  })

  it('Test probes the credential (open) and shows the result on its row', async () => {
    const server = fakeServer(pagesRoutes({ 'POST credentials/test': { status: 'ok', http_status: 200, latency_ms: 41, scopes: ['repo'] } }))
    const { container } = renderWith(<Credentials />, { server })
    await loaded()
    await click(screen.getAllByRole('button', { name: 'Test gh-work' })[0])
    await waitFor(() => expect(container.querySelector('[data-test-line]')?.textContent).toBe('test: ok · 200 · 41ms · scopes: repo'))
    expect(callsTo(server, 'POST', 'credentials/test')[0].body).toEqual({ slug: 'gh-work' })
  })
})
