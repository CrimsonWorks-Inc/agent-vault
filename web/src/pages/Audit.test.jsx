import { describe, expect, it } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { fakeServer, renderWith } from '../test/harness.jsx'
import { Audit } from './Audit.jsx'

const row = (seq, kind, extra = {}) => ({ seq, kind, ts: `2026-11-01T21:0${seq % 10}:12.000Z`, hash: `h${seq}abcdef0123456789`, ...extra })

function routes(over = {}) {
  return {
    'GET audit': ({ query }) => {
      if (query.limit === '1') return { items: [row(214, 'request.allowed')], next_cursor: 'x', prev_cursor: null, total: null }
      return {
        items: [
          row(214, 'request.allowed', { decision: 'allow', credential_slug: 'gh-work' }),
          row(213, 'request.denied', { decision: 'deny', reason_code: 'AV_POLICY_DENIED' }),
          row(212, 'session.created', { session_id: 's_1' }),
        ],
        next_cursor: query.cursor ? null : 'older',
        prev_cursor: null,
        total: null,
      }
    },
    'GET audit/verify': { ok: true, count: 214 },
    'GET audit/checkpoint': { seq: 214, hash: 'h214', mac: 'm' },
    ...over,
  }
}

const table = () => screen.getByRole('table', { name: 'Audit records, newest first' })

describe('Audit (parity with app.html, paged through the whole log)', () => {
  it('shows the witness head and the records newest first, decisions in words', async () => {
    const server = fakeServer(routes())
    renderWith(<Audit />, { server })
    expect(await screen.findByText(/head: record 214, h214abcdef012345…/)).toBeTruthy()
    const t = within(table())
    expect(await t.findByText('request.denied')).toBeTruthy()
    expect(t.getByText('allow')).toBeTruthy()
    expect(t.getByText('deny')).toBeTruthy()
    expect(t.getByText('AV_POLICY_DENIED')).toBeTruthy()
    expect(t.getByText('gh-work')).toBeTruthy()
    expect(t.getByText('2026-11-01 21:04:12')).toBeTruthy()
    const call = server.calls.find((c) => c.path === 'audit' && c.query.limit === '25')
    expect(call.query).toMatchObject({ paged: '1' })
    expect(call.query.kind).toBeUndefined()
  })

  it('pages with the server\'s cursor, and a new kind goes back to page one with the kind sent', async () => {
    const server = fakeServer(routes())
    renderWith(<Audit />, { server })
    await within(table()).findByText('request.denied')
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
    await waitFor(() => expect(server.calls.some((c) => c.path === 'audit' && c.query.cursor === 'older')).toBe(true))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Previous page' }).disabled).toBe(false))

    fireEvent.click(screen.getByRole('button', { name: /Kind of record/ }))
    fireEvent.click(await screen.findByRole('option', { name: /Tripwires/ }))
    await waitFor(() => expect(server.calls.some((c) => c.path === 'audit' && c.query.kind === 'tripwire' && !c.query.cursor)).toBe(true))
  })

  it('searches with q', async () => {
    const server = fakeServer(routes())
    renderWith(<Audit />, { server })
    await within(table()).findByText('request.denied')
    fireEvent.change(screen.getByRole('searchbox', { name: 'Search the audit log' }), { target: { value: 's_1' } })
    await waitFor(() => expect(server.calls.some((c) => c.path === 'audit' && c.query.q === 's_1')).toBe(true))
  })

  it('verifies the chain and fetches a checkpoint to copy', async () => {
    const server = fakeServer(routes())
    renderWith(<Audit />, { server })
    await screen.findByText(/head: record 214/)
    fireEvent.click(screen.getByRole('button', { name: 'Verify chain' }))
    expect(await screen.findByText('Chain intact across 214 records')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Copy checkpoint' }))
    expect(await screen.findByText('{"seq":214,"hash":"h214","mac":"m"}')).toBeTruthy()
  })

  it('says when the chain is broken', async () => {
    const server = fakeServer(routes({ 'GET audit/verify': { ok: false, brokenAt: 97 } }))
    renderWith(<Audit />, { server })
    await screen.findByText(/head: record 214/)
    fireEvent.click(screen.getByRole('button', { name: 'Verify chain' }))
    expect(await screen.findByText('Chain broken at record 97')).toBeTruthy()
  })

  it('locked: nothing is asked of the log, and the page says to unlock', async () => {
    const server = fakeServer(routes())
    renderWith(<Audit />, { server, vault: { locked: true } })
    expect(screen.getByText('Unlock to read the audit log.')).toBeTruthy()
    expect(screen.getByText('locked')).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Go to Overview' }).getAttribute('href')).toBe('#overview')
    await new Promise((r) => setTimeout(r, 30))
    expect(server.calls.some((c) => c.path === 'audit')).toBe(false)
  })

  it('an unreadable log says so and re-checks the lock', async () => {
    let checked = 0
    const server = fakeServer(routes({ 'GET audit': { __status: 500, body: { error: 'internal error' } } }))
    renderWith(<Audit />, { server, vault: { refresh: () => { checked++ } } })
    expect(await screen.findByText('Could not read the audit log.')).toBeTruthy()
    expect(checked).toBeGreaterThan(0)
  })

  it('an empty log says so', async () => {
    const server = fakeServer(routes({ 'GET audit': { items: [], next_cursor: null, prev_cursor: null, total: null } }))
    renderWith(<Audit />, { server })
    expect(await screen.findByText('No records yet')).toBeTruthy()
    expect(await screen.findByText('head: no records yet')).toBeTruthy()
  })
})
