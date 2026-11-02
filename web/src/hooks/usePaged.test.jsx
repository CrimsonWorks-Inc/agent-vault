import { describe, expect, it } from 'vitest'
import { act, screen, waitFor } from '@testing-library/react'
import { fakeServer, renderWith } from '../test/harness.jsx'
import { usePaged } from './usePaged.js'
import { Pagination } from '../components/ui/Pagination.jsx'
import { SearchInput } from '../components/ui/SearchInput.jsx'

let latest
function List({ path = 'credentials', poll = 0 }) {
  const list = usePaged(path, { poll })
  latest = list
  return (
    <>
      <SearchInput value={list.q} onChange={list.setQ} label="Search" />
      <ul>{list.items.map((x) => <li key={x.slug}>{x.slug}</li>)}</ul>
      <Pagination {...list.pagination} />
    </>
  )
}

const envelope = (cursor, q) => {
  if (q) return { items: [{ slug: `match-${q}` }], next_cursor: null, prev_cursor: null, total: 1 }
  return cursor === 'c2'
    ? { items: [{ slug: 'z' }], next_cursor: null, prev_cursor: 'c1', total: 26 }
    : { items: Array.from({ length: 25 }, (_, i) => ({ slug: `s${i}` })), next_cursor: 'c2', prev_cursor: null, total: 26 }
}

describe('usePaged', () => {
  it('asks for paged=1 with the remembered page size, and walks Next and Prev by cursor', async () => {
    const server = fakeServer({ 'GET credentials': ({ query }) => envelope(query.cursor, query.q) })
    renderWith(<List />, { server })
    await screen.findByText('s0')
    expect(server.calls[0].query).toEqual({ paged: '1', limit: '25' })
    expect(screen.getByText('Showing 1–25 of 26')).toBeTruthy()
    await act(async () => { latest.next() })
    await screen.findByText('z')
    expect(server.calls.at(-1).query).toEqual({ paged: '1', limit: '25', cursor: 'c2' })
    expect(screen.getByText('Showing 26–26 of 26')).toBeTruthy()
    await act(async () => { latest.prev() })
    await screen.findByText('s0')
    expect(server.calls.at(-1).query.cursor).toBeUndefined()
  })

  it('debounces the search and goes back to the first page with it', async () => {
    const server = fakeServer({ 'GET credentials': ({ query }) => envelope(query.cursor, query.q) })
    renderWith(<List />, { server })
    await screen.findByText('s0')
    await act(async () => { latest.next() })
    await screen.findByText('z')
    const before = server.calls.length
    await act(async () => { latest.setQ('g'); latest.setQ('gh') })
    expect(server.calls.length).toBe(before)
    await screen.findByText('match-gh')
    expect(server.calls.length).toBe(before + 1)
    expect(server.calls.at(-1).query).toEqual({ paged: '1', limit: '25', q: 'gh' })
  })

  it('a new page size is remembered and starts from page one', async () => {
    const server = fakeServer({ 'GET credentials': ({ query }) => envelope(query.cursor) })
    renderWith(<List />, { server })
    await screen.findByText('s0')
    await act(async () => { latest.setLimit(100) })
    await waitFor(() => expect(server.calls.at(-1).query.limit).toBe('100'))
    expect(localStorage.getItem('agent-vault.page-size.credentials')).toBe('100')
  })

  it('pages the daemon list the way the UI server does: slug order, sealed cursors, its search', async () => {
    const server = fakeServer({ 'GET credentials': Array.from({ length: 30 }, (_, i) => ({ slug: `c${i}` })) })
    renderWith(<List />, { server })
    await screen.findByText('c0')
    expect(screen.getByText('Showing 1–25 of 30')).toBeTruthy()
    // Slug order, as src/ui/server.js LISTS.credentials sorts: c4 is the 25th.
    expect(screen.getByText('c4')).toBeTruthy()
    expect(screen.queryByText('c5')).toBeNull()
    await act(async () => { latest.next() })
    await screen.findByText('c9')
    expect(screen.queryByText('c0')).toBeNull()
    expect(server.calls.at(-1).query.cursor).toMatch(/^[A-Za-z0-9_-]{20,}$/)
    await act(async () => { latest.setQ('C2') })
    await waitFor(() => expect(screen.getByText('Showing 1–11 of 11')).toBeTruthy())
  })

  it('a list answer that is not a page is an error, not a guess', async () => {
    const server = fakeServer({ 'GET credentials': () => ({ __status: 200, body: [{ slug: 'old' }] }) })
    renderWith(<List />, { server })
    await waitFor(() => expect(latest.error?.name).toBe('EnvelopeError'))
    expect(screen.queryByText('old')).toBeNull()
  })

  it('a cursor the server no longer opens starts the list again', async () => {
    let refuse = false
    const server = fakeServer({
      'GET credentials': ({ query }) => (refuse && query.cursor
        ? { __status: 400, body: { error: 'that cursor is not one this server made', code: 'AV_BAD_CURSOR', detail: { code: 'AV_BAD_CURSOR' } } }
        : envelope(query.cursor, query.q)),
    })
    renderWith(<List />, { server })
    await screen.findByText('s0')
    await act(async () => { latest.next() })
    await screen.findByText('z')
    refuse = true
    await act(async () => { latest.reload() })
    await screen.findByText('s0')
    expect(latest.error).toBeNull()
    expect(latest.page).toBe(1)
  })
})
