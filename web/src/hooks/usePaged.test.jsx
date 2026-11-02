import { describe, expect, it } from 'vitest'
import { act, screen, waitFor } from '@testing-library/react'
import { fakeServer, renderWith } from '../test/harness.jsx'
import { usePaged } from './usePaged.js'
import { Pagination } from '../components/ui/Pagination.jsx'
import { SearchInput } from '../components/ui/SearchInput.jsx'

let latest
function List({ path = 'credentials', poll = 0 }) {
  const list = usePaged(path, { searchFields: ['slug'], poll })
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
    await screen.findByText('match-gh', {}, { timeout: 2000 })
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

  it('a server that answers a bare array is paged here, the same way', async () => {
    const server = fakeServer({ 'GET credentials': Array.from({ length: 30 }, (_, i) => ({ slug: `c${i}` })) })
    renderWith(<List />, { server })
    await screen.findByText('c0')
    expect(screen.getByText('Showing 1–25 of 30')).toBeTruthy()
    await act(async () => { latest.next() })
    await screen.findByText('c29')
    expect(screen.queryByText('c0')).toBeNull()
  })
})
