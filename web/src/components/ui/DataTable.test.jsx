import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { DataTable } from './DataTable.jsx'

const columns = [
  { key: 'slug', header: 'Name', primary: true, sortable: true },
  { key: 'kind', header: 'Kind' },
  { key: 'actions', header: 'Actions', cell: (r) => <button type="button">Test {r.slug}</button> },
]

describe('DataTable', () => {
  it('renders rows as a table and as cards', () => {
    const { container } = render(<DataTable caption="Credentials" columns={columns} rows={[{ id: 1, slug: 'gh', kind: 'github' }]} />)
    const table = container.querySelector('table')
    expect(within(table).getByText('github')).toBeTruthy()
    const cards = container.querySelector('ul')
    expect(within(cards).getByText('gh')).toBeTruthy()
    expect(within(cards).getByText('Test gh')).toBeTruthy()
  })

  it('shows a skeleton while the first page loads, and the empty state when there is nothing', () => {
    const { rerender } = render(<DataTable columns={columns} rows={[]} loading />)
    expect(screen.getByRole('status').textContent).toBe('Loading')
    rerender(<DataTable columns={columns} rows={[]} empty={{ title: 'No credentials yet', body: 'Add one below.' }} />)
    expect(screen.getByText('No credentials yet')).toBeTruthy()
    expect(screen.getByText('Add one below.')).toBeTruthy()
  })

  it('a sortable header is a button that reports its order', () => {
    const onSort = vi.fn()
    const { container } = render(<DataTable columns={columns} rows={[]} sort={{ key: 'slug', dir: 'asc' }} onSort={onSort} />)
    const th = container.querySelector('th[aria-sort]')
    expect(th.getAttribute('aria-sort')).toBe('ascending')
    fireEvent.click(within(th).getByRole('button'))
    expect(onSort).toHaveBeenCalledWith('slug')
  })

  it('cell text is text: a value with markup is not rendered as markup', () => {
    const { container } = render(<DataTable columns={columns.slice(0, 2)} rows={[{ id: 1, slug: '<b>x</b>', kind: 'k' }]} />)
    expect(container.querySelector('b')).toBeNull()
  })
})
