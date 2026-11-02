import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Pagination } from './Pagination.jsx'
import { showing } from '../../lib/paging.js'

const props = (over = {}) => ({
  page: 2, limit: 25, hasNext: true, hasPrev: true, onNext: vi.fn(), onPrev: vi.fn(), onLimitChange: vi.fn(),
  range: showing({ page: 2, limit: 25, count: 25, total: 312 }), ...over,
})

describe('Pagination (U4)', () => {
  it('says where you are when the total is known', () => {
    render(<Pagination {...props()} />)
    expect(screen.getByText('Showing 26–50 of 312')).toBeTruthy()
    expect(screen.getByRole('navigation', { name: 'Pagination' })).toBeTruthy()
  })

  it('Prev and Next are buttons that call back, and disable at the ends', () => {
    const p = props()
    render(<Pagination {...p} />)
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
    fireEvent.click(screen.getByRole('button', { name: 'Previous page' }))
    expect(p.onNext).toHaveBeenCalledOnce()
    expect(p.onPrev).toHaveBeenCalledOnce()
  })

  it('cannot go back from the first page or on past the last', () => {
    render(<Pagination {...props({ page: 1, hasPrev: false, hasNext: false })} />)
    expect(screen.getByRole('button', { name: 'Previous page' }).disabled).toBe(true)
    expect(screen.getByRole('button', { name: 'Next page' }).disabled).toBe(true)
  })

  it('offers 25, 50 and 100 per page, by keyboard', async () => {
    const p = props()
    render(<Pagination {...p} />)
    const user = userEvent.setup()
    await user.tab()
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Rows per page' }), 'the page size is the first stop in the control')
    await user.keyboard('{ArrowDown}')
    const options = await screen.findAllByRole('option')
    expect(options.map((o) => o.textContent)).toEqual(['25', '50', '100'])
    await user.keyboard('{ArrowDown}{ArrowDown}{Enter}')
    expect(p.onLimitChange).toHaveBeenCalledWith(100)
  })
})
