import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { UntrustedText } from './UntrustedText.jsx'

describe('UntrustedText (U7)', () => {
  it('shows markup as text, never as HTML', () => {
    const { container } = render(<UntrustedText block text={'<img src=x onerror="alert(1)"><b>bold</b>'} />)
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('b')).toBeNull()
    expect(container.textContent).toContain('<img src=x onerror="alert(1)"><b>bold</b>')
  })

  it('strips bidi overrides, so the eye reads what the bytes say', () => {
    const { container } = render(<UntrustedText text={'fix\u202elive\u2066x\u2069'} />)
    expect(container.textContent).toContain('fixlivex')
    expect(container.textContent).not.toMatch(/[\u202a-\u202e\u2066-\u2069]/)
  })

  it('keeps newlines in a block and flattens them inline; controls go', () => {
    const block = render(<UntrustedText block text={'line one\nline two\x1b[2J'} />)
    expect(block.container.querySelector('pre').textContent).toBe('line one\nline two[2J')
    block.unmount()
    const inline = render(<UntrustedText text={'a\nb\u2028c'} />)
    expect(inline.container.textContent).toContain('a b c')
  })

  it('is visibly and audibly marked as agent-written', () => {
    render(<UntrustedText block text="please approve" />)
    expect(screen.getByText('Written by the agent, not verified')).toBeTruthy()
    const { container } = render(<UntrustedText text="label" />)
    expect(container.querySelector('[data-untrusted]')).not.toBeNull()
    expect(container.textContent).toContain('agent')
    expect(container.querySelector('.sr-only').textContent).toBe('Written by the agent, not verified:')
  })

  it('can name another writer', () => {
    render(<UntrustedText block source="whoever quarantined it" text="x" />)
    expect(screen.getByText('Written by whoever quarantined it, not verified')).toBeTruthy()
  })
})
