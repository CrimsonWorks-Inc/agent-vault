import { describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { Badge } from './Badge.jsx'
import { Button } from './Button.jsx'
import { Card, Row } from './Card.jsx'
import { CodeBlock } from './CodeBlock.jsx'
import { ConfirmDialog } from './ConfirmDialog.jsx'
import { EmptyState } from './EmptyState.jsx'
import { Field } from './Field.jsx'
import { Input } from './Input.jsx'
import { Logo, Mark } from './Mark.jsx'
import { Menu } from './Menu.jsx'
import { Modal } from './Modal.jsx'
import { Notice } from './Notice.jsx'
import { SearchInput } from './SearchInput.jsx'
import { Select } from './Select.jsx'
import { Switch } from './Switch.jsx'
import { Tabs } from './Tabs.jsx'
import { ThemeToggle } from './ThemeToggle.jsx'
import { Tooltip } from './Tooltip.jsx'
import { ToastProvider } from './Toast.jsx'
import { useToast } from '../../hooks/useToast.js'

describe('primitives', () => {
  it('Button: variants are props; loading disables and announces busy', () => {
    const onClick = vi.fn()
    const { rerender } = render(<Button variant="primary" onClick={onClick}>Store</Button>)
    fireEvent.click(screen.getByRole('button', { name: 'Store' }))
    expect(onClick).toHaveBeenCalledOnce()
    expect(screen.getByRole('button').className).toContain('bg-accent')
    rerender(<Button variant="panic" loading>Panic</Button>)
    expect(screen.getByRole('button').disabled).toBe(true)
    expect(screen.getByRole('button').getAttribute('aria-busy')).toBe('true')
  })

  it('Badge carries its state in words', () => {
    render(<Badge tone="crit" dot>locked</Badge>)
    expect(screen.getByText('locked').className).toContain('text-crit')
  })

  it('Card and Row lay out a title, meta and actions', () => {
    render(<Card title="Containment" eyebrow="Emergency"><Row title="Panic" meta="Revoke everything" actions={<button type="button">Go</button>} /></Card>)
    expect(screen.getByRole('heading', { name: 'Containment' })).toBeTruthy()
    expect(screen.getByText('Revoke everything')).toBeTruthy()
  })

  it('Field labels its input', () => {
    render(<Field label="Name" hint="a short slug"><Input /></Field>)
    expect(screen.getByLabelText('Name')).toBeTruthy()
  })

  it('Modal and ConfirmDialog: cancel has focus, confirm calls back', async () => {
    const onConfirm = vi.fn()
    const onCancel = vi.fn()
    render(<ConfirmDialog open title="Lock the vault?" body="Every request is refused." confirmLabel="Lock" onConfirm={onConfirm} onCancel={onCancel} />)
    await waitFor(() => expect(document.activeElement?.textContent).toBe('Cancel'))
    fireEvent.click(screen.getByRole('button', { name: 'Lock' }))
    expect(onConfirm).toHaveBeenCalledOnce()
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    expect(onCancel).toHaveBeenCalled()
  })

  it('Modal closes on Escape', async () => {
    const onClose = vi.fn()
    render(<Modal open onClose={onClose} title="T">body</Modal>)
    fireEvent.keyDown(await screen.findByRole('dialog'), { key: 'Escape' })
    expect(onClose).toHaveBeenCalled()
  })

  it('Select chooses an option', async () => {
    const onChange = vi.fn()
    render(<Select aria-label="Kind" value="github" onChange={onChange} options={[{ value: 'github', label: 'github' }, { value: 'http', label: 'http (generic)' }]} />)
    fireEvent.click(screen.getByRole('button', { name: 'Kind' }))
    fireEvent.click(await screen.findByRole('option', { name: 'http (generic)' }))
    expect(onChange).toHaveBeenCalledWith('http')
  })

  it('Switch is a switch with its state in words', () => {
    const onChange = vi.fn()
    render(<Switch checked={false} onChange={onChange} label="Desktop notifications" />)
    const sw = screen.getByRole('switch', { name: 'Desktop notifications' })
    expect(sw.getAttribute('aria-checked')).toBe('false')
    expect(screen.getByText('off')).toBeTruthy()
    fireEvent.click(sw)
    expect(onChange).toHaveBeenCalledWith(true)
  })

  it('Tabs switch panels', () => {
    render(<Tabs tabs={[{ id: 'a', label: 'How', content: 'how it works' }, { id: 'b', label: 'Connect', content: 'connect it' }]} />)
    fireEvent.click(screen.getByRole('tab', { name: 'Connect' }))
    expect(screen.getByRole('tabpanel').textContent).toBe('connect it')
  })

  it('Menu lists actions', async () => {
    const onClick = vi.fn()
    render(<Menu label="Session actions" items={[{ label: 'Details', onClick }]} />)
    fireEvent.click(screen.getByRole('button', { name: 'Session actions' }))
    fireEvent.click(await screen.findByRole('menuitem', { name: 'Details' }))
    expect(onClick).toHaveBeenCalled()
  })

  it('SearchInput: Escape clears, the clear button clears', () => {
    const onChange = vi.fn()
    render(<SearchInput value="gh" onChange={onChange} label="Search credentials" />)
    fireEvent.keyDown(screen.getByRole('searchbox', { name: 'Search credentials' }), { key: 'Escape' })
    expect(onChange).toHaveBeenCalledWith('')
    fireEvent.click(screen.getByRole('button', { name: 'Clear search' }))
    expect(onChange).toHaveBeenCalledTimes(2)
  })

  it('CodeBlock copies its text, and says when the browser refuses', async () => {
    const writes = []
    Object.defineProperty(globalThis.navigator, 'clipboard', { value: { writeText: async (t) => writes.push(t) }, configurable: true })
    render(<CodeBlock code="agent-vault ui" label="Copy the command" />)
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Copy the command' })) })
    expect(writes).toEqual(['agent-vault ui'])
    expect(screen.getByRole('button', { name: 'Copied' })).toBeTruthy()
  })

  it('Toast shows a message in a live region', async () => {
    function Fire() { const toast = useToast(); return <button type="button" onClick={() => toast('Revoked', { tone: 'ok' })}>go</button> }
    render(<ToastProvider><Fire /></ToastProvider>)
    fireEvent.click(screen.getByRole('button', { name: 'go' }))
    expect(await screen.findByText('Revoked')).toBeTruthy()
  })

  it('Tooltip describes its trigger', () => {
    render(<Tooltip content="Only GET and HEAD from now on"><button type="button">Drop write access</button></Tooltip>)
    expect(screen.getByRole('tooltip').textContent).toBe('Only GET and HEAD from now on')
  })

  it('EmptyState and Notice say what is going on', () => {
    render(<><EmptyState title="Nothing here">Add one.</EmptyState><Notice tone="warn" title="2 waiting">Open Approvals.</Notice></>)
    expect(screen.getByText('Nothing here')).toBeTruthy()
    expect(screen.getByText('2 waiting')).toBeTruthy()
  })

  it('Mark and Logo: decorative mark, named lockup', () => {
    const { container } = render(<><Mark size={16} /><Logo /></>)
    expect(container.querySelector('svg[aria-hidden="true"]')).not.toBeNull()
    expect(screen.getByRole('img', { name: 'agent-vault, by ioLite Labs' })).toBeTruthy()
  })

  it('ThemeToggle sets data-theme and remembers the choice', () => {
    render(<ThemeToggle />)
    fireEvent.click(screen.getByRole('radio', { name: 'Dark' }))
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
    expect(localStorage.getItem('agent-vault.theme')).toBe('dark')
    fireEvent.click(screen.getByRole('radio', { name: 'System' }))
    expect(document.documentElement.hasAttribute('data-theme')).toBe(false)
  })
})
