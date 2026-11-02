import { useCallback, useMemo, useRef, useState } from 'react'
import { PromptContext } from '../../hooks/usePrompt.js'
import { Button } from './Button.jsx'
import { Field } from './Field.jsx'
import { Input } from './Input.jsx'
import { Modal } from './Modal.jsx'

/**
 * One page-drawn dialog at a time, as a promise (hooks/usePrompt.js).
 * A secret is typed into a password field, kept only in this component's
 * state while the dialog is open, and handed to the caller once.
 */
export function PromptProvider({ children }) {
  const [req, setReq] = useState(null)
  const [text, setText] = useState('')
  const resolver = useRef(null)
  const inputRef = useRef(null)
  const cancelRef = useRef(null)

  const open = useCallback((kind, opts) => new Promise((resolve) => {
    resolver.current?.(null)
    resolver.current = resolve
    setText(opts.initial ?? '')
    setReq({ kind, ...opts })
  }), [])

  const close = (value) => {
    const r = resolver.current
    resolver.current = null
    setReq(null)
    setText('')
    r?.(value)
  }

  const api = useMemo(() => ({
    secret: (opts = {}) => open('secret', typeof opts === 'string' ? { title: opts } : opts),
    text: (opts = {}) => open('text', typeof opts === 'string' ? { title: opts } : opts),
    confirm: (opts = {}) => open('confirm', typeof opts === 'string' ? { title: opts } : opts).then((v) => v === true),
  }), [open])

  const submit = (e) => {
    e.preventDefault()
    if (!req) return
    close(req.kind === 'confirm' ? true : req.kind === 'text' ? text.trim() : text)
  }

  return (
    <PromptContext.Provider value={api}>
      {children}
      <Modal
        open={req !== null}
        onClose={() => close(req?.kind === 'confirm' ? false : null)}
        title={req?.title ?? ''}
        description={req?.body}
        size="sm"
        initialFocus={req?.kind === 'confirm' ? cancelRef : inputRef}
      >
        <form onSubmit={submit} className="space-y-4">
          {req?.kind !== 'confirm' && (
            <Field label={req?.label || (req?.kind === 'secret' ? 'Passphrase' : 'Value')} hint={req?.hint}>
              <Input
                ref={inputRef}
                type={req?.kind === 'secret' ? 'password' : 'text'}
                autoComplete={req?.kind === 'secret' ? 'current-password' : 'off'}
                value={text}
                maxLength={req?.maxLength}
                placeholder={req?.placeholder}
                onChange={(e) => setText(e.target.value)}
              />
            </Field>
          )}
          {req?.children}
          <div className="flex justify-end gap-2">
            <Button ref={cancelRef} onClick={() => close(req?.kind === 'confirm' ? false : null)}>Cancel</Button>
            <Button type="submit" variant={req?.danger ? 'panic' : 'primary'}>{req?.submit || (req?.kind === 'secret' ? 'Unlock' : 'OK')}</Button>
          </div>
        </form>
      </Modal>
    </PromptContext.Provider>
  )
}
