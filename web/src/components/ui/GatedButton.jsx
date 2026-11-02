import { useState } from 'react'
import { FingerPrintIcon } from '@heroicons/react/20/solid'
import { usePresence } from '../../hooks/usePresence.js'
import { useToast } from '../../hooks/useToast.js'
import { canonicalJson } from '../../lib/presence.js'
import { Button } from './Button.jsx'
import { Modal } from './Modal.jsx'

/**
 * A button for a change that has to be signed with Touch ID (GATED in
 * src/ui/server.js).
 *
 *   <GatedButton
 *     operation={() => operationFor('session.revoke', { sid })}   // or a plain object
 *     label={`revoke session ${sid}`}                              // what the human is told
 *     send={(proof) => api.del('sessions', { sid }, { presence: proof })}
 *     onDone={() => { toast('Revoked'); list.reload() }}
 *     variant="danger"
 *   >Revoke</GatedButton>
 *
 * Before the platform dialog opens the page names the operation ("Touch ID to
 * revoke session s_123", PresenceStatus), because the platform dialog says who
 * is asking and never what for (U7). With `review`, the exact operation is
 * shown first and signing waits for "Sign it" (the old page's showOperation, used
 * where the dialog cannot describe the change, like a rotation).
 */
export function GatedButton({
  operation, label, send, onDone, onError, review = false, reviewTitle, children,
  variant = 'secondary', size = 'md', disabled, className, ...rest
}) {
  const presence = usePresence()
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  const [pending, setPending] = useState(null)

  const build = async () => (typeof operation === 'function' ? operation() : operation)

  const sign = async (op) => {
    setBusy(true)
    try {
      const result = await presence.gated(op, send, { label: label || presence.describe(op) })
      await onDone?.(result)
    } catch (e) {
      if (onError) onError(e)
      else toast(e?.message || String(e), { tone: 'crit' })
    } finally {
      setBusy(false)
    }
  }

  const click = async () => {
    let op
    try { op = await build() } catch (e) { toast(e?.message || String(e), { tone: 'crit' }); return }
    if (review) setPending(op)
    else await sign(op)
  }

  const what = label || (pending ? presence.describe(pending) : '')
  return (
    <>
      <Button
        variant={variant}
        size={size}
        loading={busy}
        disabled={disabled}
        onClick={click}
        icon={FingerPrintIcon}
        data-gated=""
        title={label ? `Asks for Touch ID to ${label}` : 'Asks for Touch ID'}
        className={className}
        {...rest}
      >
        {children}
      </Button>
      {review && (
        <Modal
          open={pending !== null}
          onClose={() => setPending(null)}
          title={reviewTitle || `Sign: ${what}`}
          description="This is what your authenticator will sign. A secret value is bound by its digest and never shown."
          footer={(
            <>
              <Button onClick={() => setPending(null)}>Cancel</Button>
              <Button
                variant="primary"
                icon={FingerPrintIcon}
                onClick={() => { const op = pending; setPending(null); sign(op) }}
              >
                Sign it
              </Button>
            </>
          )}
        >
          <pre className="max-h-80 overflow-auto rounded-control border border-line bg-sunken px-3 py-2 font-mono text-xs leading-relaxed text-ink">
            {pending ? JSON.stringify(JSON.parse(canonicalJson(pending)), null, 2) : ''}
          </pre>
        </Modal>
      )}
    </>
  )
}
