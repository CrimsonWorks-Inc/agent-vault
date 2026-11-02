import { useEffect, useState } from 'react'
import { FingerPrintIcon } from '@heroicons/react/20/solid'
import { useApi, useSlowCache } from '../../hooks/useApi.js'
import { usePresence } from '../../hooks/usePresence.js'
import { useToast } from '../../hooks/useToast.js'
import { useVault } from '../../hooks/useVault.js'
import { canonicalJson } from '../../lib/presence.js'
import { Button } from '../ui/Button.jsx'
import { Field } from '../ui/Field.jsx'
import { Input } from '../ui/Input.jsx'
import { Modal } from '../ui/Modal.jsx'
import { Select } from '../ui/Select.jsx'
import { heldDenied } from './credentialText.js'

const MODES = [
  { value: 'keep', label: 'keep working, with the new value' },
  { value: 'revoke', label: 'lose their grants now' },
]

/**
 * A new value for a credential (F7): typed here, signed by digest, never
 * echoed. Two steps in one dialog, as app.html had them: the form, then the
 * exact operation the authenticator will sign ("Sign it"), because the
 * platform dialog cannot describe a rotation. The value lives only in this
 * dialog's state and is cleared when it closes.
 */
export function RotateDialog({ slug, onClose, onDone }) {
  const api = useApi()
  const slow = useSlowCache()
  const presence = usePresence()
  const toast = useToast()
  const vault = useVault()
  const [value, setValue] = useState('')
  const [mode, setMode] = useState('keep')
  const [retire, setRetire] = useState('24')
  const [review, setReview] = useState(null) // { body, operation }
  const [busy, setBusy] = useState(false)

  // A new slug is a new dialog; nothing typed for the last one carries over.
  useEffect(() => { setValue(''); setMode('keep'); setRetire('24'); setReview(null) }, [slug])

  const close = () => { setValue(''); setReview(null); onClose() }

  const next = async (e) => {
    e?.preventDefault()
    if (!value) {
      toast('No value was typed. Nothing was changed.', { tone: 'warn' })
      return
    }
    const body = { slug, value, mode, retire_hours: Number(retire) }
    setReview({ body, operation: await presence.operationFor('cred.rotate', body) })
  }

  const cancelReview = () => { toast('Cancelled. Nothing was changed.', { tone: 'warn' }); close() }

  const sign = async () => {
    const { body, operation } = review
    setBusy(true)
    try {
      const r = await presence.gated(operation, (proof) => api.post('credentials/rotate', { ...body, presence: proof }), { label: `rotate credential ${slug}` })
      toast(`Rotated ${slug} to version ${r?.rotated?.version ?? '?'}${heldDenied(r?.invalidated_approvals)}`, { tone: 'ok' })
      slow.clear()
      vault.refresh?.()
      close()
      onDone?.()
    } catch (err) {
      toast(err?.message || String(err), { tone: 'crit' })
    } finally {
      setBusy(false)
    }
  }

  const open = Boolean(slug)
  if (review) {
    return (
      <Modal
        open={open}
        onClose={cancelReview}
        title={`Rotate ${slug}`}
        description="This is what your authenticator will sign. The new value is bound by its digest and never shown."
        footer={(
          <>
            <Button onClick={cancelReview}>Cancel</Button>
            <Button variant="primary" icon={FingerPrintIcon} loading={busy} onClick={sign}>Sign it</Button>
          </>
        )}
      >
        <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-control border border-line bg-sunken px-3 py-2 font-mono text-xs leading-relaxed text-ink" data-operation="">
          {JSON.stringify(JSON.parse(canonicalJson(review.operation)), null, 2)}
        </pre>
      </Modal>
    )
  }
  return (
    <Modal
      open={open}
      onClose={close}
      title={`Rotate ${slug ?? ''}`}
      description="The new value goes straight to the daemon and is never sent back to this page."
      footer={(
        <>
          <Button onClick={close}>Cancel</Button>
          <Button variant="primary" type="submit" form="rotate-form">Next</Button>
        </>
      )}
    >
      <form id="rotate-form" onSubmit={next} className="space-y-4">
        <Field label={`New value for ${slug ?? ''} (not echoed)`}>
          <Input type="password" mono autoComplete="new-password" value={value} onChange={(e) => setValue(e.target.value)} />
        </Field>
        <Field label="Sessions using it">
          <Select value={mode} onChange={setMode} options={MODES} />
        </Field>
        <Field label="Keep scrubbing the old value for (hours)" hint="0 to 168. Responses are still scrubbed of the old value for this long.">
          <Input type="number" min={0} max={168} value={retire} onChange={(e) => setRetire(e.target.value)} />
        </Field>
      </form>
    </Modal>
  )
}
