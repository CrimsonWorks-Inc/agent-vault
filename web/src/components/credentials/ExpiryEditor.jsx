import { useEffect, useState } from 'react'
import { useApi, useSlowCache } from '../../hooks/useApi.js'
import { usePresence } from '../../hooks/usePresence.js'
import { useToast } from '../../hooks/useToast.js'
import { Field } from '../ui/Field.jsx'
import { GatedButton } from '../ui/GatedButton.jsx'
import { Input } from '../ui/Input.jsx'
import { expiryDay, expiryIso } from './credentialText.js'

/**
 * When the token runs out (F10): a note for you, not a lock. Setting and
 * clearing it are signed (cred.expiry_set) over exactly what is sent.
 */
export function ExpiryEditor({ c, onChanged }) {
  const api = useApi()
  const slow = useSlowCache()
  const presence = usePresence()
  const toast = useToast()
  const stored = expiryDay(c)
  const [day, setDay] = useState(stored)
  useEffect(() => { setDay(stored) }, [stored])
  const slug = c.slug

  const send = (expiresAt) => (proof) => api.post('credentials/expiry', { slug, expires_at: expiresAt, presence: proof })
  const done = (expiresAt) => () => {
    toast(expiresAt ? `${slug} expires ${expiresAt.slice(0, 10)}` : `Cleared the expiry on ${slug}`, { tone: 'ok' })
    slow.clear()
    onChanged?.()
  }
  const chosen = () => {
    if (!day) throw new Error('Pick a date first')
    return expiryIso(day)
  }

  return (
    <section aria-labelledby={`expiry-${slug}`} className="space-y-3">
      <h3 id={`expiry-${slug}`} className="text-sm font-semibold text-ink">Expiry{stored ? ` (${stored})` : ''}</h3>
      <Field label="Expires on" className="sm:max-w-xs">
        <Input type="date" value={day} onChange={(e) => setDay(e.target.value)} />
      </Field>
      <div className="flex flex-wrap gap-2">
        <GatedButton
          label={day ? `set ${slug} to expire ${day}` : `set the expiry on ${slug}`}
          operation={() => presence.operationFor('cred.expiry_set', { slug, expires_at: chosen() })}
          send={(proof) => send(chosen())(proof)}
          onDone={() => done(chosen())()}
        >
          Set expiry
        </GatedButton>
        {c.expires_at && (
          <GatedButton
            label={`clear the expiry on ${slug}`}
            operation={() => presence.operationFor('cred.expiry_set', { slug, expires_at: null })}
            send={send(null)}
            onDone={done(null)}
          >
            Clear
          </GatedButton>
        )}
      </div>
      <p className="text-sm text-muted">A reminder, not enforcement: an expired token is still sent until the upstream refuses it.</p>
    </section>
  )
}
