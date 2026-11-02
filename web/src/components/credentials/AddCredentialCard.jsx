import { useEffect, useState } from 'react'
import { useApi, useSlowCache } from '../../hooks/useApi.js'
import { usePresence } from '../../hooks/usePresence.js'
import { useToast } from '../../hooks/useToast.js'
import { Card } from '../ui/Card.jsx'
import { Field } from '../ui/Field.jsx'
import { GatedButton } from '../ui/GatedButton.jsx'
import { Input } from '../ui/Input.jsx'
import { Select } from '../ui/Select.jsx'
import { KINDS } from './credentialText.js'

/**
 * Store a credential. The value is write-only: it is held in this form's
 * state until it is sent, goes straight to the daemon, is bound into the
 * signature by its digest (cred.add, value_sha256), and is cleared after
 * storing and when the form goes away.
 */
export function AddCredentialCard({ onAdded }) {
  const api = useApi()
  const slow = useSlowCache()
  const presence = usePresence()
  const toast = useToast()
  const [slug, setSlug] = useState('')
  const [kind, setKind] = useState('github')
  const [host, setHost] = useState('')
  const [value, setValue] = useState('')
  useEffect(() => () => setValue(''), [])

  const body = () => ({ slug: slug.trim(), kind, value, host: host.trim() || undefined })
  const operation = () => {
    const b = body()
    if (!b.slug || !b.value) throw new Error('A name and a value are both required')
    return presence.operationFor('cred.add', b)
  }

  return (
    <Card title="Add a credential" description="The value goes straight to the daemon and is never sent back to this page.">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <Field label="Name">
          <Input mono placeholder="gh-frozencrow" autoComplete="off" value={slug} onChange={(e) => setSlug(e.target.value)} />
        </Field>
        <Field label="Kind">
          <Select value={kind} onChange={setKind} options={KINDS} />
        </Field>
        <Field label="Host" hint="Generic (http) credentials only.">
          <Input mono placeholder="api.example.com" autoComplete="off" value={host} onChange={(e) => setHost(e.target.value)} />
        </Field>
        <Field label="Value" className="sm:col-span-2 lg:col-span-3">
          <Input
            type="password"
            mono
            autoComplete="new-password"
            placeholder="paste the token; it is not echoed and never returned"
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
        </Field>
      </div>
      <div className="mt-4">
        <GatedButton
          variant="primary"
          label={`store credential ${slug.trim()}`}
          operation={operation}
          send={(proof) => api.post('credentials', { ...body(), presence: proof })}
          onDone={() => {
            const stored = slug.trim()
            setValue('')
            toast(`Stored ${stored}`, { tone: 'ok' })
            slow.clear()
            onAdded?.()
          }}
        >
          Store credential
        </GatedButton>
      </div>
    </Card>
  )
}
