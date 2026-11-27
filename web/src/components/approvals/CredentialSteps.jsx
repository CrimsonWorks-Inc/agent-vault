import { useRef } from 'react'
import { CheckIcon } from '@heroicons/react/20/solid'
import { useApi } from '../../hooks/useApi.js'
import { usePresence } from '../../hooks/usePresence.js'
import { useToast } from '../../hooks/useToast.js'
import { cleanLine } from '../../lib/text.js'
import { Button } from '../ui/Button.jsx'
import { Field } from '../ui/Field.jsx'
import { GatedButton } from '../ui/GatedButton.jsx'
import { Input } from '../ui/Input.jsx'
import { credentialCall } from './decide.js'

/**
 * Finishing a credential an agent proposed, in two steps: check the hosts the
 * key would be sent to, then type the key and save it. The key is held in the
 * card's draft until it is sent, goes straight to the daemon, is bound into
 * the signature by its digest, and is dropped once the proposal is decided.
 *
 * `draft` is `{ hostsConfirmed, value }`; `onDraft` replaces it.
 */
export function CredentialSteps({ item, draft = {}, onDraft, onDecided }) {
  const hosts = item.hosts || []
  const confirmed = draft.hostsConfirmed === true
  const slug = cleanLine(item.proposal?.slug ?? '')
  return (
    <div className="mt-4 space-y-4">
      <section aria-label="Step 1: check the host">
        <p className="text-sm font-medium text-ink">1. This key will be sent only to:</p>
        <ul className="mt-1.5 space-y-1">
          {hosts.map((h) => (
            <li key={h} className="break-all font-mono text-[0.9375rem] font-semibold text-ink">{cleanLine(h)}</li>
          ))}
        </ul>
        {confirmed ? (
          <p className="mt-2 inline-flex items-center gap-1.5 text-sm text-ok">
            <CheckIcon className="size-4" aria-hidden="true" />
            You confirmed the host.
            <button type="button" className="ml-1 text-muted underline" onClick={() => onDraft?.({ hostsConfirmed: false, value: '' })}>Change</button>
          </p>
        ) : (
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <Button size="sm" onClick={() => onDraft?.({ ...draft, hostsConfirmed: true })} disabled={!hosts.length}>
              Yes, that is the right host
            </Button>
            <span className="text-sm text-muted">Not the service you meant? Deny it.</span>
          </div>
        )}
      </section>

      {confirmed && (
        <section aria-label="Step 2: enter the key">
          <Field label={`2. Enter the key for ${slug}`} hint="It is not shown as you type, goes straight to the vault, and is never sent back to this page or to the agent.">
            <Input
              type="password"
              mono
              autoComplete="new-password"
              placeholder="paste the key"
              value={draft.value ?? ''}
              onChange={(e) => onDraft?.({ ...draft, value: e.target.value })}
            />
          </Field>
        </section>
      )}

      <div className="flex flex-wrap gap-2">
        {confirmed && <SaveButton item={item} draft={draft} onDone={onDecided} />}
        <DenyButton item={item} onDone={onDecided} />
      </div>
    </div>
  )
}

function SaveButton({ item, draft, onDone }) {
  const api = useApi()
  const toast = useToast()
  const { operationFor } = usePresence()
  const sendRef = useRef(null)
  const slug = cleanLine(item.proposal?.slug ?? '')
  return (
    <GatedButton
      variant="primary"
      label={`save the key for ${slug}`}
      disabled={!String(draft.value ?? '').trim()}
      operation={async () => {
        const call = await credentialCall(item, true, draft, { operationFor, api })
        sendRef.current = call.send
        return call.operation
      }}
      send={(proof) => sendRef.current(proof)}
      onDone={() => { toast(`Saved ${slug}`, { tone: 'ok' }); onDone?.(item, true) }}
    >
      Save key
      <span className="sr-only"> {item.id}</span>
    </GatedButton>
  )
}

function DenyButton({ item, onDone }) {
  const api = useApi()
  const toast = useToast()
  const { operationFor } = usePresence()
  const sendRef = useRef(null)
  return (
    <GatedButton
      variant="danger"
      label={`deny credential proposal ${item.id}`}
      operation={async () => {
        const call = await credentialCall(item, false, {}, { operationFor, api })
        sendRef.current = call.send
        return call.operation
      }}
      send={(proof) => sendRef.current(proof)}
      onDone={() => { toast('Denied', { tone: 'ok' }); onDone?.(item, false) }}
    >
      Deny
      <span className="sr-only"> {item.id}</span>
    </GatedButton>
  )
}
