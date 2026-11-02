import { useRef } from 'react'
import { useApi } from '../../hooks/useApi.js'
import { usePresence } from '../../hooks/usePresence.js'
import { useToast } from '../../hooks/useToast.js'
import { ago } from '../../lib/format.js'
import { cleanLine } from '../../lib/text.js'
import { Badge } from '../ui/Badge.jsx'
import { GatedButton } from '../ui/GatedButton.jsx'
import { Notice } from '../ui/Notice.jsx'
import { UntrustedText } from '../ui/UntrustedText.jsx'
import { decisionCall } from './decide.js'
import { NarrowingFields } from './NarrowingFields.jsx'
import { RequestPreview } from './RequestPreview.jsx'

/** "approve session request r_1", the words shown while Touch ID is open. */
export function decisionLabel(item, granted) {
  return `${granted ? 'approve' : 'deny'} ${item.kind === 'session' ? 'session request' : 'request'} ${item.id}`
}

/** The tick that puts one item in a bulk decision. */
export function PickBox({ item, checked, onChange, className }) {
  return (
    <label className={`inline-flex items-center gap-2 text-sm text-muted ${className || ''}`}>
      <input
        type="checkbox"
        className="size-4 accent-accent"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        aria-label={`Select ${item.id}`}
      />
      <span aria-hidden="true">select</span>
    </label>
  )
}

/**
 * One waiting decision, of whichever kind (app.html's approvals card). What
 * it shows came from GET pending, built by src/pending.js: the headline is
 * the daemon's summary of what it actually received; the claim is whatever
 * the agent said, shown and never believed.
 */
export function PendingCard({ item, draft, onDraft, selected, onSelect, onDecided }) {
  const isSession = item.kind === 'session'
  return (
    <article data-item={item.id} aria-label={`${isSession ? 'Session requested' : 'Held request'} ${item.id}`} className="min-w-0">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-muted">
        <PickBox item={item} checked={selected} onChange={onSelect} className="mr-1 md:hidden" />
        <Badge tone={isSession ? 'accent' : 'warn'}>{isSession ? 'session requested' : 'held request'}</Badge>
        <span className="font-mono text-xs">{cleanLine(item.id)}</span>
        <span aria-hidden="true">·</span>
        <span>asked {item.created_at ? ago(item.created_at) : ''}</span>
      </div>

      <p className="mt-2 break-words font-mono text-[0.9375rem] font-semibold text-ink">{cleanLine(item.headline)}</p>

      {item.proposal?.template && (
        <p className="mt-1 flex flex-wrap items-baseline gap-1.5 text-sm text-muted">
          template <UntrustedText text={item.proposal.template} label="Named by the agent, not verified" /> v{cleanLine(item.proposal.template_version ?? '?')}
        </p>
      )}

      {item.claim && (
        <div className="mt-3">
          <p className="mb-1 text-sm text-muted">Claimed by the agent, unverified:</p>
          <UntrustedText text={item.claim} block />
        </div>
      )}

      {item.kind === 'request' && <RequestPreview preview={item.preview} />}

      {item.caution && <Notice tone="warn" className="mt-3">{cleanLine(item.caution)}</Notice>}

      <NarrowingFields item={item} draft={draft} onChange={onDraft} />

      <div className="mt-4 flex flex-wrap gap-2">
        <DecideButton item={item} granted draft={draft} onDone={onDecided} />
        <DecideButton item={item} granted={false} draft={draft} onDone={onDecided} />
      </div>
    </article>
  )
}

function DecideButton({ item, granted, draft, onDone }) {
  const api = useApi()
  const toast = useToast()
  const { operationFor } = usePresence()
  // The request is built with the operation, from the same parse, so what is
  // sent is exactly what was signed.
  const sendRef = useRef(null)
  return (
    <GatedButton
      variant={granted ? 'primary' : 'danger'}
      label={decisionLabel(item, granted)}
      operation={async () => {
        const call = await decisionCall(item, granted, draft, { operationFor, api })
        sendRef.current = call.send
        return call.operation
      }}
      send={(proof) => sendRef.current(proof)}
      onDone={() => { toast(granted ? 'Approved' : 'Denied', { tone: 'ok' }); onDone?.(item, granted) }}
    >
      {granted ? (item.kind === 'session' ? 'Approve session' : 'Approve once') : 'Deny'}
      <span className="sr-only"> {item.id}</span>
    </GatedButton>
  )
}
