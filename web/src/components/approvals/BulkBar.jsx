import { useRef } from 'react'
import { useApi } from '../../hooks/useApi.js'
import { usePresence } from '../../hooks/usePresence.js'
import { useToast } from '../../hooks/useToast.js'
import { Button } from '../ui/Button.jsx'
import { GatedButton } from '../ui/GatedButton.jsx'
import { bulkDecisions, bulkOutcome } from './decide.js'

/**
 * Several decisions, one signature (the old page's bulk bar). It appears only
 * when something is ticked and counts what is. `picked` is the ticked items
 * in the order they are shown; nothing else is ever in the list.
 */
export function BulkBar({ picked, onClear, onDone }) {
  if (!picked.length) return null
  return (
    <div role="region" aria-label="Decide the selected" className="sticky top-16 z-20 rounded-card border border-accent/40 bg-surface px-4 py-3 shadow-raised lg:top-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-sm text-muted">
          <strong className="font-semibold text-ink"><span data-testid="bulk-count">{picked.length}</span> selected</strong>
          {' · '}one signature covers exactly these, and nothing that arrives after.
        </p>
        <div className="flex flex-wrap gap-2">
          <BulkButton picked={picked} granted onDone={onDone} />
          <BulkButton picked={picked} granted={false} onDone={onDone} />
          <Button variant="ghost" onClick={onClear}>Clear</Button>
        </div>
      </div>
    </div>
  )
}

function BulkButton({ picked, granted, onDone }) {
  const api = useApi()
  const toast = useToast()
  const { operationFor } = usePresence()
  const sent = useRef(null)
  return (
    <GatedButton
      variant={granted ? 'primary' : 'danger'}
      label={`${granted ? 'approve' : 'deny'} ${picked.length} selected`}
      operation={async () => {
        const decisions = bulkDecisions(picked, granted)
        sent.current = decisions
        return operationFor('pending.decide_many', { decisions })
      }}
      send={(proof) => api.post('pending/decide-many', { decisions: sent.current, presence: proof })}
      onDone={(answered) => {
        toast(bulkOutcome(sent.current, answered, granted), { tone: 'ok' })
        if (answered?.note) toast(answered.note, { tone: 'info' })
        onDone?.()
      }}
    >
      {granted ? 'Approve selected' : 'Deny selected'}
    </GatedButton>
  )
}
