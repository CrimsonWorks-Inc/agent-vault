import { useState } from 'react'
import { AdjustmentsHorizontalIcon, DocumentMagnifyingGlassIcon } from '@heroicons/react/16/solid'
import { useApi } from '../../hooks/useApi.js'
import { usePresence } from '../../hooks/usePresence.js'
import { useToast } from '../../hooks/useToast.js'
import { cleanLine } from '../../lib/text.js'
import { Button } from '../ui/Button.jsx'
import { GatedButton } from '../ui/GatedButton.jsx'
import { Modal } from '../ui/Modal.jsx'
import { NARROWINGS } from './sessionLogic.js'

/**
 * Details for any session; for a live one, the three one-click narrowings
 * (F15) and Revoke. Each narrowing and the revoke is signed over exactly the
 * body it sends (session.narrow, session.revoke).
 */
export function SessionActions({ s, onDetails, onNarrowed, onChanged }) {
  const api = useApi()
  const presence = usePresence()
  const toast = useToast()
  const [narrowing, setNarrowing] = useState(false)
  const sid = s.id
  const active = s.state === 'active'

  return (
    <div className="flex flex-wrap items-center gap-1.5 md:flex-nowrap md:justify-end">
      <Button size="sm" icon={DocumentMagnifyingGlassIcon} onClick={() => onDetails(sid)} aria-label={`Details of session ${sid}`}>Details</Button>
      {active && (
        <>
          <Button size="sm" icon={AdjustmentsHorizontalIcon} onClick={() => setNarrowing(true)} aria-label={`Narrow session ${sid}`}>Narrow</Button>
          <GatedButton
            size="sm"
            variant="danger"
            label={`revoke session ${sid}`}
            operation={() => presence.operationFor('session.revoke', { sid })}
            send={(proof) => api.del('sessions', { sid }, { presence: proof })}
            onDone={() => { toast('Revoked', { tone: 'ok' }); onChanged?.() }}
            aria-label={`Revoke session ${sid}`}
          >
            Revoke
          </GatedButton>
          <NarrowDialog
            open={narrowing}
            s={s}
            onClose={() => setNarrowing(false)}
            onDone={(which, result) => { setNarrowing(false); onNarrowed?.(sid, which, result) }}
          />
        </>
      )}
    </div>
  )
}

/**
 * The three narrowings, each named with what it does. Nothing here can widen
 * a live session.
 */
function NarrowDialog({ open, s, onClose, onDone }) {
  const api = useApi()
  const presence = usePresence()
  const toast = useToast()
  const sid = s.id
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={`Narrow ${cleanLine(s.label ?? '') || sid}`}
      description="Each of these only takes capability away, while the session runs. Nothing here can widen a live session."
      footer={<Button onClick={onClose}>Cancel</Button>}
    >
      <ul className="divide-y divide-line">
        {Object.entries(NARROWINGS).map(([key, which]) => (
          <li key={key} className="flex flex-col gap-2 py-3 first:pt-0 last:pb-0 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <p className="text-sm font-medium text-ink">{which.label}</p>
              <p className="text-sm text-muted">{which.hint}</p>
            </div>
            <GatedButton
              size="sm"
              label={`${which.label.toLowerCase()} on session ${sid}`}
              title={which.hint}
              operation={() => presence.operationFor('session.narrow', which.body(sid))}
              send={(proof) => api.post('sessions/narrow', { ...which.body(sid), presence: proof })}
              onDone={(result) => { toast(which.title, { tone: 'ok' }); onDone(key, result) }}
              data-narrow={key}
            >
              {which.label}
            </GatedButton>
          </li>
        ))}
      </ul>
    </Modal>
  )
}
