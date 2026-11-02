import { useState } from 'react'
import { ExclamationTriangleIcon } from '@heroicons/react/20/solid'
import { useAction } from '../../hooks/useAction.js'
import { useApi, useSlowCache } from '../../hooks/useApi.js'
import { usePaged } from '../../hooks/usePaged.js'
import { usePresence } from '../../hooks/usePresence.js'
import { useToast } from '../../hooks/useToast.js'
import { ago, span } from '../../lib/format.js'
import { cleanLine } from '../../lib/text.js'
import { Badge } from '../ui/Badge.jsx'
import { Button } from '../ui/Button.jsx'
import { Card, Row } from '../ui/Card.jsx'
import { ConfirmDialog } from '../ui/ConfirmDialog.jsx'
import { Disclosure } from '../ui/Disclosure.jsx'
import { Field } from '../ui/Field.jsx'
import { GatedButton } from '../ui/GatedButton.jsx'
import { Input } from '../ui/Input.jsx'
import { Notice } from '../ui/Notice.jsx'
import { Pagination } from '../ui/Pagination.jsx'
import { SearchInput } from '../ui/SearchInput.jsx'
import { Textarea } from '../ui/Textarea.jsx'
import { readRules, shownRules, toggleBody } from './tripwires.js'

/**
 * Panic, and the tripwires that can pull it for you (F16). Panic is open on
 * purpose: in an emergency a fingerprint prompt only slows you down, and it
 * only takes away. This page signs every tripwire change, turning them on
 * included.
 *
 * `tripwires` is the complete settings snapshot (every rule, read through
 * every page): the editor and the signed bodies work from it, so a rule on
 * another page of the list, or hidden by a search, is never dropped. The
 * list itself is a page of the server's rules, with search and paging (U3,
 * U4), read again whenever the snapshot changes.
 */
export function ContainmentCard({ tripwires, fired, onChanged }) {
  const tw = tripwires
  const { rules, shown } = shownRules(tw)
  const on = tw?.enabled === true
  const recent = Array.isArray(fired) ? fired : []
  return (
    <Card eyebrow="Containment" title="Emergency controls" padded={false}>
      <Row
        title="Panic"
        meta="Revoke every session, infinite ones included, and deny everything waiting for you. Nothing comes back by itself. No fingerprint is asked: in an emergency it only slows you down."
        actions={<PanicButton onDone={onChanged} />}
      />
      {tw && (
        <Row
          title={<>Tripwires <Badge tone={on ? 'ok' : 'neutral'} dot>{on ? 'on' : 'off'}</Badge></>}
          meta={on
            ? 'A session that trips one of these is revoked before its refused request returns.'
            : rules.length ? 'Off. Turning them on uses your rules below.'
              : tw.rules_saved === false ? 'Off. Turning them on stores and uses the default rules below.'
                : 'Off. Turning them on stores and uses the default rules.'}
          actions={<TripwireToggle tw={tw} onDone={onChanged} />}
        >
          <RuleList key={JSON.stringify([tw.enabled, tw.rules_saved, tw.rules])} />
          {recent.length > 0 && (
            <p className="mt-2 text-sm text-muted">
              Fired recently:{' '}
              {recent.map((r, i) => (
                <span key={`${r.rule_id}-${r.ts}-${i}`}>
                  {i > 0 && ' · '}
                  <span className="font-mono text-ink">{cleanLine(r.rule_id)}</span> {r.ts ? ago(r.ts) : ''} → {cleanLine(r.action || '')}
                </span>
              ))}
            </p>
          )}
          <RulesEditor shown={shown} onDone={onChanged} />
        </Row>
      )}
    </Card>
  )
}

/**
 * The rules in force, one per line: what trips it, how often, and what it
 * does. A page at a time from the server, searchable, like every list.
 */
export function RuleList() {
  const list = usePaged('tripwires', { storageKey: 'agent-vault.page-size.tripwire-rules' })
  return (
    <div className="mt-3 space-y-2">
      <SearchInput value={list.q} onChange={list.setQ} label="Search tripwire rules" placeholder="Search rule, code, action…" />
      {list.error && !list.loading && (
        <Notice tone="crit" role="alert" title="Could not read the tripwire rules." actions={<Button size="sm" onClick={list.reload}>Try again</Button>}>
          {list.error.message}
        </Notice>
      )}
      {!list.items.length
        ? !list.loading && !list.error && <p className="text-sm text-muted">{list.q ? 'No rule matches that search.' : 'No rules.'}</p>
        : (
          <ul aria-label="Tripwire rules" className="divide-y divide-line overflow-hidden rounded-control border border-line bg-sunken/60">
            {list.items.map((r, i) => <RuleLine key={`${r?.id}-${i}`} r={r} />)}
          </ul>
        )}
      <Pagination {...list.pagination} label="Tripwire rule pages" />
    </div>
  )
}

function RuleLine({ r }) {
  const what = (r?.codes || []).length ? r.codes.join(', ') : r?.rule_prefix ? `${r.rule_prefix}*` : '?'
  return (
    <li className="grid grid-cols-[1fr_auto] gap-x-3 gap-y-0.5 px-3 py-2 text-xs">
      <span className="font-mono font-medium text-ink">{r?.id}</span>
      <span className="text-right text-muted"><span className="tabular-nums">{r?.threshold}</span> in {span(r?.window_s)}</span>
      <span className="min-w-0 break-all font-mono text-muted">{what}</span>
      <span className="text-right font-mono text-crit">→ {r?.action}</span>
    </li>
  )
}

function TripwireToggle({ tw, onDone }) {
  const api = useApi()
  const slow = useSlowCache()
  const toast = useToast()
  const { operationFor } = usePresence()
  const on = tw?.enabled === true
  // With no rules stored yet, turning them on also stores the defaults.
  const body = toggleBody(tw)
  return (
    <GatedButton
      variant={on ? 'secondary' : 'primary'}
      label={on ? 'turn tripwires off' : 'turn tripwires on'}
      operation={() => operationFor('tripwires.set', body)}
      send={(proof) => api.post('tripwires', { ...body, presence: proof })}
      onDone={() => { toast(on ? 'Tripwires off' : 'Tripwires on', { tone: 'ok' }); slow.clear(); onDone?.() }}
    >
      {on ? 'Turn off' : 'Turn on'}
    </GatedButton>
  )
}

function RulesEditor({ shown, onDone }) {
  const api = useApi()
  const slow = useSlowCache()
  const toast = useToast()
  const { operationFor } = usePresence()
  const [text, setText] = useState(() => JSON.stringify(shown, null, 2))
  const [error, setError] = useState('')

  const read = () => readRules(text)
  return (
    <Disclosure title="Edit rules" className="mt-3">
      <Field label="Rules (JSON)" error={error}>
        <Textarea mono rows={8} value={text} onChange={(e) => { setText(e.target.value); setError('') }} />
      </Field>
      <div className="mt-2">
        <GatedButton
          label="save tripwire rules"
          operation={async () => { const rules = read(); return operationFor('tripwires.set', { rules }) }}
          send={(proof) => api.post('tripwires', { rules: read(), presence: proof })}
          onDone={() => { toast('Tripwire rules saved', { tone: 'ok' }); slow.clear(); onDone?.() }}
          onError={(e) => { setError(e.message); toast(e.message, { tone: 'crit' }) }}
        >
          Save rules
        </GatedButton>
      </div>
    </Disclosure>
  )
}

/** Panic, confirmed in a dialog this page draws, never window.confirm. */
function PanicButton({ onDone }) {
  const api = useApi()
  const slow = useSlowCache()
  const [open, setOpen] = useState(false)
  const [lock, setLock] = useState(false)
  const [reason, setReason] = useState('')
  const [run, busy] = useAction()
  const close = () => { setOpen(false); setLock(false); setReason('') }
  const go = () => run(async () => {
    const r = await api.post('panic', { lock, ...(reason.trim() ? { reason: reason.trim() } : {}) })
    close()
    return r
  }, {
    done: (r) => `Panic: ${r.revoked_sessions ?? 0} sessions revoked · ${r.denied_approvals ?? 0} held requests denied`
      + ` · ${r.denied_session_requests ?? 0} session requests denied${r.locked ? ' · vault locked' : ''}`,
    tone: 'warn',
    after: () => { slow.clear(); onDone?.() },
  })
  return (
    <>
      <Button variant="panic" icon={ExclamationTriangleIcon} onClick={() => setOpen(true)}>Panic</Button>
      <ConfirmDialog
        open={open}
        danger
        busy={busy}
        title="Panic: end every session now"
        body="Every session is revoked, infinite ones included, and everything waiting for you is denied. Nothing comes back by itself."
        confirmLabel="Panic now"
        onCancel={close}
        onConfirm={go}
      >
        <div className="space-y-4">
          <label className="flex items-center gap-2 text-sm text-ink">
            <input type="checkbox" checked={lock} onChange={(e) => setLock(e.target.checked)} className="size-4 accent-crit" />
            Lock the vault too
          </label>
          <Field label="Reason, for the audit log" optional>
            <Input value={reason} maxLength={200} onChange={(e) => setReason(e.target.value)} autoComplete="off" />
          </Field>
        </div>
      </ConfirmDialog>
    </>
  )
}
