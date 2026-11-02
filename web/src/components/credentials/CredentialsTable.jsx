import { KeyIcon, MagnifyingGlassIcon } from '@heroicons/react/24/outline'
import { Badge } from '../ui/Badge.jsx'
import { DataTable } from '../ui/DataTable.jsx'
import { UntrustedText } from '../ui/UntrustedText.jsx'
import { cleanLine } from '../../lib/text.js'
import { credentialBadges, credentialFacts, expiryLine, pinsText, quarantineLine, testParts } from './credentialText.js'
import { CredentialActions } from './CredentialActions.jsx'

/**
 * The stored credentials, one row each: what it is, what to notice about it,
 * and what can be done to it. A table on md and up, cards below.
 */
export function CredentialsTable({ list, tests, onTest, onManage, onRotate, onChanged }) {
  const searching = Boolean(list.q.trim())
  return (
    <DataTable
      caption="Stored credentials"
      rows={list.items}
      rowKey="slug"
      loading={list.loading}
      empty={searching
        ? { icon: MagnifyingGlassIcon, title: 'Nothing matches', body: `No credential matches “${list.q.trim()}”.` }
        : { icon: KeyIcon, title: 'No credentials yet', body: 'Add one below.' }}
      columns={[
        { key: 'slug', header: 'Name', primary: true, cell: (c) => <CredentialName c={c} /> },
        { key: 'details', header: 'Details', cell: (c) => <CredentialDetails c={c} test={tests.get(c.slug)} /> },
        {
          key: 'actions', header: 'Actions', align: 'right', className: 'w-px',
          cell: (c) => <CredentialActions c={c} onTest={onTest} onManage={onManage} onRotate={onRotate} onChanged={onChanged} />,
        },
      ]}
    />
  )
}

export function CredentialName({ c }) {
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      <span className="font-mono text-sm font-medium text-ink">{cleanLine(c.slug)}</span>
      <Badge mono>{cleanLine(c.kind)}</Badge>
      {credentialBadges(c).map((b) => <Badge key={b.text} tone={b.tone} dot>{b.text}</Badge>)}
    </span>
  )
}

function CredentialDetails({ c, test }) {
  const pins = pinsText(c.pins)
  const expiry = expiryLine(c)
  return (
    <div className="min-w-0 space-y-1 text-sm">
      <p className="flex flex-wrap gap-x-3 gap-y-0.5 text-muted">
        {credentialFacts(c).map(([k, v]) => (
          <span key={k}>
            {k} <span className={k === 'host' || k === 'version' ? 'text-ink' : 'font-mono text-[0.8125rem] text-ink'}>{cleanLine(v) || '—'}</span>
          </span>
        ))}
      </p>
      {pins && <p className="font-mono text-xs text-muted">{cleanLine(pins)}</p>}
      {expiry && <p className="text-xs text-warn">{expiry}</p>}
      {c.quarantine && <QuarantineLine q={c.quarantine} />}
      {test && <TestLine test={test} />}
    </div>
  )
}

/** Who quarantined it and why; the reason is whatever they wrote. */
export function QuarantineLine({ q }) {
  const reason = q.reason_untrusted
  return (
    <div className="space-y-1 text-xs text-crit">
      <p>{quarantineLine(q)}</p>
      {reason && <UntrustedText text={reason} source="whoever quarantined it" />}
    </div>
  )
}

/** The last probe of this credential (F12). */
export function TestLine({ test }) {
  const t = testParts(test)
  if (t.error) {
    return <p className="text-xs" data-test-line=""><span className="text-muted">test: </span><span className="font-medium text-crit">{cleanLine(t.error)}</span></p>
  }
  return (
    <p className="text-xs text-muted" data-test-line="">
      test: <span className={t.ok ? 'font-medium text-ok' : 'font-medium text-crit'}>{cleanLine(t.status)}</span>
      <span className="font-mono">{cleanLine(t.rest)}</span>
    </p>
  )
}
