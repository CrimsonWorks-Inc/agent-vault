import { FunnelIcon, KeyIcon, MagnifyingGlassIcon } from '@heroicons/react/24/outline'
import { FolderIcon } from '@heroicons/react/16/solid'
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
export function CredentialsTable({ list, tests, onTest, onManage, onRotate, onChanged, onMove, selected, onSelect, narrowed = false, showFolder = true }) {
  const searching = Boolean(list.q.trim())
  const pageSlugs = list.items.map((c) => c.slug)
  const allOnPage = pageSlugs.length > 0 && pageSlugs.every((s) => selected?.has(s))
  const toggleAll = () => onSelect?.(allOnPage ? new Set([...selected].filter((s) => !pageSlugs.includes(s))) : new Set([...(selected ?? []), ...pageSlugs]))
  const toggle = (slug) => {
    const next = new Set(selected)
    if (next.has(slug)) next.delete(slug)
    else next.add(slug)
    onSelect?.(next)
  }
  return (
    <DataTable
      caption="Stored credentials"
      rows={list.items}
      rowKey="slug"
      loading={list.loading}
      empty={searching
        ? { icon: MagnifyingGlassIcon, title: 'Nothing matches', body: `No credential here matches “${cleanLine(list.q.trim())}”.` }
        : narrowed
          ? { icon: FunnelIcon, title: 'Nothing here', body: 'No credential is in this folder with these filters.' }
          : { icon: KeyIcon, title: 'No credentials yet', body: 'Add one below.' }}
      columns={[
        ...(onSelect ? [{
          key: 'select',
          className: 'w-px',
          // On cards the header would repeat as each row's label; phones move
          // one at a time from the row menu.
          hideOnCard: true,
          header: <input type="checkbox" className="size-4 accent-accent" checked={allOnPage} onChange={toggleAll} aria-label="Select every credential on this page" />,
          cell: (c) => <input type="checkbox" className="size-4 accent-accent" checked={selected?.has(c.slug) ?? false} onChange={() => toggle(c.slug)} aria-label={`Select ${cleanLine(c.slug)}`} />,
        }] : []),
        { key: 'slug', header: 'Name', primary: true, cell: (c) => <CredentialName c={c} showFolder={showFolder} /> },
        { key: 'details', header: 'Details', cell: (c) => <CredentialDetails c={c} test={tests.get(c.slug)} /> },
        {
          key: 'actions', header: 'Actions', align: 'right', className: 'w-px',
          cell: (c) => <CredentialActions c={c} onTest={onTest} onManage={onManage} onRotate={onRotate} onChanged={onChanged} onMove={onMove} />,
        },
      ]}
    />
  )
}

export function CredentialName({ c, showFolder = true }) {
  return (
    <span className="flex min-w-0 flex-col gap-0.5">
      <span className="flex flex-wrap items-center gap-1.5">
        <span className="font-mono text-sm font-medium text-ink">{cleanLine(c.slug)}</span>
        <Badge mono>{cleanLine(c.kind)}</Badge>
        {credentialBadges(c).map((b) => <Badge key={b.text} tone={b.tone} dot>{b.text}</Badge>)}
      </span>
      {showFolder && typeof c.folder === 'string' && (
        <span className="flex items-center gap-1 text-xs text-muted">
          <FolderIcon aria-hidden="true" className="size-3.5 shrink-0" />
          <span className="sr-only">Folder </span>
          <span className="truncate font-mono">{cleanLine(c.folder).split('/').join(' / ')}</span>
        </span>
      )}
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
