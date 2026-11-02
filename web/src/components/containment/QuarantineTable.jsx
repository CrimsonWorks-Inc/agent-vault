import { NoSymbolIcon } from '@heroicons/react/20/solid'
import { KeyIcon } from '@heroicons/react/24/outline'
import { useAction } from '../../hooks/useAction.js'
import { useApi, useSlowCache } from '../../hooks/useApi.js'
import { usePaged } from '../../hooks/usePaged.js'
import { usePresence } from '../../hooks/usePresence.js'
import { usePrompt } from '../../hooks/usePrompt.js'
import { useToast } from '../../hooks/useToast.js'
import { ago } from '../../lib/format.js'
import { cleanLine } from '../../lib/text.js'
import { Badge } from '../ui/Badge.jsx'
import { Button } from '../ui/Button.jsx'
import { Card } from '../ui/Card.jsx'
import { DataTable } from '../ui/DataTable.jsx'
import { GatedButton } from '../ui/GatedButton.jsx'
import { Notice } from '../ui/Notice.jsx'
import { Pagination } from '../ui/Pagination.jsx'
import { SearchInput } from '../ui/SearchInput.jsx'
import { UntrustedText } from '../ui/UntrustedText.jsx'

/** "1 held request denied", for the toasts after a quarantine or a release. */
const heldDenied = (n) => (n ? `; ${n} held request${n > 1 ? 's' : ''} denied` : '')

/**
 * Who quarantined it, when, and why. The reason is whatever whoever
 * quarantined it typed (an agent can quarantine), so it is shown as theirs.
 */
export function QuarantineNote({ q }) {
  const reason = q.reason_untrusted
  return (
    <div className="space-y-1 text-sm text-muted">
      <p>
        quarantined {q.since ? ago(q.since) : ''} by <span className="font-mono text-ink">{cleanLine(q.by)}</span>
        {q.rule_id ? <> (tripwire <span className="font-mono text-ink">{cleanLine(q.rule_id)}</span>)</> : null}
      </p>
      {reason ? <UntrustedText text={reason} source="whoever quarantined it" /> : null}
    </div>
  )
}

/**
 * Every credential, and whether it is quarantined. Quarantine stops every use
 * of one credential at once and is open to anything that can reach the
 * vault, because it only takes away; releasing it gives capability back, so
 * it is signed (cred.release).
 */
export function QuarantineTable({ onChanged }) {
  const list = usePaged('credentials')
  const changed = () => { list.reload(); onChanged?.() }
  return (
    <Card
      eyebrow="Quarantine"
      title="Stop one credential"
      description="Every use stops at once (AV_QUARANTINED) and anything waiting on it is denied. Its sessions are paused, not revoked."
      padded={false}
      actions={<SearchInput value={list.q} onChange={list.setQ} label="Search credentials" placeholder="Search credentials…" />}
    >
      {list.error && !list.loading && (
        <Notice tone="crit" className="m-4" title="Could not read the credentials." actions={<Button size="sm" onClick={list.reload}>Try again</Button>}>
          {list.error.message}
        </Notice>
      )}
      <DataTable
        caption="Credentials and their quarantine"
        rows={list.items}
        rowKey="slug"
        loading={list.loading}
        empty={list.q
          ? { icon: KeyIcon, title: 'No credential matches that search' }
          : { icon: KeyIcon, title: 'No credentials yet', body: 'There is nothing to quarantine until a credential is stored.' }}
        columns={[
          {
            key: 'slug',
            header: 'Credential',
            primary: true,
            cell: (c) => (
              <span className="inline-flex flex-wrap items-center gap-2">
                <span className="font-mono font-medium">{cleanLine(c.slug)}</span>
                <Badge mono>{cleanLine(c.kind)}</Badge>
              </span>
            ),
          },
          {
            key: 'state',
            header: 'State',
            cell: (c) => (c.quarantine
              ? <div className="space-y-1"><Badge tone="crit" dot>quarantined</Badge><QuarantineNote q={c.quarantine} /></div>
              : <Badge tone="ok" dot>in use</Badge>),
          },
          {
            key: 'actions',
            header: 'Actions',
            align: 'right',
            cell: (c) => (c.quarantine
              ? <ReleaseButton slug={c.slug} onDone={changed} />
              : <QuarantineButton slug={c.slug} onDone={changed} />),
          },
        ]}
      />
      <div className="border-t border-line px-4"><Pagination {...list.pagination} label="Credential pages" /></div>
    </Card>
  )
}

/** Ungated on purpose: it only takes capability away. The reason is optional. */
export function QuarantineButton({ slug, onDone }) {
  const api = useApi()
  const slow = useSlowCache()
  const prompt = usePrompt()
  const [run, busy] = useAction()
  const go = async () => {
    const reason = await prompt.text({
      title: `Quarantine ${slug}`,
      body: 'Nothing can use it until you release it.',
      label: 'Reason (optional)',
      maxLength: 200,
      submit: 'Quarantine',
      danger: true,
    })
    if (reason === null) return
    await run(() => api.post('credentials/quarantine', { slug, ...(reason ? { reason } : {}) }), {
      done: (r) => `Quarantined ${slug}${heldDenied(Number(r?.denied_approvals) || 0)}`,
      tone: 'warn',
      after: () => { slow.clear(); onDone?.() },
    })
  }
  return (
    <Button size="sm" variant="danger" icon={NoSymbolIcon} loading={busy} onClick={go}>
      Quarantine<span className="sr-only"> {slug}</span>
    </Button>
  )
}

/** Signed: a release gives every paused session back its use of the credential. */
export function ReleaseButton({ slug, onDone }) {
  const api = useApi()
  const slow = useSlowCache()
  const toast = useToast()
  const { operationFor } = usePresence()
  return (
    <GatedButton
      size="sm"
      label={`release ${slug} from quarantine`}
      operation={() => operationFor('cred.release', { slug })}
      send={(proof) => api.post('credentials/release', { slug, presence: proof })}
      onDone={() => { toast(`Released ${slug}`, { tone: 'ok' }); slow.clear(); onDone?.() }}
    >
      Release<span className="sr-only"> {slug}</span>
    </GatedButton>
  )
}
