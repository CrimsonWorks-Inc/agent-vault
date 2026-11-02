import { ShieldCheckIcon } from '@heroicons/react/16/solid'
import { useAction } from '../../hooks/useAction.js'
import { useApi } from '../../hooks/useApi.js'
import { count } from '../../lib/format.js'
import { Button } from '../ui/Button.jsx'
import { Stat } from '../ui/Stat.jsx'

/** Four numbers, and the audit chain check beside the last. */
export function AtAGlance({ credentials, activeSessions, placeholders, auditRecords, loading }) {
  const api = useApi()
  const [run, busy] = useAction()
  const verify = () => run(() => api.get('audit/verify'), {
    done: (v) => (v.ok ? `Chain intact across ${v.count} records` : `Chain broken at record ${v.brokenAt}`),
    tone: (v) => (v.ok ? 'ok' : 'crit'),
  })
  return (
    <section aria-label="At a glance" className="rounded-card border border-line bg-surface shadow-card">
      <dl className="grid grid-cols-2 divide-line lg:grid-cols-4 [&>div]:border-line max-lg:[&>div:nth-child(-n+2)]:border-b max-lg:[&>div:nth-child(odd)]:border-r lg:[&>div:not(:last-child)]:border-r">
        <div><Stat label="Credentials" value={count(credentials)} hint="stored" loading={loading} /></div>
        <div><Stat label="Sessions" value={count(activeSessions)} hint="active" loading={loading} /></div>
        <div><Stat label="Placeholders" value={count(placeholders)} hint="live" loading={loading} /></div>
        <div>
          <Stat
            label="Audit records"
            value={auditRecords == null ? '—' : count(auditRecords)}
            hint={auditRecords == null ? 'unavailable while locked' : 'hash-chained'}
            loading={loading}
            action={<Button size="sm" variant="ghost" icon={ShieldCheckIcon} loading={busy} onClick={verify} className="-my-1 -mr-2 h-7 px-2 text-accent">Verify chain</Button>}
          />
        </div>
      </dl>
    </section>
  )
}
