// Containment: what to pull when an agent does something you did not expect
// (contract U5). Panic and the tripwires are the old page's containment card
// (components/overview/ContainmentCard.jsx, shared with the Overview);
// quarantine was a row action on the old page's Credentials page and lives here
// too, beside the history of every tripwire that fired.
//
// Panic and quarantine only take capability away, so neither asks for a
// fingerprint. Releasing a credential gives capability back, so it is signed,
// and this page signs every tripwire change, turning them on included. (The
// daemon lets the CLI turn tripwires on unsigned only when rules are already
// stored; the first turn-on stores the defaults and needs confirmation.)

import { useCallback } from 'react'
import { useApiQuery, useSlowCache } from '../hooks/useApi.js'
import { useVault } from '../hooks/useVault.js'
import { Button } from '../components/ui/Button.jsx'
import { Notice } from '../components/ui/Notice.jsx'
import { PageHeader } from '../components/ui/PageHeader.jsx'
import { ContainmentCard } from '../components/overview/ContainmentCard.jsx'
import { FiredTable } from '../components/containment/FiredTable.jsx'
import { QuarantineTable } from '../components/containment/QuarantineTable.jsx'
import { LockedAudit } from './Audit.jsx'
import { readFired, readTripwires } from './Overview.jsx'

/**
 * The tripwire settings and the last few that fired, through the Overview's
 * own readers and under the same cache keys, so the two pages share one
 * shape: tripwires walks every cursor page (paged=1) and puts the rules back
 * beside `enabled`, `rules_saved` and `defaults`.
 */
export async function loadContainment(api, slow, locked) {
  const quiet = (p) => p.catch(() => null)
  const [tripwires, fired] = await Promise.all([
    slow.get('tripwires', () => readTripwires(api.get)),
    locked ? null : quiet(slow.get('fired', () => readFired(api.get))),
  ])
  return { tripwires, fired }
}

export function Containment() {
  const vault = useVault()
  const slow = useSlowCache()
  const locked = vault.locked === true
  const q = useApiQuery((api) => loadContainment(api, slow, locked), [locked])
  const changed = useCallback(() => { slow.clear(); q.reload(); vault.refresh() }, [slow, q, vault])

  return (
    <>
      <PageHeader
        eyebrow="agent-vault"
        title="Containment"
        description="End every session at once, stop one credential, or let tripwires revoke a session that behaves like an attack. Panic and quarantine ask for no fingerprint, because each only takes capability away; nothing comes back by itself. Changing tripwires here, turning them on included, asks you to confirm."
      />
      <div className="space-y-4">
        {q.error && !q.data && (
          <Notice tone="crit" title="Could not read the tripwire settings." actions={<Button size="sm" onClick={q.reload}>Try again</Button>}>
            {q.error.message}
          </Notice>
        )}
        {/* Panic is always here, even before (or without) the tripwire settings. */}
        <ContainmentCard tripwires={q.data?.tripwires ?? null} fired={q.data?.fired ?? null} onChanged={changed} />
        {!q.data && q.loading && <p role="status" className="sr-only">Loading the tripwire settings</p>}
        <QuarantineTable onChanged={changed} />
        {locked
          ? <LockedAudit />
          : <FiredTable />}
      </div>
    </>
  )
}
