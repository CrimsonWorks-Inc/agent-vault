// Settings: the authenticator that confirms every change, Touch ID unlock,
// and the lock (contract U5). In the old page these were the Overview's
// Confirmation and Unlocking cards, its lock banner, and the sidebar's lock
// button; the cards are components/overview/SecurityCards.jsx, shared with
// the Overview, so the two pages cannot drift.

import { useCallback } from 'react'
import { useApiQuery } from '../hooks/useApi.js'
import { usePresence } from '../hooks/usePresence.js'
import { useVault } from '../hooks/useVault.js'
import { prfSupported } from '../lib/presence.js'
import { Badge } from '../components/ui/Badge.jsx'
import { Card } from '../components/ui/Card.jsx'
import { Notice } from '../components/ui/Notice.jsx'
import { PageHeader } from '../components/ui/PageHeader.jsx'
import { Skeleton } from '../components/ui/Skeleton.jsx'
import { ConfirmationCard, LockBanner, UnlockingCard } from '../components/overview/SecurityCards.jsx'
import { VaultLockCard } from '../components/settings/VaultLockCard.jsx'
import { Cmd } from '../components/docs/Prose.jsx'

/** Presence state and the unlock factors, each standing alone (the old page's `quiet`). */
export async function loadSettings(api, presence) {
  const [unlockState, lockState] = await Promise.all([
    api.get('unlock/state').catch(() => null),
    api.get('lockstate').catch(() => null),
    presence.refresh(),
  ])
  return { unlockState, lockState }
}

export function Settings() {
  const presence = usePresence()
  const vault = useVault()
  const q = useApiQuery((api) => loadSettings(api, presence), [])
  const changed = useCallback(() => { q.reload(); vault.refresh() }, [q, vault])
  const webauthn = prfSupported()
  const locked = vault.locked === true
  const cli = vault.context.cli

  return (
    <>
      <PageHeader
        eyebrow="agent-vault"
        title="Settings"
        status={presence.known ? (presence.enrolled ? <Badge tone="ok" dot>confirmation on</Badge> : <Badge tone="warn" dot>confirmation not set up</Badge>) : null}
        description="Two separate protections: the authenticator that confirms every change an agent could not make on its own, and the lock that decides whether the vault can be used at all."
      />
      {!q.data ? (
        <div role="status" aria-label="Loading settings" className="grid gap-4 lg:grid-cols-2">
          {[0, 1].map((i) => (
            <div key={i} className="space-y-3 rounded-card border border-line bg-surface p-5"><Skeleton className="w-1/3" /><Skeleton className="w-2/3" /><Skeleton className="w-1/2" /></div>
          ))}
        </div>
      ) : (
        <div className="space-y-4">
          {!webauthn && (
            <Notice tone="warn" title="This browser has no WebAuthn.">
              No change can be confirmed and Touch ID cannot unlock from here. The command line can make every change.
            </Notice>
          )}
          {locked && <LockBanner unlockState={q.data.unlockState} webauthn={webauthn} onChanged={changed} />}
          <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
            <div className="min-w-0 space-y-4">
              {presence.known && <ConfirmationCard enrolled={presence.enrolled} onChanged={changed} />}
              {!locked && <UnlockingCard unlockState={q.data.unlockState} webauthn={webauthn} onChanged={changed} />}
              {!locked && !q.data.unlockState && webauthn && (
                <Notice tone="warn" title="Could not read the unlock factors.">Touch ID unlock is managed here once the daemon answers.</Notice>
              )}
            </div>
            <div className="min-w-0 space-y-4">
              <VaultLockCard locked={locked} lockState={q.data.lockState || vault.lockState} onChanged={changed} />
              <Card eyebrow="Command line" title="The same, from a terminal">
                <Cmd code={`${cli} passphrase set`} caption="Set the passphrase: the recovery factor, and what makes the lock cryptographic." />
                <Cmd code={`${cli} lock\n${cli} unlock`} />
              </Card>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
