import { LockClosedIcon, LockOpenIcon } from '@heroicons/react/20/solid'
import { useAction } from '../../hooks/useAction.js'
import { useApi, useSlowCache } from '../../hooks/useApi.js'
import { usePresence } from '../../hooks/usePresence.js'
import { usePrompt } from '../../hooks/usePrompt.js'
import { unlockWithPassphrase } from '../../layouts/AppLayout.jsx'
import { Badge } from '../ui/Badge.jsx'
import { Button } from '../ui/Button.jsx'
import { Card, Row } from '../ui/Card.jsx'

/**
 * The lock (the old page's sidebar "Lock vault" / "Unlock vault"). Locking is a
 * signed change (POST lock, op vault.lock), confirmed in a page-drawn dialog
 * first. Unlocking is not behind the change gate: the passphrase is the proof.
 */
export function VaultLockCard({ locked, lockState, onChanged }) {
  const api = useApi()
  const slow = useSlowCache()
  const presence = usePresence()
  const prompt = usePrompt()
  const [run, busy] = useAction()
  const after = () => { slow.clear(); onChanged?.() }
  const ls = lockState || {}

  const lock = () => run(async () => {
    const ok = await prompt.confirm({
      title: 'Lock the vault?',
      body: 'Every proxied request is refused until it is unlocked, and it stays locked across restarts.',
      submit: 'Lock with Touch ID',
      danger: true,
    })
    if (!ok) return null
    await presence.lock()
    return true
  }, { done: (r) => (r ? 'Vault locked' : null), after })

  const unlock = () => run(() => unlockWithPassphrase({ api, prompt }), {
    done: (ok) => (ok === true ? 'Unlocked' : ok === null ? 'Cancelled' : 'That passphrase did not unlock the vault'),
    tone: (ok) => (ok === true ? 'ok' : 'warn'),
    after,
  })

  return (
    <Card eyebrow="Vault" title="Lock" padded={false} footer={<p className="text-sm text-muted">No credential value is ever sent to this page, and every change needs a fingerprint.</p>}>
      <Row
        title={<>Vault lock {locked ? <Badge tone="crit" dot>locked</Badge> : <Badge tone="ok" dot>unlocked</Badge>}</>}
        meta={locked
          ? 'Every proxied request is refused until you unlock.'
          : `Locking refuses every proxied request until you unlock${ls.has_passphrase ? ', and with a passphrase the key is wrapped, so a locked vault on a stolen disk is just ciphertext' : ''}.`}
        actions={locked
          ? <Button variant="primary" icon={LockOpenIcon} loading={busy} onClick={unlock}>{ls.has_passphrase ? 'Unlock with passphrase' : 'Unlock'}</Button>
          : <Button variant="danger" icon={LockClosedIcon} loading={busy} onClick={lock} title="Asks for Touch ID to lock the vault">Lock vault</Button>}
      />
      <Row
        title={<>Passphrase {ls.has_passphrase ? <Badge tone="ok">set</Badge> : <Badge tone="warn">none</Badge>}</>}
        meta={ls.has_passphrase
          ? 'The recovery factor, and what the command line uses. It is changed from the command line only.'
          : 'Without one the lock is not cryptographic, and Touch ID unlock is not offered. Set one from the command line.'}
      />
    </Card>
  )
}
