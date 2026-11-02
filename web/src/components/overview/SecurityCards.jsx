import { FingerPrintIcon, LockOpenIcon } from '@heroicons/react/20/solid'
import { useAction } from '../../hooks/useAction.js'
import { useApi } from '../../hooks/useApi.js'
import { usePresence } from '../../hooks/usePresence.js'
import { usePrompt } from '../../hooks/usePrompt.js'
import { TOUCHID_NEEDS_PASSPHRASE } from '../../lib/presence.js'
import { unlockWithPassphrase } from '../../layouts/AppLayout.jsx'
import { Badge } from '../ui/Badge.jsx'
import { Button } from '../ui/Button.jsx'
import { Card, Row } from '../ui/Card.jsx'
import { Notice } from '../ui/Notice.jsx'

/**
 * The vault is locked: unlock with Touch ID (when enrolled for unlock and the
 * browser can), or with the passphrase. The old page's lock banner.
 */
export function LockBanner({ unlockState, webauthn, onChanged }) {
  const api = useApi()
  const prompt = usePrompt()
  const presence = usePresence()
  const [run, busy] = useAction()
  const ls = unlockState || {}
  const touch = ls.has_touchid && webauthn
  const hint = !ls.has_touchid && ls.has_passphrase && webauthn
  return (
    <Notice
      tone="crit"
      title="The vault is locked."
      actions={(
        <>
          {touch && (
            <Button variant="primary" icon={FingerPrintIcon} loading={busy} onClick={() => run(() => presence.touchIdUnlock(), { done: 'Unlocked with Touch ID', after: onChanged })}>
              Unlock with Touch ID
            </Button>
          )}
          <Button
            variant={touch ? 'secondary' : 'primary'}
            icon={LockOpenIcon}
            loading={busy}
            onClick={() => run(() => unlockWithPassphrase({ api, prompt }), {
              done: (ok) => (ok === true ? 'Unlocked' : ok === null ? 'Cancelled' : 'That passphrase did not unlock the vault'),
              tone: (ok) => (ok === true ? 'ok' : 'warn'),
              after: onChanged,
            })}
          >
            {ls.has_passphrase ? 'Use passphrase' : 'Unlock'}
          </Button>
        </>
      )}
    >
      Every proxied request is refused until it is unlocked, and it stays locked across restarts.
      {hint && (
        <p className="mt-2 text-muted">
          Want to unlock with a fingerprint next time? Unlock once with your passphrase, then turn on <strong className="text-ink">Touch ID unlock</strong> on this page.
        </p>
      )}
    </Notice>
  )
}

/**
 * Change confirmation: the authenticator that signs every change. Enrolled,
 * it can be replaced (signed by the current key); not enrolled, nothing can
 * change from this page until it is.
 */
export function ConfirmationCard({ enrolled, onChanged }) {
  const presence = usePresence()
  const [run, busy] = useAction()
  if (!enrolled) {
    return (
      <Notice
        tone="warn"
        title="Changes need confirmation."
        actions={(
          <Button variant="primary" icon={FingerPrintIcon} loading={busy} onClick={() => run(() => presence.enroll(), { done: 'Authenticator enrolled', after: onChanged })}>
            Set up change confirmation
          </Button>
        )}
      >
        Set up Touch ID to confirm changes: adding a credential, approving a request, revoking a session.
        (This is separate from unlocking the vault, which you set up below.) Enrolling asks for your
        passphrase once; after that, changes need only your fingerprint.
      </Notice>
    )
  }
  return (
    <Card eyebrow="Security" title="Confirmation" padded={false}>
      <Row
        title={<>Authenticator enrolled <Badge tone="ok" dot>active</Badge></>}
        meta="Every change asks for Touch ID, and the signature covers that one operation. A browser driven by software reaches the dialog and stops there."
        actions={(
          <Button
            icon={FingerPrintIcon}
            loading={busy}
            title="Enrol a new authenticator, confirmed with the one you have now"
            onClick={() => run(() => presence.replaceKey(), { done: 'Authenticator replaced. The old one no longer confirms anything.', after: onChanged })}
          >
            Replace authenticator
          </Button>
        )}
      />
    </Card>
  )
}

/**
 * Touch ID unlock, offered when unlocked. Without a passphrase the row says
 * what to do first rather than hiding: an owner whose only factor is the
 * authenticator otherwise never learns why it is not offered.
 */
export function UnlockingCard({ unlockState, webauthn, onChanged }) {
  const presence = usePresence()
  const [run, busy] = useAction()
  const ls = unlockState || {}
  if (!webauthn || !unlockState) return null
  let row
  if (!ls.has_passphrase) {
    row = <Row title={<>Touch ID unlock <Badge tone="warn">needs a passphrase</Badge></>} meta={TOUCHID_NEEDS_PASSPHRASE} />
  } else if (ls.has_touchid) {
    row = (
      <Row
        title={<>Touch ID unlock <Badge tone="ok" dot>on</Badge></>}
        meta="Unlock with a fingerprint; your passphrase still works as recovery."
        actions={<Button icon={FingerPrintIcon} loading={busy} onClick={() => run(() => presence.disableTouchId(), { done: 'Touch ID unlock turned off', after: onChanged })}>Turn off</Button>}
      />
    )
  } else {
    row = (
      <Row
        title={<>Touch ID unlock <Badge>off</Badge></>}
        meta="Unlock the vault with a fingerprint instead of typing the passphrase. Your passphrase stays as a backup."
        actions={<Button variant="primary" icon={FingerPrintIcon} loading={busy} onClick={() => run(() => presence.enableTouchId(), { done: 'Touch ID unlock enabled', after: onChanged })}>Enable</Button>}
      />
    )
  }
  return <Card eyebrow="Security" title="Unlocking" padded={false}>{row}</Card>
}
