import { FingerPrintIcon } from '@heroicons/react/24/outline'
import { usePresence } from '../../hooks/usePresence.js'

/**
 * While a signature is being asked for, say what it is for, on the page,
 * before and during the platform dialog: "Touch ID to revoke session s_123".
 */
export function PresenceStatus() {
  const { signing } = usePresence()
  return (
    <div aria-live="assertive" role="status" className="pointer-events-none fixed inset-x-0 top-3 z-[70] flex justify-center px-4">
      {signing && (
        <div className="flex max-w-xl items-center gap-3 rounded-card border border-accent/40 bg-surface px-4 py-3 shadow-raised" data-presence-status="">
          <span className="inline-flex size-9 shrink-0 items-center justify-center rounded-pill bg-accent-soft text-accent">
            <FingerPrintIcon aria-hidden="true" className="size-5" />
          </span>
          <div className="min-w-0 text-sm">
            <p className="font-semibold text-ink">Touch ID to {signing.label}</p>
            <p className="text-muted">Your authenticator signs exactly this change and nothing else.</p>
          </div>
        </div>
      )}
    </div>
  )
}
