import { useState } from 'react'
import { ArrowPathIcon, BeakerIcon, LockClosedIcon, ShieldCheckIcon, TrashIcon } from '@heroicons/react/16/solid'
import { useApi, useSlowCache } from '../../hooks/useApi.js'
import { usePresence } from '../../hooks/usePresence.js'
import { usePrompt } from '../../hooks/usePrompt.js'
import { useToast } from '../../hooks/useToast.js'
import { useVault } from '../../hooks/useVault.js'
import { queryBound } from '../../lib/presence.js'
import { Button } from '../ui/Button.jsx'
import { GatedButton } from '../ui/GatedButton.jsx'
import { Menu } from '../ui/Menu.jsx'
import { heldDenied } from './credentialText.js'

/**
 * What can be done to one credential (app.html's row buttons): Test and
 * Rotate in view, Release in view while it is quarantined, the rest in a
 * menu. Each gated change is signed over exactly what is sent.
 */
export function CredentialActions({ c, onTest, onManage, onRotate, onChanged }) {
  const api = useApi()
  const slow = useSlowCache()
  const presence = usePresence()
  const prompt = usePrompt()
  const toast = useToast()
  const vault = useVault()
  const [testing, setTesting] = useState(false)
  const slug = c.slug
  const fail = (e) => toast(e?.message || String(e), { tone: 'crit' })

  const test = async () => {
    setTesting(true)
    try { await onTest(slug) } finally { setTesting(false) }
  }

  // Containment (F16) is open on purpose: in an emergency a fingerprint only
  // slows you down, and a quarantine only takes away.
  const quarantine = async () => {
    const reason = await prompt.text({
      title: `Quarantine ${slug}`,
      body: 'Nothing can use it until you release it.',
      label: 'Reason (optional)',
      submit: 'Quarantine',
      danger: true,
    })
    if (reason === null) return
    try {
      const r = await api.post('credentials/quarantine', { slug, ...(reason ? { reason } : {}) })
      toast(`Quarantined ${slug}${heldDenied(r?.denied_approvals)}`, { tone: 'ok' })
      slow.clear()
      vault.refresh?.()
      onChanged?.()
    } catch (e) { fail(e) }
  }

  const remove = async () => {
    const ok = await prompt.confirm({
      title: `Remove ${slug}?`,
      body: 'Every grant using it is revoked.',
      submit: 'Remove with Touch ID',
      danger: true,
    })
    if (!ok) return
    try {
      const r = queryBound('DELETE credentials', { slug })
      await presence.gated(r.operation, (proof) => api.del(r.path, r.query, { presence: proof }), { label: `remove credential ${slug}` })
      toast('Removed', { tone: 'ok' })
      slow.clear()
      onChanged?.()
    } catch (e) { fail(e) }
  }

  const menu = [
    { label: 'Scrub patterns and expiry', icon: ShieldCheckIcon, onClick: () => onManage(slug) },
    ...(c.quarantine ? [] : [{ label: 'Quarantine', icon: LockClosedIcon, danger: true, onClick: quarantine }]),
    { label: 'Remove', icon: TrashIcon, danger: true, onClick: remove },
  ]

  return (
    <div className="flex flex-wrap items-center justify-start gap-1.5 md:flex-nowrap md:justify-end">
      <Button size="sm" icon={BeakerIcon} loading={testing} onClick={test} aria-label={`Test ${slug}`}>Test</Button>
      <Button size="sm" icon={ArrowPathIcon} onClick={() => onRotate(slug)} aria-label={`Rotate ${slug}`}>Rotate</Button>
      {c.quarantine && (
        <GatedButton
          size="sm"
          label={`release ${slug} from quarantine`}
          operation={() => presence.operationFor('cred.release', { slug })}
          send={(proof) => api.post('credentials/release', { slug, presence: proof })}
          onDone={() => { toast(`Released ${slug}`, { tone: 'ok' }); slow.clear(); vault.refresh?.(); onChanged?.() }}
          aria-label={`Release ${slug}`}
        >
          Release
        </GatedButton>
      )}
      <Menu label={`More actions for ${slug}`} items={menu} />
    </div>
  )
}
