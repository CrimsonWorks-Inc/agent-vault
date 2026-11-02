import { useState } from 'react'
import { useToast } from '../../hooks/useToast.js'
import { notificationsOn, setNotifications } from '../../lib/notify.js'
import { Card, Row } from '../ui/Card.jsx'
import { CodeBlock } from '../ui/CodeBlock.jsx'
import { Switch } from '../ui/Switch.jsx'

const storage = () => { try { return globalThis.localStorage } catch { return null } }

/** Desktop notifications in this tab, and the webhook, read-only (F14). */
export function NotificationsCard({ notify, cli = 'agent-vault' }) {
  const toast = useToast()
  const N = globalThis.Notification
  const supported = typeof N !== 'undefined'
  const [on, setOn] = useState(() => supported && notificationsOn(storage()) && N.permission === 'granted')
  const hook = notify?.webhook

  const toggle = async (want) => {
    let next = want
    if (next && supported && N.permission !== 'granted') {
      const answer = await N.requestPermission()
      if (answer !== 'granted') next = false
    }
    setNotifications(storage(), next)
    setOn(next)
    toast(next ? 'Desktop notifications on while this tab is open' : 'Desktop notifications off', { tone: next ? 'ok' : 'info' })
  }

  return (
    <Card eyebrow="Signals" title="Notifications" padded={false}>
      <Row
        title="Desktop notifications"
        meta={supported
          ? 'While this tab is open, say so when something starts waiting for you. The notice only opens Approvals; deciding still needs your fingerprint.'
          : 'This browser cannot show desktop notifications.'}
        actions={supported && <Switch checked={on} onChange={toggle} label={<span className="sr-only">Desktop notifications</span>} />}
      />
      <Row
        title="Webhook"
        meta={hook
          ? <><span className="font-mono text-ink">{hook.host}</span> · {hook.detail} · since {hook.configured_at ? String(hook.configured_at).slice(0, 10) : ''}</>
          : 'No webhook. Set one from the command line:'}
      >
        {!hook && <CodeBlock className="mt-2" code={`${cli} notify set`} label="Copy the command" />}
      </Row>
    </Card>
  )
}
