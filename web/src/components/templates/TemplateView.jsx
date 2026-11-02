import { useApiQuery } from '../../hooks/useApi.js'
import { formatHash } from '../../lib/router.js'
import { cleanLine } from '../../lib/text.js'
import { Button } from '../ui/Button.jsx'
import { CodeBlock } from '../ui/CodeBlock.jsx'
import { KeyValue } from '../ui/KeyValue.jsx'
import { Modal } from '../ui/Modal.jsx'
import { Notice } from '../ui/Notice.jsx'
import { Skeleton } from '../ui/Skeleton.jsx'

/** One template as stored (`template show`): its version, hash and spec. */
export function TemplateView({ name, onClose }) {
  const { data: t, error } = useApiQuery((api) => (name ? api.get('templates', { name }) : null), [name], { enabled: Boolean(name) })
  return (
    <Modal
      open={Boolean(name)}
      onClose={onClose}
      size="lg"
      title={`Template ${cleanLine(name ?? '')}`}
      description="The session this template creates. A new session can narrow any of it, never widen it."
      footer={(
        <>
          <Button onClick={onClose}>Close</Button>
          <Button variant="primary" onClick={() => { globalThis.location.hash = formatHash('sessions', `new:${name}`); onClose() }}>Start a session from it</Button>
        </>
      )}
    >
      {error && !t ? <Notice tone="crit" role="alert">{error.message}</Notice> : !t ? (
        <div className="space-y-2" role="status" aria-label="Loading the template"><Skeleton className="w-1/2" /><Skeleton className="w-2/3" /></div>
      ) : (
        <div className="space-y-4">
          <KeyValue rows={[['version', String(t.version ?? '')], ['hash', cleanLine(t.hash ?? '')]]} />
          <CodeBlock code={JSON.stringify(t.spec ?? {}, null, 2)} label="Copy the spec" />
        </div>
      )}
    </Modal>
  )
}
