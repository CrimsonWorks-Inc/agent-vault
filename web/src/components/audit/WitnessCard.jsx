import { useState } from 'react'
import { ShieldCheckIcon } from '@heroicons/react/20/solid'
import { useAction } from '../../hooks/useAction.js'
import { useApi, useApiQuery } from '../../hooks/useApi.js'
import { useToast } from '../../hooks/useToast.js'
import { pageQuery, readEnvelope } from '../../lib/paging.js'
import { Badge } from '../ui/Badge.jsx'
import { Button } from '../ui/Button.jsx'
import { Card, Row } from '../ui/Card.jsx'
import { CodeBlock } from '../ui/CodeBlock.jsx'
import { Notice } from '../ui/Notice.jsx'
import { Skeleton } from '../ui/Skeleton.jsx'

/** The newest record: one row of the unfiltered log, newest first (U3). */
export async function loadHead(api) {
  const data = await api.get('audit', pageQuery({ limit: 1 }))
  const items = readEnvelope(data, { limit: 1 }).items
  // A server that answers with a bare array gives the tail oldest first.
  return items.reduce((a, r) => (Number.isInteger(r?.seq) && (!a || r.seq > a.seq) ? r : a), null)
}

export const verifyText = (v) => (v?.ok ? `Chain intact across ${v.count} records` : `Chain broken at record ${v?.brokenAt}`)

/**
 * The log's head, a signed checkpoint of it, and the chain check (app.html's
 * Witness card, with Verify chain from its Overview). A checkpoint kept where
 * an agent cannot write shows later whether records were cut from the end.
 */
export function WitnessCard() {
  const api = useApi()
  const toast = useToast()
  const head = useApiQuery((a) => loadHead(a), [], { poll: 10_000 })
  const [checkpoint, setCheckpoint] = useState(null)
  const [verify, verifying] = useAction()
  const [fetchCheckpoint, fetching] = useAction()
  const h = head.data

  const getCheckpoint = () => fetchCheckpoint(async () => {
    const cp = await api.get('audit/checkpoint')
    setCheckpoint(cp)
    try {
      await globalThis.navigator.clipboard.writeText(JSON.stringify(cp))
      toast('Checkpoint copied', { tone: 'ok' })
    } catch { /* shown below with its own copy button */ }
    return cp
  })

  return (
    <Card eyebrow="Witness" title="The end of the log" padded={false}>
      <Row
        title={<HeadLine head={head} />}
        meta="A checkpoint is the head, signed with a key only this vault holds. Kept somewhere an agent cannot write, it shows later whether records were removed."
        actions={(
          <>
            <Button icon={ShieldCheckIcon} loading={verifying} onClick={() => verify(() => api.get('audit/verify'), { done: verifyText, tone: (v) => (v?.ok ? 'ok' : 'crit'), after: head.reload })}>
              Verify chain
            </Button>
            <Button loading={fetching} onClick={getCheckpoint}>Copy checkpoint</Button>
          </>
        )}
      />
      {head.error && (
        <div className="border-t border-line px-5 py-4">
          <Notice
            tone="crit"
            role="alert"
            title={h === undefined ? 'Could not read the head of the log.' : 'Could not refresh the head of the log; the one shown may be out of date.'}
            actions={<Button size="sm" loading={head.loading} onClick={head.reload}>Try again</Button>}
          >
            {head.error.message}
          </Notice>
        </div>
      )}
      {checkpoint && (
        <div className="border-t border-line px-5 py-4">
          <p className="mb-1.5 text-sm text-muted">Checkpoint</p>
          <CodeBlock code={JSON.stringify(checkpoint)} label="Copy the checkpoint" wrap />
        </div>
      )}
    </Card>
  )
}

/**
 * The head, as far as a successful read says. "no records yet" only after a
 * read that answered with none: a failed read is not an empty log.
 */
function HeadLine({ head }) {
  const h = head.data
  if (h === undefined) {
    if (head.error) return <span className="text-sm text-muted">head: unknown</span>
    return <Skeleton className="w-56" />
  }
  return (
    <>
      <span className="break-all font-mono text-sm">{h ? `head: record ${h.seq}, ${String(h.hash || '').slice(0, 16)}…` : 'head: no records yet'}</span>
      {head.error && <Badge tone="warn">stale</Badge>}
    </>
  )
}
