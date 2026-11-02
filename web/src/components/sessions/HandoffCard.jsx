import { CheckIcon } from '@heroicons/react/16/solid'
import { cleanLine } from '../../lib/text.js'
import { Button } from '../ui/Button.jsx'
import { Card } from '../ui/Card.jsx'
import { CodeBlock } from '../ui/CodeBlock.jsx'
import { Notice } from '../ui/Notice.jsx'
import { EnvMapping } from './EnvMapping.jsx'
import { exampleCall, sessionExpiry } from './sessionLogic.js'

/**
 * What to give the agent, shown once after a session is created here
 * (HANDOFF in src/ui/server.js). None of it is a secret: the token and the
 * placeholders are capabilities the agent is about to hold anyway, and
 * neither can be turned back into a credential. They live only in the
 * Sessions page's state: Done, leaving the page or reloading drops them, and
 * nothing here writes them to browser storage (U7).
 */
export function HandoffCard({ handoff, onDismiss }) {
  const s = handoff
  const grants = s.grants.length ? s.grants : []
  const curl = grants.length ? exampleCall({ ...grants[0], token: s.token, sites: s.sites, probe: s.probe }) : ''
  return (
    <Card
      eyebrow="Shown once"
      title="Hand this to the agent"
      className="border-accent/50"
      data-handoff=""
      footer={<Button variant="primary" icon={CheckIcon} onClick={onDismiss}>Done</Button>}
    >
      <div className="space-y-5">
        <p className="text-sm text-muted">
          Session <span className="font-mono text-ink">{cleanLine(s.session_id)}</span>, {sessionExpiry(s)}.
          Shown once here: leave this page or reload it and it is gone. It is saved to <span className="font-mono text-ink">~/.agent-vault/cli-state.json</span>,
          which is where the CLI and the MCP bridge look for it.
        </p>

        <div>
          <p className="mb-1.5 text-sm font-medium text-ink">Session token</p>
          <CodeBlock code={s.token} label="Copy the session token" />
        </div>

        {grants.map((g, i) => (
          <section key={`${g.cred}-${i}`} className="space-y-3 border-t border-line pt-4" aria-label={`Credential ${g.cred}`}>
            <h3 className="font-mono text-sm font-semibold text-ink">{cleanLine(g.cred)}</h3>
            <div className="grid gap-3 lg:grid-cols-2">
              <div>
                <p className="mb-1.5 text-xs text-muted">Base URL</p>
                <CodeBlock code={g.base_url} label={`Copy the base URL for ${g.cred}`} />
              </div>
              <div>
                <p className="mb-1.5 text-xs text-muted">Placeholder</p>
                <CodeBlock code={g.placeholder} label={`Copy the placeholder for ${g.cred}`} />
              </div>
            </div>
            <div>
              <p className="text-xs text-muted">The placeholder goes here, and nowhere else:</p>
              <ul className="mt-1 flex flex-wrap gap-1.5">
                {g.usage.map((u) => <li key={u}><CodeBlock inline code={cleanLine(u)} /></li>)}
              </ul>
            </div>
            {g.lint.length > 0 && <Notice tone="warn">{g.lint.map((p) => <p key={p}>{cleanLine(p)}</p>)}</Notice>}
          </section>
        ))}

        <div className="border-t border-line pt-4">
          <EnvMapping cli={s.cli} sessionId={s.session_id} grants={grants} />
        </div>

        {curl && (
          <div className="border-t border-line pt-4">
            <p className="mb-1.5 text-sm text-muted">A request that exercises the first one:</p>
            <CodeBlock code={curl} label="Copy the example request" />
          </div>
        )}
      </div>
    </Card>
  )
}
