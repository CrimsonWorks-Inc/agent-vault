import { ArrowPathIcon } from '@heroicons/react/16/solid'
import { Button } from '../components/ui/Button.jsx'
import { CodeBlock } from '../components/ui/CodeBlock.jsx'
import { Logo } from '../components/ui/Mark.jsx'

/**
 * A single message in the middle of the page, for when there is no app to
 * show: no session, a link already used, a daemon that does not answer.
 */
export function CenteredLayout({ title, children, actions }) {
  return (
    <div className="flex min-h-dvh flex-col items-center justify-center bg-bg px-4 py-12">
      <Logo size="lg" className="mb-10" />
      <main className="w-full max-w-md rounded-card border border-line bg-surface p-7 shadow-raised">
        <h1 className="text-xl font-semibold tracking-tight text-ink">{title}</h1>
        <div className="mt-2 space-y-3 text-sm leading-relaxed text-muted">{children}</div>
        {actions && <div className="mt-6 flex flex-wrap gap-2">{actions}</div>}
      </main>
      <p className="mt-8 max-w-sm text-center text-xs text-muted">
        No credential value is ever sent to this page.
      </p>
    </div>
  )
}

/** The cookie is gone: the server will not answer this tab again (401). */
export function NoSession({ cli = 'agent-vault' }) {
  return (
    <CenteredLayout title="No session">
      <p>This tab's session has ended. The UI server stops after 30 idle minutes, and a session cannot be reopened from the page.</p>
      <p>Open the UI again with the link it prints:</p>
      <CodeBlock code={`${cli} ui`} label="Copy the command" />
    </CenteredLayout>
  )
}

/** Someone else claimed the launch link first (the server's 409). */
export function LinkUsed({ cli = 'agent-vault' }) {
  return (
    <CenteredLayout title="This link was already used">
      <p>Another browser claimed this session first. If that was not you, close it and start a new one, then check the audit log:</p>
      <CodeBlock code={`${cli} ui\n${cli} audit tail`} label="Copy the commands" />
    </CenteredLayout>
  )
}

/** The UI server is up but the daemon is not, or the UI server is gone. */
export function Unreachable({ error, onRetry, cli = 'agent-vault' }) {
  const server = error?.kind === 'server'
  return (
    <CenteredLayout
      title={server ? 'Cannot reach the UI server' : 'Cannot reach the daemon'}
      actions={onRetry && <Button variant="primary" icon={ArrowPathIcon} onClick={onRetry}>Try again</Button>}
    >
      <p>{error?.message}</p>
      {server
        ? <p>Start it again with <code className="font-mono text-ink">{cli} ui</code> and open the link it prints.</p>
        : <>
          <p>Start it, or check what it says about itself:</p>
          <CodeBlock code={`${cli} daemon\n${cli} status`} label="Copy the commands" />
        </>}
      <p className="text-xs">This page checks again every few seconds.</p>
    </CenteredLayout>
  )
}
