import { Button } from '../ui/Button.jsx'
import { Notice } from '../ui/Notice.jsx'

/**
 * A list that could not be read: what the server said, and a way to ask
 * again. A bad cursor (the UI server restarted) goes back to page one.
 */
export function ListError({ error, onRetry, what = 'this list' }) {
  if (!error) return null
  return (
    <div className="px-5 py-4">
      <Notice
        tone="crit"
        role="alert"
        title={`Could not read ${what}.`}
        actions={onRetry ? <Button size="sm" onClick={onRetry}>Try again</Button> : null}
      >
        {error.message}
      </Notice>
    </div>
  )
}
