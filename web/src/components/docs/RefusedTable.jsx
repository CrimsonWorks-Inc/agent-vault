import { C } from './Prose.jsx'

/**
 * Every refusal code a caller can hit, what happened and what to do, as
 * The old page's "When a request is refused" table had them. `fix` is a function
 * of the CLI name where the fix is a command.
 */
export const REFUSED = [
  ['AV_BAD_LOCATION', 'A placeholder appeared somewhere the credential is not allowed to go. Nothing was sent upstream.', () => 'Put it only where vault_list_creds says. This usually means the agent tried to copy the token somewhere.'],
  ['AV_PH_EXHAUSTED', 'An n-use placeholder ran out of uses.', (cli) => <>Ask for another: <C>{`${cli} ph next <cred>`}</C></>],
  ['AV_PH_STALE', 'The placeholder is older than the session allows.', () => 'Issue a fresh one. Nothing is wrong.'],
  ['AV_PH_REPLAY', 'A placeholder that was already burned or revoked came back.', () => 'Reuse is treated as hostile and is logged. Get a new one.'],
  ['AV_PH_MALFORMED', 'The placeholder failed its own checksum, so it was altered in transit.', () => 'Copy it whole; do not trim or re-encode it.'],
  ['AV_PH_CROSS_SESSION', 'A placeholder from a different session was used.', () => 'Sessions do not share placeholders. Use this session’s own.'],
  ['AV_PH_WRONG_CONNECTOR', 'A placeholder for one credential was sent to another credential’s route.', () => 'Match the placeholder to the route it belongs to.'],
  ['AV_NO_GRANT', 'This session has no grant for that credential or host.', () => 'Create a session that includes it, or widen the grant.'],
  ['AV_POLICY_DENIED', 'The method, path or host is outside what the session allows, or the profile denies it outright.', () => 'Check the grant. Some paths are denied by the profile no matter what you grant.'],
  ['AV_APPROVAL_PENDING', 'The request needs you.', () => 'Open Approvals, or run the approve command.'],
  ['AV_LOCKED', 'The vault is locked.', (cli) => <><C>{`${cli} unlock`}</C>, or unlock from the Overview page.</>],
  ['AV_PRESENCE_REQUIRED', 'Something tried to widen capability without confirmation.', () => 'Do it from this page with your fingerprint, or from the CLI after proving your passphrase.'],
  ['AV_PRESENCE_DENIED', 'The passphrase or signature did not verify.', () => 'Try again. Repeated failures are in the audit log.'],
  ['AV_RATE_LIMITED', 'Too many passphrase attempts in a row.', () => 'Wait for the backoff named in the message. Each further failure doubles it, up to thirty seconds.'],
  ['AV_SESSION_REQUIRED', 'No session token was presented.', () => <>Send it as <C>Authorization: Bearer</C>, or use a placeholder at a declared header site.</>],
  ['AV_SESSION_EXPIRED', 'The session ran out of time or budget.', () => 'Create a new one.'],
  ['AV_SESSION_REVOKED', 'You revoked it.', () => 'Create a new one if that was not what you meant.'],
  ['AV_ENCODED_BODY', 'The request body was compressed, so placeholders in it could not be found.', () => 'Send identity encoding. An unreadable body is never forwarded.'],
  ['AV_UNSCANNABLE', 'The upstream response could not be decoded for scrubbing, so it was not returned.', () => 'A response the vault cannot read might carry the secret back; it is withheld rather than trusted.'],
  ['AV_BROWSER_ORIGIN', 'The request carried Origin or Sec-Fetch-Site.', () => 'The proxy is not for browsers. Call it from your agent or your code.'],
  ['AV_REMOTE_FORBIDDEN', 'A remote session attempted something allowed only from this machine.', () => 'Do it locally.'],
  ['AV_UPSTREAM_UNREACHABLE', 'The upstream did not answer.', () => 'Not your policy’s fault; the placeholder use was refunded. Retry.'],
  ['AV_QUOTA_EXCEEDED', 'A rate, concurrency or quota limit on the grant was reached.', () => <>Wait the seconds in <C>retry_after</C>, then retry. If it keeps happening, the limit is too low for the task.</>],
  ['AV_GRANT_EXPIRED', 'This grant’s own lifetime ran out, though the session may still be live.', () => <>Ask for a new grant with <C>vault_request_session</C>, or create a new session.</>],
  ['AV_QUARANTINED', 'You quarantined this credential.', (cli) => <>Nothing can use it until you release it: <C>{`${cli} cred release <slug>`}</C></>],
  ['AV_PIN_MISMATCH', 'The upstream’s TLS key matched none of the pins for that host, so nothing was sent.', (cli) => <>Something may be intercepting TLS on this machine, or the provider changed keys. Compare: <C>{`${cli} cred pin <slug> --host <host> --live`}</C></>],
]

/** A table at md and up, a list of cards below it, like DataTable. */
export function RefusedTable({ cli }) {
  return (
    <div className="mb-4 overflow-hidden rounded-card border border-line bg-surface shadow-card">
      <table className="hidden w-full border-collapse text-sm md:table">
        <caption className="sr-only">Refusal codes</caption>
        <thead>
          <tr className="border-b border-line">
            {['Code', 'What happened', 'What to do'].map((h) => (
              <th key={h} scope="col" className="px-4 py-2.5 text-left font-mono text-eyebrow font-medium uppercase tracking-[0.12em] text-muted">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {REFUSED.map(([code, what, fix]) => (
            <tr key={code} className="border-b border-line align-top last:border-b-0">
              <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-crit">{code}</td>
              <td className="px-4 py-3 text-ink">{what}</td>
              <td className="px-4 py-3 text-muted">{fix(cli)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <ul className="divide-y divide-line md:hidden" aria-label="Refusal codes">
        {REFUSED.map(([code, what, fix]) => (
          <li key={code} className="space-y-1 px-4 py-3 text-sm">
            <p className="break-all font-mono text-xs text-crit">{code}</p>
            <p className="text-ink">{what}</p>
            <p className="text-muted">{fix(cli)}</p>
          </li>
        ))}
      </ul>
    </div>
  )
}
