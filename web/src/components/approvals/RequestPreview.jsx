import { cleanLine } from '../../lib/text.js'
import { Disclosure } from '../ui/Disclosure.jsx'
import { UntrustedText } from '../ui/UntrustedText.jsx'

const UNTRUSTED = 'written by the agent, not verified'

/**
 * What a held request sends, as the gateway previewed it (F13). The gateway
 * has already put labels where placeholders were and scrubbed any secret;
 * this paints it and decides nothing. Every byte of it came from the agent,
 * so all of it is cleaned text, and the body is in UntrustedText.
 */
export function RequestPreview({ preview }) {
  const p = preview
  if (!p || typeof p !== 'object') return null
  const body = p.body && typeof p.body === 'object' ? p.body : {}
  const pairs = (list, where) => (Array.isArray(list) ? list : []).filter((x) => Array.isArray(x)).map(([k, v]) => [where, k, v])
  const rows = [...pairs(p.query, 'query'), ...pairs(p.headers, 'header')]
  const chips = Array.isArray(p.placeholders) ? p.placeholders : []
  const bytes = Number.isInteger(body.bytes) ? body.bytes : 0

  return (
    <Disclosure title={`What it sends (${UNTRUSTED})`} className="mt-3">
      <p className="break-all font-mono text-xs text-muted">
        {cleanLine(p.method)} {cleanLine(p.host)}{cleanLine(p.path)}
        {' · '}{cleanLine(p.content_type || 'no content type')}
        {' · '}{bytes} bytes{body.truncated === true ? `, first ${Number(body.shown_bytes) || 0} shown` : ''}
      </p>
      {typeof body.text === 'string'
        ? <UntrustedText text={body.text} block className="mt-2" />
        : <p className="mt-2 text-sm text-muted">{body.kind === 'binary' ? 'A binary body, not shown.' : 'No body.'}</p>}
      {rows.length > 0 && (
        <table className="mt-2 w-full border-collapse text-xs">
          <caption className="sr-only">Query parameters and headers it sends</caption>
          <tbody>
            {rows.map(([where, k, v], i) => (
              <tr key={`${where}-${i}`} className="border-t border-line align-top">
                <td className="w-px whitespace-nowrap py-1 pr-3 text-muted">{where}</td>
                <td className="break-all py-1 pr-3 font-mono text-ink">{cleanLine(k)}</td>
                <td className="break-all py-1 font-mono text-ink">{cleanLine(v)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {chips.length > 0 && (
        <p className="mt-2 flex flex-wrap items-center gap-1.5 text-xs text-muted">
          Placeholders:
          {chips.map((x, i) => (
            <span key={i} className="rounded-pill border border-line px-2 py-0.5 font-mono text-ink">
              {cleanLine(x?.label)} @ {cleanLine(x?.location)}
            </span>
          ))}
        </p>
      )}
    </Disclosure>
  )
}
