import { ChatBubbleBottomCenterTextIcon } from '@heroicons/react/16/solid'
import { cleanLine, cleanText } from '../../lib/text.js'
import { cx } from '../../lib/cx.js'

/**
 * Text an agent wrote: a session request's reason, an approval preview, a
 * quarantine reason, a label (contract U7). The one way the page shows it.
 *
 *   - Rendered as a React text node, so it is never HTML.
 *   - Controls and bidi characters are stripped first (lib/text.js, the CLI's
 *     rules), so "fix\u202elive" cannot read as "fixevil".
 *   - Marked as agent-written, visibly and to screen readers, so it never
 *     reads as the page's own words.
 *
 * `block` for multi-line text (newlines and tabs kept, in a scrolling box);
 * inline otherwise (one line, controls become spaces).
 */
export function UntrustedText({ text, block = false, source = 'agent', label, className, maxHeight = 'max-h-80' }) {
  // The attribution can be agent-controlled too (a writer's name), and it is
  // the caption, the title and the screen-reader text: cleaned like the body,
  // so a bidi override cannot reorder "Written by ..., not verified".
  const who = cleanLine(label ?? (source === 'agent' ? 'Written by the agent, not verified' : `Written by ${source}, not verified`))
  if (block) {
    return (
      <figure data-untrusted="" className={cx('my-1.5 overflow-hidden rounded-control border border-dashed border-warn/70 bg-warn-soft/40', className)}>
        <figcaption className="flex items-center gap-1.5 border-b border-dashed border-warn/50 px-3 py-1 font-mono text-eyebrow uppercase tracking-[0.12em] text-warn">
          <ChatBubbleBottomCenterTextIcon aria-hidden="true" className="size-3.5" />
          {who}
        </figcaption>
        <pre className={cx('overflow-auto whitespace-pre-wrap break-words px-3 py-2 font-mono text-xs leading-relaxed text-ink', maxHeight)}>{cleanText(text)}</pre>
      </figure>
    )
  }
  return (
    <span data-untrusted="" className={cx('inline-flex max-w-full items-baseline gap-1.5', className)}>
      <span className="shrink-0 self-center rounded-[0.25rem] border border-dashed border-warn/70 px-1 font-mono text-[0.5625rem] font-medium uppercase leading-4 tracking-[0.1em] text-warn" title={who}>
        <span aria-hidden="true">{source === 'agent' ? 'agent' : 'unverified'}</span>
        <span className="sr-only">{who}:</span>
      </span>
      <span className="min-w-0 break-words font-mono text-[0.8125rem] text-ink">{cleanLine(text)}</span>
    </span>
  )
}
