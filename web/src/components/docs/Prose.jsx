// The small pieces the Docs sections are written in: headings, paragraphs,
// lists, inline code and copyable command blocks. Everything is React text,
// never HTML, so a credential slug in a command cannot become markup.

import { cx } from '../../lib/cx.js'
import { CodeBlock } from '../ui/CodeBlock.jsx'

/** A run of reading text, kept to a comfortable measure. */
export function Prose({ children, className }) {
  return <div className={cx('max-w-[68ch] text-base leading-relaxed text-ink [&>*:last-child]:mb-0', className)}>{children}</div>
}

export function H3({ children }) {
  return <h3 className="mb-2 mt-7 text-lg font-semibold tracking-tight text-ink first:mt-0">{children}</h3>
}

export function P({ children }) {
  return <p className="mb-3">{children}</p>
}

export function UL({ children }) {
  return <ul className="mb-3 list-disc space-y-1.5 pl-5 marker:text-muted">{children}</ul>
}

/** Inline code: a flag, a code, a variable name. */
export function C({ children }) {
  return <code className="rounded-[0.3rem] bg-accent-soft px-1.5 py-0.5 font-mono text-[0.8125rem] text-accent">{children}</code>
}

export function B({ children }) {
  return <strong className="font-semibold">{children}</strong>
}

/** A command to paste, with what it does above it. */
export function Cmd({ code, caption }) {
  return (
    <div className="mb-4 max-w-[68ch]">
      {caption && <p className="mb-1.5 text-sm text-muted">{caption}</p>}
      <CodeBlock code={code} label="Copy the command" />
    </div>
  )
}
