// Where JSX renders a `*_untrusted` field (contract U7).
//
// Agent-written text reaches the page only through <UntrustedText text={...}>.
// This finds every JSX expression container that mentions an `_untrusted`
// name, as a child (`>{r.reason_untrusted}<`) or as a prop value
// (`title={q.reason_untrusted}`), and allows exactly one shape: the `text`
// prop of an UntrustedText element. Anything else, including another
// component's `text` prop, is reported.
//
// It is a scan, not a parser. It reads expression containers that open after
// `>` or `}` (children) or right after `name=` with no space (a prop), so a
// plain object literal in ordinary JS (`const o = { a: x_untrusted }`) is not
// mistaken for rendering.

const UNTRUSTED = /\b\w*_untrusted\b/

/** `[{ line, expr, why }]` for every rendering of an untrusted field outside UntrustedText's text prop. */
export function findUntrustedRendering(source) {
  const out = []
  for (const { start, end } of containers(source)) {
    const expr = source.slice(start, end + 1)
    if (!UNTRUSTED.test(rendered(expr))) continue
    const before = source.slice(0, start)
    const prop = /(\w+)=$/.exec(before)
    const child = !prop && isChild(before)
    if (!prop && !child) continue // not JSX
    if (prop && prop[1] === 'text' && openTag(before) === 'UntrustedText') continue
    out.push({
      line: before.split('\n').length,
      expr: expr.replace(/\s+/g, ' '),
      why: prop ? `${openTag(before) ?? '?'} ${prop[1]}=` : 'rendered as a child',
    })
  }
  return out
}

/**
 * The part of an expression container whose value reaches the page. Nested
 * containers and JSX elements are blanked (each is scanned on its own); then
 * `a && b` renders b (a falsy string renders nothing), `c ? x : y` renders x
 * or y, and `a || b` or anything else renders all of it. So
 * `{r.reason_untrusted && <UntrustedText text={r.reason_untrusted} />}` uses
 * the field as a condition and passes, and `{r.reason_untrusted || '-'}` fails.
 */
export function rendered(expr) {
  let body = expr.slice(1, -1)
  // Blank nested containers, innermost first, then whole JSX elements.
  // A template literal's `${...}` is part of this value, not a container of
  // its own, so it is kept.
  for (let prev = null; prev !== body;) { prev = body; body = body.replace(/(^|[^$])\{[^{}]*\}/g, '$1{}') }
  for (let prev = null; prev !== body;) {
    prev = body
    body = body.replace(/<([A-Za-z][\w.]*)\b[^<>]*\/>/g, ' ').replace(/<([A-Za-z][\w.]*)\b[^<>]*>[^<>]*<\/\1>/g, ' ')
  }
  const top = splitTop(body)
  if (top.ternary) return top.ternary.join(' ')
  if (top.and) return top.and[top.and.length - 1]
  return body
}

/** Top-level `?`/`:` branches and `&&` operands, outside parentheses and brackets. */
function splitTop(body) {
  let depth = 0
  const ands = []
  let last = 0
  let q = -1
  for (let i = 0; i < body.length; i++) {
    const c = body[i]
    if ('([{'.includes(c)) depth++
    else if (')]}'.includes(c)) depth--
    else if (depth === 0 && c === '?' && body[i + 1] !== '.' && body[i + 1] !== '?' && body[i - 1] !== '?' && q === -1) q = i
    else if (depth === 0 && c === '&' && body[i + 1] === '&' && q === -1) { ands.push(body.slice(last, i)); last = i + 2; i++ }
  }
  if (q !== -1) return { ternary: [body.slice(q + 1)] }
  if (ands.length) return { and: [...ands, body.slice(last)] }
  return {}
}

/**
 * Whether a container opening at the end of `before` is element content: it
 * follows a tag's `>` (not an arrow's `=>` or a `>=`), with nothing but JSX
 * text, or other containers, in between. "Reason: {x}" is content; the body
 * of `(i) => {` is not.
 */
function isChild(before) {
  let flat = before
  for (let prev = null; prev !== flat;) { prev = flat; flat = flat.replace(/\{[^{}]*\}/g, 'x') }
  for (let i = flat.length - 1; i >= 0; i--) {
    const c = flat[i]
    if (c === '<') return false
    if (c === '>') {
      if (flat[i - 1] === '=' || flat[i + 1] === '=') return false
      return !/[;=`{}]/.test(flat.slice(i + 1))
    }
  }
  return false
}

/** The name of the element whose opening tag `before` ends inside, or null. */
function openTag(before) {
  const lt = before.lastIndexOf('<')
  if (lt === -1) return null
  const tail = before.slice(lt)
  if (/^<\//.test(tail) || /\/?>[^]*$/.test(tail.replace(/\{[^{}]*\}/g, ''))) return null
  const m = /^<([A-Za-z][\w.]*)/.exec(tail)
  return m ? m[1] : null
}

/** Every balanced `{ ... }` with its offsets, outermost first, skipping strings. */
function containers(source) {
  const found = []
  const stack = []
  let quote = null
  for (let i = 0; i < source.length; i++) {
    const c = source[i]
    if (quote) {
      if (c === '\\') { i++; continue }
      if (c === quote) quote = null
      continue
    }
    if (c === "'" || c === '"' || c === '`') {
      // A quote only opens a string inside an expression; JSX text may hold
      // apostrophes ("don't").
      if (stack.length) quote = c
      continue
    }
    if (c === '{') stack.push(i)
    else if (c === '}' && stack.length) {
      const start = stack.pop()
      found.push({ start, end: i, depth: stack.length })
    }
  }
  return found.sort((a, b) => a.start - b.start)
}
