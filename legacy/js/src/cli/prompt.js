// A small prompt toolkit. No dependencies, because the CLI ships with none and
// a credential prompt is the last place to add a supply chain.
//
// Everything here refuses to run without a terminal rather than guessing. A
// wizard that silently picks defaults when piped would be a wizard that quietly
// grants an agent more than someone intended.

import { createInterface } from 'node:readline'
import { stdin, stdout } from 'node:process'

const ESC = '\x1b'
const KEY = {
  up: `${ESC}[A`, down: `${ESC}[B`, right: `${ESC}[C`, left: `${ESC}[D`,
  enter: '\r', enter2: '\n', ctrlC: '\x03', ctrlD: '\x04', space: ' ', backspace: '\x7f',
}

export class Cancelled extends Error {
  constructor() { super('cancelled'); this.name = 'Cancelled' }
}

const tty = () => stdin.isTTY && stdout.isTTY

export function requireTty(what) {
  if (!tty()) {
    const e = new Error(`${what} needs a terminal`)
    e.noTty = true
    throw e
  }
}

const C = stdout.isTTY && !process.env.NO_COLOR
  ? {
    dim: (s) => `${ESC}[2m${s}${ESC}[0m`,
    bold: (s) => `${ESC}[1m${s}${ESC}[0m`,
    cyan: (s) => `${ESC}[36m${s}${ESC}[0m`,
    green: (s) => `${ESC}[32m${s}${ESC}[0m`,
    red: (s) => `${ESC}[31m${s}${ESC}[0m`,
    yellow: (s) => `${ESC}[33m${s}${ESC}[0m`,
    inverse: (s) => `${ESC}[7m${s}${ESC}[0m`,
  }
  : { dim: (s) => s, bold: (s) => s, cyan: (s) => s, green: (s) => s, red: (s) => s, yellow: (s) => s, inverse: (s) => s }

export { C as colors }

/**
 * Read single keypresses until `onKey` signals it is finished.
 *
 * `beforeFirstRead` runs after the listener is attached but before anything is
 * awaited, so a key pressed while the prompt is still painting is handled
 * rather than dropped. Attaching afterwards loses type-ahead, which shows up as
 * a wizard that ignores the first thing you type.
 */
function readKeys(onKey, beforeFirstRead) {
  return new Promise((resolve, reject) => {
    const wasRaw = stdin.isRaw
    stdin.setRawMode(true)
    stdin.resume()
    stdin.setEncoding('utf8')

    const cleanup = () => {
      stdin.setRawMode(wasRaw)
      stdin.pause()
      stdin.removeListener('data', handler)
    }
    const handler = (chunk) => {
      // A paste, or a fast typist, arrives as several keys in one chunk.
      // Splitting escape sequences out keeps arrow keys intact.
      for (const key of splitKeys(String(chunk))) {
        if (key === KEY.ctrlC || key === KEY.ctrlD) {
          cleanup()
          stdout.write('\n')
          return reject(new Cancelled())
        }
        const done = onKey(key)
        if (done !== undefined) { cleanup(); return resolve(done) }
      }
      return undefined
    }
    stdin.on('data', handler)
    if (beforeFirstRead) beforeFirstRead()
  })
}

/** Split a chunk into individual keys, keeping escape sequences whole. */
function splitKeys(chunk) {
  const keys = []
  for (let i = 0; i < chunk.length; i++) {
    if (chunk[i] === ESC && /^\[[A-D]/.test(chunk.slice(i + 1, i + 3))) {
      keys.push(chunk.slice(i, i + 3))
      i += 2
    } else {
      keys.push(chunk[i])
    }
  }
  return keys
}

/**
 * A single-choice list, driven by arrow keys, with number shortcuts.
 * @param {string} question
 * @param {{value:any, label:string, hint?:string}[]} choices
 */
export async function select(question, choices, { initial = 0 } = {}) {
  requireTty('this question')
  let index = Math.max(0, Math.min(initial, choices.length - 1))
  let drawnLines = 0

  const draw = () => {
    if (drawnLines) stdout.write(`${ESC}[${drawnLines}A`)
    const lines = [`${C.bold('?')} ${question}`]
    choices.forEach((choice, i) => {
      const selected = i === index
      const marker = selected ? C.cyan('>') : ' '
      const label = selected ? C.cyan(choice.label) : choice.label
      const hint = choice.hint ? ` ${C.dim(choice.hint)}` : ''
      lines.push(`  ${marker} ${label}${hint}`)
    })
    lines.push(C.dim('  up/down to move, enter to choose'))
    stdout.write(`${lines.map((l) => `${ESC}[2K${l}`).join('\n')}\n`)
    drawnLines = lines.length
  }

  const chosen = await readKeys((key) => {
    if (key === KEY.up) { index = (index - 1 + choices.length) % choices.length; draw(); return }
    if (key === KEY.down) { index = (index + 1) % choices.length; draw(); return }
    if (/^[1-9]$/.test(key)) {
      const n = Number(key) - 1
      if (n < choices.length) { index = n; draw() }
      return
    }
    if (key === KEY.enter || key === KEY.enter2) return choices[index]
    return undefined
  }, draw)

  // Replace the list with a single settled line.
  stdout.write(`${ESC}[${drawnLines}A`)
  for (let i = 0; i < drawnLines; i++) stdout.write(`${ESC}[2K\n`)
  stdout.write(`${ESC}[${drawnLines}A`)
  stdout.write(`${C.green('✓')} ${question} ${C.cyan(chosen.label)}\n`)
  return chosen.value
}

/** A free-text question with an optional default and validation. */
export async function text(question, { placeholder, defaultValue, validate, allowEmpty = false } = {}) {
  requireTty('this question')
  for (;;) {
    const suffix = defaultValue ? C.dim(` (${defaultValue})`) : placeholder ? C.dim(` (${placeholder})`) : ''
    const answer = await new Promise((resolve, reject) => {
      const rl = createInterface({ input: stdin, output: stdout })
      rl.question(`${C.bold('?')} ${question}${suffix} `, (a) => { rl.close(); resolve(a) })
      rl.on('SIGINT', () => { rl.close(); stdout.write('\n'); reject(new Cancelled()) })
    })
    const value = answer.trim() || defaultValue || ''
    if (!value && !allowEmpty) { stdout.write(`${C.red('  a value is required')}\n`); continue }
    if (validate) {
      const problem = validate(value)
      if (problem) { stdout.write(`${C.red(`  ${problem}`)}\n`); continue }
    }
    return value
  }
}

/** A yes or no question. Defaults to no unless told otherwise. */
export async function confirm(question, { defaultYes = false } = {}) {
  requireTty('this question')
  const hint = defaultYes ? 'Y/n' : 'y/N'
  const answer = await new Promise((resolve, reject) => {
    const rl = createInterface({ input: stdin, output: stdout })
    rl.question(`${C.bold('?')} ${question} ${C.dim(`[${hint}]`)} `, (a) => { rl.close(); resolve(a) })
    rl.on('SIGINT', () => { rl.close(); stdout.write('\n'); reject(new Cancelled()) })
  })
  const t = answer.trim().toLowerCase()
  if (!t) return defaultYes
  return /^y(es)?$/.test(t)
}

/**
 * Read a value without echoing it. Used for credential values, which must never
 * reach argv where ps would show them, nor the terminal scrollback.
 */
export async function secret(question) {
  requireTty('entering a credential value')
  let value = ''
  await readKeys((key) => {
    if (key === KEY.enter || key === KEY.enter2) { stdout.write('\n'); return true }
    if (key === KEY.backspace) {
      if (value.length) { value = value.slice(0, -1); stdout.write('\b \b') }
      return
    }
    // Ignore escape sequences so an arrow key does not land in the value.
    if (key.startsWith(ESC)) return
    value += key
    stdout.write('*')
    return undefined
  }, () => stdout.write(`${C.bold('?')} ${question} `))
  return value
}

/** A heading that separates steps of a wizard. */
export function step(n, total, title) {
  stdout.write(`\n${C.dim(`step ${n}/${total}`)}  ${C.bold(title)}\n`)
}

export function note(lines) {
  for (const line of [].concat(lines)) stdout.write(`  ${C.dim(line)}\n`)
}

export function blank() { stdout.write('\n') }

/** A settled summary block, shown before anything is committed. */
export function summary(title, rows) {
  stdout.write(`\n  ${C.bold(title)}\n`)
  const width = Math.max(...rows.map(([k]) => k.length))
  for (const [k, v] of rows) stdout.write(`    ${C.dim(k.padEnd(width))}  ${v}\n`)
  stdout.write('\n')
}
