// Files the CLI writes for the human: env files now, backups and audit exports
// later. Each one lands in a directory an agent may be able to write to, so
// the writer assumes the path has been prepared against it.
//
//   - Never overwritten by accident. Creating uses O_EXCL, so an existing file
//     is an error, not a target; replacing needs `force` and goes through a
//     fresh temporary file and a rename.
//   - Never followed. O_NOFOLLOW, and O_EXCL refuses a symlink too, so a link
//     an agent planted at `.env` cannot aim the write at ~/.ssh/config.
//   - Never readable by anyone else. The mode is set with fchmod after the
//     write, so the file ends up exactly 0600 whatever the umask. open() only
//     applies the umask, and the umask only removes bits: 0277 would leave
//     0400, which the owner can read but not write. And open() never changes
//     the mode of a file that is already there, so a 0644 log stays 0644.

import { openSync, writeSync, fsyncSync, fchmodSync, closeSync, lstatSync, fstatSync, renameSync, unlinkSync, constants } from 'node:fs'
import { dirname, basename, join } from 'node:path'
import { randomBytes } from 'node:crypto'
import * as ph from '../core/placeholder.js'

const { O_WRONLY, O_CREAT, O_EXCL, O_APPEND, O_NOFOLLOW, O_RDONLY, O_NONBLOCK } = constants

const problem = (code, message) => Object.assign(new Error(message), { code })

/** Write all of `text` to an open descriptor, then make it durable and set its mode. */
function writeAll(fd, text, mode) {
  const buf = Buffer.from(String(text), 'utf8')
  let off = 0
  while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off)
  fsyncSync(fd)
  fchmodSync(fd, mode)
}

/**
 * Write `text` to `path`, which must not exist unless `force` is set.
 *
 * @returns {{ replaced: boolean }}
 * @throws `{ code: 'EEXIST' }` when the path exists and `force` is not set
 *   (a symlink, even a dangling one, counts as existing); `{ code:
 *   'ENOTREGULAR' }` when `force` is set and the path is not a regular file
 *   owned by this user.
 */
export function writeFileExclusive(path, text, { force = false, mode = 0o600 } = {}) {
  if (!force) {
    let fd
    try {
      fd = openSync(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode)
    } catch (e) {
      if (e.code === 'EEXIST') throw problem('EEXIST', `${path} exists`)
      throw e
    }
    try { writeAll(fd, text, mode) } finally { closeSync(fd) }
    return { replaced: false }
  }

  let replaced = false
  try {
    const st = lstatSync(path)
    if (!st.isFile() || st.uid !== process.getuid()) throw problem('ENOTREGULAR', `${path} is not a regular file you own`)
    replaced = true
  } catch (e) {
    if (e.code !== 'ENOENT') throw e
  }
  // A new file beside the target, then a rename over it. rename replaces the
  // directory entry, so if the path has turned into a symlink since the check
  // above, the link is replaced and whatever it pointed at is untouched.
  const dir = dirname(path)
  const tmp = join(dir, `.${basename(path)}.av-${randomBytes(4).toString('hex')}`)
  const fd = openSync(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode)
  let written
  try {
    try {
      writeAll(fd, text, mode)
      written = fstatSync(fd, { bigint: true })
    } finally { closeSync(fd) }
    renameSync(tmp, path)
  } catch (e) {
    try { unlinkSync(tmp) } catch { /* already gone */ }
    throw e
  }
  // The temporary name sits in the same directory, so it can be swapped too:
  // for a symlink between close and rename, and rename then moves the link
  // into place. So check that what landed is the file this wrote, without
  // following it. If not, remove the entry (a link, not what it points at).
  if (!isFile(path, written)) {
    try { unlinkSync(path) } catch { /* already gone */ }
    throw problem('ENOTREGULAR', `${path} was replaced while it was being written; nothing was left there`)
  }
  // Best effort: the rename is durable once its directory is.
  try {
    const dfd = openSync(dir, O_RDONLY)
    try { fsyncSync(dfd) } finally { closeSync(dfd) }
  } catch { /* not every platform lets a directory be fsynced */ }
  return { replaced }
}

/**
 * Whether `path` is, right now, the regular file `st` describes. Opened with
 * O_NOFOLLOW, so a symlink is ELOOP, and O_NONBLOCK, so a fifo cannot hang it.
 */
function isFile(path, st) {
  let fd
  try {
    fd = openSync(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
  } catch {
    return false
  }
  try {
    const now = fstatSync(fd, { bigint: true })
    return now.isFile() && now.dev === st.dev && now.ino === st.ino
  } finally {
    closeSync(fd)
  }
}

/**
 * Append one line to `path`, creating it 0600 if it is not there, and making
 * it 0600 if it is. Refuses a symlink (O_NOFOLLOW) and anything that is not a
 * regular file. O_NONBLOCK, so a planted fifo with no reader is refused at
 * once (ENXIO) instead of hanging the open; with a reader it opens and fstat
 * refuses it before anything is written.
 */
export function appendLineExclusive(path, line) {
  let fd
  try {
    fd = openSync(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_NONBLOCK, 0o600)
  } catch (e) {
    if (e.code === 'ELOOP' || e.code === 'ENXIO') throw problem('ENOTREGULAR', `${path} is not a regular file`)
    throw e
  }
  try {
    if (!fstatSync(fd).isFile()) throw problem('ENOTREGULAR', `${path} is not a regular file`)
    // Before the line goes in, so it is never in a file someone else can read.
    fchmodSync(fd, 0o600)
    const text = String(line)
    const buf = Buffer.from(text.endsWith('\n') ? text : `${text}\n`, 'utf8')
    let off = 0
    while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
}

/** A variable name an env file may carry. */
export const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/
/** Every value an env file may carry is made of these, so none needs quoting. */
const SAFE_VALUE = /^[A-Za-z0-9._:/-]+$/

/**
 * The last check before an env file is opened: every value is a placeholder
 * for this session and the entry's own credential, or exactly a loopback
 * gateway URL for this session's port. Nothing else — not the session token,
 * not a value the daemon sent that looks almost right — is ever written.
 *
 * `entries` are `{ name, value, cred }`. Throws `{ code: 'NOT_PLACEHOLDER' }`
 * naming no value, because the value is exactly what must not be printed.
 */
export function assertPlaceholderOnly(entries, { sid, port, slugs }) {
  const refuse = () => problem('NOT_PLACEHOLDER', 'refusing to write a value that is not a placeholder')
  const known = new Set(slugs || [])
  const urls = new Set([`http://127.0.0.1:${port}`, ...[...known].map((s) => `http://127.0.0.1:${port}/p/${s}`)])
  if (!Array.isArray(entries) || !Number.isInteger(port) || typeof sid !== 'string' || !sid) throw refuse()
  for (const e of entries) {
    if (!e || typeof e.name !== 'string' || !ENV_NAME.test(e.name)) throw refuse()
    const v = e.value
    if (typeof v !== 'string' || !SAFE_VALUE.test(v)) throw refuse()
    const parsed = ph.parseAt(v)
    const isPlaceholder = parsed?.text === v && parsed.sid === sid && parsed.slug === e.cred && known.has(e.cred)
    if (!isPlaceholder && !urls.has(v)) throw refuse()
  }
}
