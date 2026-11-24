// Credential folders on the page: the same path rules the daemon enforces
// (av-store folders.rs), said the same way, so a bad name is caught before
// it is sent; and the flat list the daemon sends, made into a tree.

export const MAX_DEPTH = 4
export const MAX_NAME = 40
const NAME = /^[A-Za-z0-9 ._-]+$/

/** Why a folder path would be refused, or null. */
export function folderProblem(path) {
  if (!path) return 'Give a name like clients/acme.'
  const parts = path.split('/')
  if (parts.length > MAX_DEPTH) return `At most ${MAX_DEPTH} levels deep, like a/b/c/d.`
  for (const part of parts) {
    if (!part) return 'Drop the leading, trailing or doubled /.'
    if ([...part].length > MAX_NAME) return `Each folder name is at most ${MAX_NAME} characters.`
    if (part === '.' || part === '..') return 'A folder can’t be named . or ..'
    if (part.startsWith(' ') || part.endsWith(' ')) return 'A folder name can’t start or end with a space.'
    if (!NAME.test(part)) return 'Use letters, digits, spaces, and - _ . only, with / between levels.'
  }
  return null
}

/** Whether `path` is `folder` itself or beneath it. */
export function isWithin(path, folder) {
  return path === folder || (typeof path === 'string' && path.startsWith(`${folder}/`))
}

/** The last name in a path. */
export const leafOf = (path) => path.slice(path.lastIndexOf('/') + 1)

/**
 * `[{path, direct, total}]` (sorted by path, every ancestor present) as a
 * tree: `[{path, name, direct, total, children}]`.
 */
export function folderTree(folders = []) {
  const byPath = new Map()
  const roots = []
  for (const f of folders) {
    if (!f || typeof f.path !== 'string') continue
    const node = { path: f.path, name: leafOf(f.path), direct: f.direct ?? 0, total: f.total ?? 0, children: [] }
    byPath.set(f.path, node)
    const cut = f.path.lastIndexOf('/')
    const parent = cut > 0 ? byPath.get(f.path.slice(0, cut)) : null
    if (parent) parent.children.push(node)
    else roots.push(node)
  }
  return roots
}

/** Every folder path, for pickers. */
export const folderPaths = (folders = []) => folders.map((f) => f.path).filter((p) => typeof p === 'string')
