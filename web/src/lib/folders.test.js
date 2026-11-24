import { describe, expect, it } from 'vitest'
import { folderProblem, folderTree, isWithin } from './folders.js'
import { withQuery } from './api.js'

describe('folders', () => {
  it('accepts what the daemon accepts and says why the rest is refused', () => {
    for (const ok of ['clients', 'clients/acme', 'a/b/c/d', 'Prod Keys/v1.2_x-y', 'x'.repeat(40)]) expect(folderProblem(ok)).toBeNull()
    for (const [bad, says] of [
      ['', 'name like'], ['/a', 'leading'], ['a/', 'trailing'], ['a//b', 'doubled'], ['a/b/c/d/e', '4 levels'],
      ['a/..', '. or ..'], [' a', 'space'], ['café', 'letters'], [`a${String.fromCharCode(0x202e)}b`, 'letters'], ['x'.repeat(41), '40'],
    ]) expect(folderProblem(bad)).toContain(says)
  })

  it('within is the folder or beneath it, never a name that only starts the same', () => {
    expect(isWithin('clients', 'clients')).toBe(true)
    expect(isWithin('clients/acme', 'clients')).toBe(true)
    expect(isWithin('clients-old', 'clients')).toBe(false)
    expect(isWithin(undefined, 'clients')).toBe(false)
  })

  it('makes the daemon’s flat list into a tree', () => {
    const tree = folderTree([
      { path: 'clients', direct: 1, total: 2 },
      { path: 'clients/acme', direct: 1, total: 1 },
      { path: 'infra', direct: 0, total: 1 },
      { path: 'infra/aws', direct: 1, total: 1 },
    ])
    expect(tree.map((n) => n.name)).toEqual(['clients', 'infra'])
    expect(tree[0].children.map((n) => [n.name, n.path, n.total])).toEqual([['acme', 'clients/acme', 1]])
  })

  it('sends an array filter as one key per value', () => {
    expect(withQuery('credentials', { status: ['attention', 'expiring'], kind: [], q: '' }))
      .toBe('credentials?status=attention&status=expiring')
  })
})
