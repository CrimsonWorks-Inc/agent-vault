// One page of a list route, with search, page size and Prev/Next (U4).
//
//   const list = usePaged('credentials', { searchFields: ['slug', 'kind'] })
//   <SearchInput value={list.q} onChange={list.setQ} />
//   <DataTable rows={list.items} loading={list.loading} ... />
//   <Pagination {...list.pagination} />
//
// Changing the filters, the search or the page size goes back to page one.
// Polling (opts.poll) refreshes the page you are on and keeps your place.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useApi } from './useApi.js'
import { usePolling } from './usePolling.js'
import {
  firstPage, nextPage, prevPage, pageQuery, readEnvelope, recallLimit, rememberLimit, showing, clampLimit,
} from '../lib/paging.js'

const SEARCH_DEBOUNCE_MS = 250
const storage = () => { try { return globalThis.localStorage } catch { return null } }

export function usePaged(path, { limit: initialLimit, filters = {}, searchFields = null, poll = 0, storageKey = `agent-vault.page-size.${path}` } = {}) {
  const api = useApi()
  const filterKey = JSON.stringify(filters)
  // Everything that decides which page is asked for lives in one state, so a
  // new search term and the reset to page one are one render and one request.
  const [view, setView] = useState(() => ({
    ...firstPage(), q: '', path, filterKey,
    limit: clampLimit(initialLimit ?? recallLimit(storage(), storageKey)),
  }))
  const [qInput, setQInput] = useState('')
  const [result, setResult] = useState({ items: [], next_cursor: null, prev_cursor: null, total: null })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const seq = useRef(0)

  // The search box is debounced; the first page comes back with the new term.
  useEffect(() => {
    const id = setTimeout(() => setView((v) => (v.q === qInput ? v : { ...v, ...firstPage(), q: qInput })), SEARCH_DEBOUNCE_MS)
    return () => clearTimeout(id)
  }, [qInput])
  useEffect(() => {
    setView((v) => (v.filterKey === filterKey && v.path === path ? v : { ...v, ...firstPage(), filterKey, path }))
  }, [filterKey, path])

  const load = useCallback(async () => {
    const mine = ++seq.current
    setLoading(true)
    try {
      const opts = { limit: view.limit, cursor: view.cursor, q: view.q, searchFields }
      const data = await api.get(view.path, pageQuery({ ...opts, filters: JSON.parse(view.filterKey) }))
      if (mine !== seq.current) return
      const env = readEnvelope(data, opts)
      // A page emptied under us (its last item was revoked) steps back one.
      if (!env.items.length && view.stack.length) {
        setView((v) => ({ ...v, ...prevPage(v) }))
        return
      }
      setResult(env)
      setError(null)
    } catch (e) {
      if (mine === seq.current) setError(e)
    } finally {
      if (mine === seq.current) setLoading(false)
    }
  // searchFields is read, not watched: a new array each render must not refetch.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api, view])

  useEffect(() => { load() }, [load])
  usePolling(load, poll, { enabled: poll > 0, immediate: false })

  const setLimit = useCallback((n) => {
    const limit = clampLimit(n)
    rememberLimit(storage(), storageKey, limit)
    setView((v) => (v.limit === limit ? v : { ...v, ...firstPage(), limit }))
  }, [storageKey])

  const nextCursor = result.next_cursor
  const next = useCallback(() => setView((v) => ({ ...v, ...nextPage(v, nextCursor) })), [nextCursor])
  const prev = useCallback(() => setView((v) => ({ ...v, ...prevPage(v) })), [])

  const hasNext = Boolean(nextCursor)
  const hasPrev = view.stack.length > 0
  const { page, limit } = view
  const range = showing({ page, limit, count: result.items.length, total: result.total })

  const pagination = useMemo(() => ({
    page, limit, hasNext, hasPrev, onNext: next, onPrev: prev, onLimitChange: setLimit, range, loading,
  }), [page, limit, hasNext, hasPrev, next, prev, setLimit, range, loading])

  return {
    items: result.items, total: result.total, page, limit, setLimit,
    hasNext, hasPrev, next, prev, reload: load, loading, error,
    q: qInput, setQ: setQInput, range, pagination,
  }
}
