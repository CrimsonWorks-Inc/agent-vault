// The UI's login is an idle timeout, not an absolute one, and only the person
// holding the page counts as activity.
//
// The cookie was set once, at claim, with Max-Age equal to the idle timeout,
// and never refreshed: thirty minutes into using the page, every call
// returned 401 and a reload said "No session", because the launch link was
// already spent. Meanwhile the server counted those 401s as activity, so it
// never idled out either: a server that stayed up and could not be used.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { UiServer } from '../../src/ui/server.js'
import { startDaemon } from './fix-control-helpers.js'

test('an authenticated call slides the cookie; an unauthenticated one is not activity', async () => {
  const d = await startDaemon()
  const ui = await new UiServer(d.sock, { port: 0, idleMs: 60_000 }).start()
  try {
    const claimed = await fetch(ui.url, { redirect: 'manual' })
    const setCookie = claimed.headers.get('set-cookie')
    assert.match(setCookie, /Max-Age=60/)
    const cookie = setCookie.split(';')[0]

    ui.lastSeen = 0
    const stranger = await fetch(`${ui.origin}/api/status`, { headers: { 'x-av-ui': '1' } })
    assert.equal(stranger.status, 401)
    assert.equal(ui.lastSeen, 0, 'a refused request kept the server alive')

    const res = await fetch(`${ui.origin}/api/status`, { headers: { 'x-av-ui': '1', cookie } })
    assert.equal(res.status, 200)
    assert.ok(ui.lastSeen > 0, 'the page using the API is activity')
    const refreshed = res.headers.get('set-cookie')
    assert.ok(refreshed, 'the cookie was not refreshed by use')
    assert.equal(refreshed.split(';')[0], cookie, 'the same session, extended')
    assert.match(refreshed, /Max-Age=60/)
    assert.match(refreshed, /HttpOnly/)
    assert.match(refreshed, /SameSite=Strict/)
  } finally { await ui.stop(); await d.stop() }
})
