// Path spellings, from outside. The grant allows /safe/** only. A raw request
// target is used so the client does not tidy the path before the daemon sees it.
import { describe, test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { request as httpRequest } from 'node:http'
import { stat } from 'node:fs/promises'
import { rustSkipReason, openWorld, leaksSecret, SECRET } from './lib/harness.js'

const skip = rustSkipReason()
if (skip) {
  test('paths', { skip }, () => {})
} else {
  describe('paths', { concurrency: false, timeout: 120_000 }, () => {
    let w
    let token
    let placeholder
    before(async () => {
      w = await openWorld()
      const added = await w.control('POST', '/v1/credentials', {
        slug: 'narrow', kind: 'http', host: `127.0.0.1:${w.upstream.port}`, scheme: 'http',
        value: SECRET, sites: ['header:authorization:Bearer'],
      })
      assert.equal(added.status, 200, added.text)
      const session = await w.control('POST', '/v1/sessions', {
        cred: 'narrow', label: 'narrow', methods: ['GET'], paths: ['/safe/**'],
        budget: 80, approval: 'on-write', ttl_hours: 1,
      })
      assert.equal(session.status, 200, session.text)
      token = session.json.token
      placeholder = session.json.placeholder
    })
    after(async () => { await w?.close() })

    function raw(path) {
      return new Promise((resolve, reject) => {
        const req = httpRequest({
          host: '127.0.0.1', port: w.port, path, method: 'GET',
          headers: {
            host: `127.0.0.1:${w.port}`,
            authorization: `Bearer ${placeholder}`,
            'av-session': token,
          },
        }, (res) => {
          const chunks = []
          res.on('data', (c) => chunks.push(c))
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8')
            let json = null
            if (text) { try { json = JSON.parse(text) } catch { json = null } }
            resolve({ status: res.statusCode, text, json })
          })
        })
        req.on('error', reject)
        req.setTimeout(20_000, () => req.destroy(new Error(`no answer for ${path}`)))
        req.end()
      })
    }

    test('paths inside the glob reach the upstream, including encoded and dot segments that stay inside', async () => {
      const cases = [
        ['/p/narrow/safe/item', '/safe/item'],
        ['/p/narrow/safe/./item', '/safe/item'],
        ['/p/narrow/safe/x/../item', '/safe/item'],
        ['/p/narrow/safe/sub/%2e%2e/item', '/safe/item'],
        ['/p/narrow/safe/%69tem', '/safe/item'],
        ['/p/narrow/safe/gemini-pro:generateContent', '/safe/gemini-pro:generateContent'],
        ['/p/narrow/safe/@scope/pkg', '/safe/@scope/pkg'],
      ]
      for (const [asked, upstreamPath] of cases) {
        const before = w.upstream.hits.length
        const res = await raw(asked)
        assert.equal(res.status, 200, `${asked} ${res.text}`)
        assert.equal(res.json.ordinary, 'ordinary-traffic-control')
        assert.equal(leaksSecret(res.text), null)
        assert.equal(w.upstream.hits.length, before + 1, asked)
        assert.equal(w.upstream.hits.at(-1).url, upstreamPath, asked)
        assert.equal(w.upstream.hits.at(-1).seen, SECRET)
      }
    })

    test('a path outside the glob is refused and not forwarded', async () => {
      const before = w.upstream.hits.length
      const res = await raw('/p/narrow/other')
      assert.equal(res.status, 403)
      assert.equal(res.json.code, 'AV_POLICY_DENIED')
      assert.equal(res.json.rule, 'paths')
      assert.equal(w.upstream.hits.length, before)
      assert.equal(leaksSecret(res.text), null)
    })

    test('an encoded dot-segment that leaves the glob is refused', async () => {
      const before = w.upstream.hits.length
      const res = await raw('/p/narrow/safe/%2e%2e/other')
      assert.equal(res.status, 403)
      assert.equal(res.json.code, 'AV_POLICY_DENIED')
      assert.equal(res.json.rule, 'paths')
      assert.equal(w.upstream.hits.length, before)
      assert.equal(leaksSecret(res.text), null)
    })

    test('dot-segments that collapse the credential route are not a route, and nothing is forwarded', async () => {
      for (const asked of ['/p/narrow/safe/../../other', '/p/narrow/%2e%2e/other']) {
        const before = w.upstream.hits.length
        const res = await raw(asked)
        assert.equal(res.status, 404, asked)
        assert.equal(res.json.code, 'AV_NOT_FOUND')
        assert.equal(w.upstream.hits.length, before)
        assert.equal(leaksSecret(res.text), null)
      }
    })

    test('a path encoded more than once is refused', async () => {
      const spellings = [
        '/p/narrow/safe/%252e%252e/other',
        '/p/narrow/%252e%252e/other',
        '/p/narrow/safe/%25252e%25252e/other',
        `/p/narrow/${'%25'.repeat(12)}61`,
      ]
      for (const asked of spellings) {
        const before = w.upstream.hits.length
        const res = await raw(asked)
        assert.equal(res.status, 403, `${asked} ${res.text}`)
        assert.equal(res.json.code, 'AV_POLICY_DENIED')
        assert.equal(res.json.rule, 'path_ambiguous_encoding')
        assert.equal(w.upstream.hits.length, before)
        assert.equal(leaksSecret(res.text), null)
      }
    })

    test('an encoded slash or a backslash is refused', async () => {
      for (const asked of ['/p/narrow/a%2fb', '/p/narrow/a%2Fb', '/p/narrow/safe/item%2fhidden', '/p/narrow/safe/a%5cb', '/p/narrow/safe/%5cother', '/p/narrow/safe/a%5Cb']) {
        const before = w.upstream.hits.length
        const res = await raw(asked)
        assert.equal(res.status, 403, `${asked} ${res.text}`)
        assert.equal(res.json.code, 'AV_POLICY_DENIED')
        assert.equal(res.json.rule, 'path_ambiguous_separator')
        assert.equal(w.upstream.hits.length, before)
        assert.equal(leaksSecret(res.text), null)
      }
    })

    test('a raw backslash is a slash to the URL parser, and it still cannot leave the glob', async () => {
      const inside = await raw('/p/narrow/safe/a\\b')
      assert.equal(inside.status, 200, inside.text)
      assert.equal(inside.json.ordinary, 'ordinary-traffic-control')
      assert.equal(w.upstream.hits.at(-1).url, '/safe/a/b')
      assert.equal(w.upstream.hits.at(-1).seen, SECRET)
      assert.equal(leaksSecret(inside.text), null)

      const before = w.upstream.hits.length
      const out = await raw('/p/narrow/safe/..\\other')
      assert.equal(out.status, 403, out.text)
      assert.equal(out.json.code, 'AV_POLICY_DENIED')
      assert.equal(out.json.rule, 'paths')
      assert.equal(w.upstream.hits.length, before)
      assert.equal(leaksSecret(out.text), null)
    })

    test('an invalid percent-escape is refused and not forwarded', async () => {
      const before = w.upstream.hits.length
      const res = await raw('/p/narrow/safe/%zz')
      assert.equal(res.status, 403, res.text)
      assert.equal(res.json.code, 'AV_POLICY_DENIED')
      assert.equal(w.upstream.hits.length, before)
      assert.equal(leaksSecret(res.text), null)
    })

    test('a control character in the path is refused', async () => {
      for (const asked of ['/p/narrow/%00safe/item', '/p/narrow/safe/%09item']) {
        const before = w.upstream.hits.length
        const res = await raw(asked)
        assert.equal(res.status, 403, `${asked} ${res.text}`)
        assert.equal(res.json.code, 'AV_POLICY_DENIED')
        assert.equal(res.json.rule, 'path_control_char')
        assert.equal(w.upstream.hits.length, before)
        assert.equal(leaksSecret(res.text), null)
      }
    })

    test('the daemon tightens the vault directory and keeps the socket private', async () => {
      // openWorld chmods the directory to 0755 before the daemon starts, so
      // this fails when the daemon never sets a mode of its own.
      const dir = await stat(w.dir)
      const sock = await stat(w.socketPath)
      assert.equal(dir.mode & 0o777, 0o700)
      assert.equal(sock.mode & 0o777, 0o600)
      // No client group is configured, so the daemon only chmods the socket.
      // On macOS, stat of that socket reports gid 0, which is not the
      // process group and is not something the daemon set.
    })
  })
}
