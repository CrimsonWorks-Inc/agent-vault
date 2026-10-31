// The in-app docs for wave 3, and the page as served.
//
// Each feature the page or the CLI gained is documented where a reader looks
// for it, with commands written through `${c.cli}` so they paste on this
// machine (and so a command added by another batch is never named here as a
// literal before it exists).

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Script } from 'node:vm'
import { servedPage } from '../../src/ui/server.js'
import { PAGE } from './control-ui-helpers.js'

const section = (id) => {
  const start = PAGE.indexOf(`id: '${id}',`)
  assert.ok(start > 0, `no ${id} section`)
  const next = PAGE.indexOf("\n    {\n      id: '", start)
  return PAGE.slice(start, next > 0 ? next : undefined)
}

test('the served page is one script that parses', () => {
  const html = servedPage()
  const code = html.slice(html.indexOf('<script>') + 8, html.lastIndexOf('</script>'))
  assert.doesNotThrow(() => new Script(code))
})

test('containment and recovery covers every wave-3 safety feature', () => {
  const safety = section('safety')
  for (const heading of ['Narrow it instead', 'Panic', 'Quarantine a credential', 'Tripwires', 'Rotate a credential',
    'Know when a token runs out', 'Extra shapes to scrub, and pinned keys', 'Hear about it when something is waiting',
    'Review what each session did', 'Back up and restore', 'Keep a witness']) {
    assert.ok(safety.includes(`<h3>${heading}</h3>`), `safety has no "${heading}"`)
  }
  assert.ok(safety.includes('The backup is encrypted with a recovery passphrase that is not your vault passphrase. Sessions and placeholders are never backed up: after a restore, every agent needs a new session.'))
  assert.match(safety, /denial of service against your own work/, 'the trade panic and quarantine make is stated')
  assert.match(safety, /a witness file that an agent can write, it can truncate/, 'the witness limit is stated honestly')
  assert.match(safety, /0 \* \* \* \* \$\{c\.cli\} audit witness/, 'a cron line')
  for (const cmd of ['panic', 'cred quarantine', 'cred release', 'tripwire on', 'cred rotate', 'cred expiry', 'cred test',
    'cred scrub', 'cred pin', 'watch', 'notify set', 'session show', 'report', 'backup export', 'backup inspect',
    'backup restore', 'audit witness', 'audit verify --witness', 'session narrow']) {
    assert.ok(safety.includes(`\${c.cli} ${cmd}`), `safety never shows ${cmd}`)
  }
})

test('the agent tools are documented, read-only ones said to be so', () => {
  const connect = section('connect')
  assert.match(connect, /It gains nine tools/)
  assert.match(connect, /<code>vault_describe_access<\/code> — [^<]*Read-only/)
  assert.match(connect, /<code>vault_preflight<\/code> — [^<]*Nothing is sent upstream and nothing is spent/)
})

test('the new session limits and templates are explained where sessions are', () => {
  const start = section('start')
  for (const flag of ['--rate 60/min', '--concurrency 4', '--quota 1000/day', '--route GET:/repos/**', '--payload-file F',
    '--graphql query', '--spend-tokens', '--spend-usd', '--redirects 2', '--grant-ttl 30']) {
    assert.ok(start.includes(flag), `start never mentions ${flag}`)
  }
  assert.ok(start.includes('template save gh-read'))
  assert.ok(start.includes('session create --template gh-read'))
})

test('the commands section lists every command after wave 3 (A.5)', () => {
  const commands = section('commands')
  for (const cmd of ['cred rotate', 'cred test', 'cred expiry', 'cred scrub', 'cred pin', 'cred quarantine', 'session narrow',
    'session show', 'template save', 'template list', 'template show', 'template rm', 'preflight', 'watch', 'notify set',
    'panic', 'tripwire show', 'audit export', 'audit witness', 'report', 'backup export', '--template NAME', '--grant-ttl MIN']) {
    assert.ok(commands.includes(cmd), `commands does not list ${cmd}`)
  }
})
