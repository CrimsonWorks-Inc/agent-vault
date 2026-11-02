#!/usr/bin/env node --experimental-websocket
// Screenshots of the built page in headless Chrome, over the DevTools
// protocol (contract U9). Development only. Pair it with dev-vault.mjs:
//
//   node web/scripts/dev-vault.mjs --enrolled &
//   node --experimental-websocket web/scripts/screenshots.mjs \
//     --url http://localhost:5180/ --out /tmp/shots --name overview \
//     [--hash '#overview'] [--drawer] [--viewport]
//
// For each of light/dark x 1440/390 it loads the page, waits for it to
// settle, and writes <out>/<name>-<theme>-<width>.png (full page). --drawer
// also opens the mobile navigation at 390 and shoots that. Every console
// error and CSP violation is printed, and any CSP violation fails the run:
// the page must work under the strict policy with no 'unsafe-inline'.

import { spawn } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { parseArgs } from 'node:util'

const { values: args } = parseArgs({
  options: {
    url: { type: 'string', default: 'http://localhost:5180/' },
    out: { type: 'string' },
    name: { type: 'string', default: 'page' },
    hash: { type: 'string', default: '' },
    drawer: { type: 'boolean', default: false },
    chrome: { type: 'string', default: process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' },
    settle: { type: 'string', default: '2500' },
    viewport: { type: 'boolean', default: false },
  },
})
if (!args.out) { console.error('--out is required'); process.exit(2) }
mkdirSync(args.out, { recursive: true })

const profile = mkdtempSync(join(tmpdir(), 'av-shots-chrome-'))
const chrome = spawn(args.chrome, [
  '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
  '--no-first-run', '--no-default-browser-check', '--hide-scrollbars', '--disable-gpu', 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] })
const wsUrl = await new Promise((resolve, reject) => {
  let buf = ''
  chrome.stderr.on('data', (d) => {
    buf += d
    const m = /DevTools listening on (ws:\/\/\S+)/.exec(buf)
    if (m) resolve(m[1])
  })
  chrome.on('exit', (c) => reject(new Error(`chrome exited ${c}: ${buf}`)))
})
const done = () => { try { chrome.kill() } catch { /* gone */ } try { rmSync(profile, { recursive: true, force: true }) } catch { /* gone */ } }

// ---- a minimal CDP client ------------------------------------------------------
const ws = new WebSocket(wsUrl)
await new Promise((r) => ws.addEventListener('open', r, { once: true }))
let nextId = 0
const waiting = new Map()
const listeners = []
ws.addEventListener('message', (ev) => {
  const msg = JSON.parse(ev.data)
  if (msg.id && waiting.has(msg.id)) {
    const { resolve, reject } = waiting.get(msg.id)
    waiting.delete(msg.id)
    msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result)
  } else if (msg.method) for (const l of listeners) l(msg)
})
const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
  const id = ++nextId
  waiting.set(id, { resolve, reject })
  ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }))
})
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const { targetId } = await send('Target.createTarget', { url: 'about:blank' })
const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true })
const page = (m, p) => send(m, p, sessionId)
await page('Page.enable')
await page('Runtime.enable')
await page('Log.enable')

const problems = []
listeners.push((msg) => {
  if (msg.sessionId !== sessionId) return
  if (msg.method === 'Runtime.consoleAPICalled' && ['error', 'warning'].includes(msg.params.type)) {
    problems.push(`console.${msg.params.type}: ${msg.params.args.map((a) => a.value ?? a.description).join(' ')}`)
  }
  if (msg.method === 'Runtime.exceptionThrown') problems.push(`exception: ${msg.params.exceptionDetails.exception?.description ?? msg.params.exceptionDetails.text}`)
  if (msg.method === 'Log.entryAdded' && ['error', 'warning'].includes(msg.params.entry.level)) problems.push(`log.${msg.params.entry.level}: ${msg.params.entry.text}`)
})

const shots = []
async function shoot(theme, width, { drawer = false } = {}) {
  const height = width > 600 ? 900 : 844
  await page('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: width > 600 ? 1 : 2, mobile: width <= 600 })
  await page('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: theme }] })
  await page('Page.navigate', { url: `${args.url}${args.hash}` })
  await sleep(Number(args.settle))
  if (drawer) {
    await page('Runtime.evaluate', { expression: "document.querySelector('button[aria-label=\"Open navigation\"]')?.click()" })
    await sleep(600)
  }
  const { result } = await page('Runtime.evaluate', { expression: 'JSON.stringify([document.documentElement.scrollWidth, document.documentElement.scrollHeight])', returnByValue: true })
  const [sw, sh] = JSON.parse(result.value)
  if (sw > width) {
    const { result: wide } = await page('Runtime.evaluate', {
      returnByValue: true,
      expression: `JSON.stringify([...document.querySelectorAll('body *')].filter((e) => e.getBoundingClientRect().right > ${width} + 1).slice(-6).map((e) => e.tagName.toLowerCase() + '.' + String(e.className).split(' ').slice(0, 4).join('.') + ' ' + Math.round(e.getBoundingClientRect().right)))`,
    })
    problems.push(`horizontal overflow at ${width}px: the page is ${sw}px wide; widest: ${wide.value}`)
  }
  const full = drawer || args.viewport ? height : Math.min(Math.max(sh, height), 6000)
  await page('Emulation.setDeviceMetricsOverride', { width, height: full, deviceScaleFactor: width > 600 ? 1 : 2, mobile: width <= 600 })
  await sleep(300)
  const { data } = await page('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false })
  const file = join(args.out, `${args.name}-${theme}-${width}${drawer ? '-drawer' : ''}.png`)
  writeFileSync(file, Buffer.from(data, 'base64'))
  shots.push(file)
}

try {
  for (const theme of ['light', 'dark']) {
    for (const width of [1440, 390]) await shoot(theme, width)
    if (args.drawer) await shoot(theme, 390, { drawer: true })
  }
} finally {
  ws.close()
  done()
}

const csp = problems.filter((p) => /Content Security Policy|Refused to/i.test(p))
console.log(JSON.stringify({ shots, problems: [...new Set(problems)] }, null, 2))
if (csp.length) { console.error('CSP violations: the page needs something the strict policy refuses'); process.exit(1) }
