// A stand-in for api.github.com that checks the Authorization header strictly
// and echoes the token back in its error body, the way real APIs do. That echo
// is what the scrubber has to catch.
import { createServer } from 'node:http'

export const REAL_TOKEN = 'ghp_DEMOSECRET00112233445566778899aabbccdd'

export function startFakeGitHub(port = 0) {
  const server = createServer((req, res) => {
    const auth = req.headers.authorization || ''
    const seen = auth.replace(/^Bearer\s+/i, '')
    const json = (status, obj) => {
      res.writeHead(status, { 'content-type': 'application/json' })
      res.end(JSON.stringify(obj, null, 2))
    }
    if (seen !== REAL_TOKEN) {
      return json(401, { message: `Bad credentials: ${seen}`, documentation_url: 'https://docs.github.com' })
    }
    if (req.url.startsWith('/user')) {
      return json(200, { login: 'frozencrow', id: 1, name: 'Eric', token_used: REAL_TOKEN })
    }
    if (req.url.includes('/issues')) {
      if (req.method === 'POST') {
        const chunks = []
        req.on('data', (c) => chunks.push(c))
        req.on('end', () => json(201, { number: 42, body: Buffer.concat(chunks).toString('utf8'), created: true }))
        return
      }
      return json(200, [{ number: 1, title: 'placeholder substitution is working', state: 'open' }])
    }
    return json(404, { message: 'Not Found' })
  })
  return new Promise((resolve) => server.listen(port, '127.0.0.1', () => resolve({ server, port: server.address().port })))
}
