// Outbound-request protections in api/_lib/net.ts, beyond what api/_lib/core.test.ts covers: connect-time address
// checks, no redirect following, the response-body cap and the timeout. Nothing here leaves this machine: the only
// servers are on 127.0.0.1 (started by the test), and every hostname is either a literal IP or resolves locally.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer, type Server } from 'node:https'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { BODY_CAP, checkTargetUrl, clean, isBlockedIp, postWebhook } from '../api/_lib/net.ts'

const req = { body: '{"hello":"world"}', headers: { 'content-type': 'application/json' } }

let hasOpenssl = true
try {
  execFileSync('openssl', ['version'], { stdio: 'ignore' })
} catch {
  hasOpenssl = false
}

test('checkTargetUrl: odd spellings of private addresses are still refused', async () => {
  // Hostnames that are not IP literals must never reach a real resolver here: this one answers with a public address.
  const pub = async () => [{ address: '93.184.215.14', family: 4 }]
  const bad = [
    'https://0x7f.0.0.1/', 'https://0177.0.0.1/', 'https://127.1/', 'https://2130706433/', 'https://0/', 'https://[::1]/',
    'https://[::ffff:7f00:1]/', 'https://[::ffff:10.0.0.1]/', 'https://[fd00::1]/', 'https://[fe80::1%25eth0]/',
    'https://169.254.169.254/latest/meta-data/', 'https://100.100.100.200/', 'https://192.168.0.1/', 'https://172.31.255.255/',
    'https://printer.local/', 'https://api.internal/', 'https://x.localhost/', 'https://nas.home.arpa/', 'https://intranet/',
    'https://example.com:80/', 'https://example.com:443443/', 'https://user@example.com/', 'file:///etc/passwd', 'javascript:alert(1)',
    'HTTP://example.com/', '//example.com/', 'https:///nohost', '', ' ',
  ]
  for (const url of bad) await assert.rejects(checkTargetUrl(url, pub), url)
  // The same names written normally, and the allowed alternate port, are accepted.
  for (const url of ['https://example.com/', 'https://example.com:8443/x?y=1', 'https://8.8.8.8/hook', 'https://[2606:4700:4700::1111]/'])
    assert.equal((await checkTargetUrl(url, pub)).href, new URL(url).href)
})

test('checkTargetUrl: a name that does not resolve, or resolves to anything private among several answers, is refused', async () => {
  await assert.rejects(checkTargetUrl('https://nowhere.example/', async () => []), /Could not resolve/)
  await assert.rejects(checkTargetUrl('https://nowhere.example/', async () => { throw new Error('ENOTFOUND') }), /Could not resolve/)
  for (const bad of ['127.0.0.1', '::1', '169.254.169.254', '10.0.0.1', 'fc00::1', '::ffff:192.168.1.1'])
    await assert.rejects(
      checkTargetUrl('https://mixed.example/', async () => [{ address: '93.184.215.14', family: 4 }, { address: bad, family: 4 }]),
      /private or reserved/,
      bad,
    )
})

test('isBlockedIp: unparseable and boundary addresses', () => {
  for (const ip of ['', ' 127.0.0.1', '127.0.0.1 ', '256.1.1.1', '1.2.3', '::g', '172.15.255.255x', '[::1]']) assert.equal(isBlockedIp(ip), true, JSON.stringify(ip))
  // Just outside the reserved ranges.
  for (const ip of ['172.15.255.255', '172.32.0.0', '100.63.255.255', '100.128.0.0', '11.0.0.0', '9.255.255.255', '169.253.255.255', '223.255.255.255'])
    assert.equal(isBlockedIp(ip), false, ip)
  // Just inside.
  for (const ip of ['172.16.0.0', '172.31.255.255', '100.64.0.0', '100.127.255.255', '10.255.255.255', '169.254.0.0', '224.0.0.1', '255.255.255.255'])
    assert.equal(isBlockedIp(ip), true, ip)
})

test('postWebhook refuses to connect when the name resolves to a private address (checked again at connect time)', async () => {
  // "localhost" resolves through the local hosts file; the connect-time lookup must refuse it, so no socket is opened.
  const r = await postWebhook(new URL('https://localhost:8443/hook'), req, 3000)
  assert.equal(r.status, null)
  assert.match(r.error ?? '', /Refused: resolves to a private address/)
  assert.equal(r.body, '')
})

test('postWebhook never reports success for an unreachable or non-HTTP peer', async () => {
  // Port 9 on loopback via an IP literal: no listener, so the connection is refused locally.
  const refused = await postWebhook(new URL('https://127.0.0.1:9/'), req, 3000)
  assert.equal(refused.status, null)
  assert.ok(refused.error)
})

test('clean strips control characters and caps the length', () => {
  assert.equal(clean('a\u0000b\u001bc\u202e\td\ne'), 'abc\td\ne')
  assert.equal(clean('x'.repeat(BODY_CAP + 500)).length, BODY_CAP)
  assert.equal(clean(''), '')
})

test('postWebhook against a local HTTPS server: no redirects, capped body, hard timeout', { skip: !hasOpenssl }, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'wc-net-'))
  const key = join(dir, 'key.pem')
  const cert = join(dir, 'cert.pem')
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=127.0.0.1'], { stdio: 'ignore' })

  const seen: string[] = []
  let followed = 0
  const server: Server = createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (rq, rs) => {
    seen.push(`${rq.method} ${rq.url}`)
    if (rq.url === '/redirect') return void rs.writeHead(302, { location: '/landed' }).end('moved')
    if (rq.url === '/landed') return void (followed++, rs.writeHead(200).end('landed'))
    if (rq.url === '/big') return void rs.writeHead(200).end('A'.repeat(BODY_CAP * 20))
    if (rq.url === '/hang') return // never answers
    if (rq.url === '/ctrl') return void rs.writeHead(200).end('ok\u0000\u001b[31mred')
    if (rq.url === '/echo') {
      const chunks: Buffer[] = []
      rq.on('data', (c: Buffer) => chunks.push(c)).on('end', () => rs.writeHead(200).end(Buffer.concat(chunks)))
      return
    }
    rs.writeHead(404).end()
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const port = (server.address() as AddressInfo).port
  // The local server uses a throwaway self-signed certificate, so certificate checking is off for this process only.
  const previous = process.env.NODE_TLS_REJECT_UNAUTHORIZED
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
  t.after(async () => {
    if (previous === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = previous
    server.closeAllConnections()
    await new Promise((r) => server.close(r))
    rmSync(dir, { recursive: true, force: true })
  })
  const at = (path: string) => new URL(`https://127.0.0.1:${port}${path}`)

  await t.test('the request is a single POST with the exact body, and the reply is returned', async () => {
    const r = await postWebhook(at('/echo'), req, 5000)
    assert.equal(r.status, 200)
    assert.equal(r.body, req.body)
    assert.deepEqual(seen.splice(0), ['POST /echo'])
  })

  await t.test('a redirect is reported as the response and not followed', async () => {
    const r = await postWebhook(at('/redirect'), req, 5000)
    assert.equal(r.status, 302)
    assert.equal(r.body, 'moved')
    assert.equal(followed, 0)
    assert.deepEqual(seen.splice(0), ['POST /redirect'])
  })

  await t.test('a huge response is cut at the body cap', async () => {
    const r = await postWebhook(at('/big'), req, 5000)
    assert.equal(r.status, 200)
    assert.ok(r.body.length > 0 && r.body.length <= BODY_CAP, `length ${r.body.length}`)
  })

  await t.test('control characters in a response are removed before they reach the report', async () => {
    const r = await postWebhook(at('/ctrl'), req, 5000)
    assert.equal(r.body, 'ok[31mred')
  })

  await t.test('a server that never answers is cut off at the timeout and reported as an error, not a status', async () => {
    const started = Date.now()
    const r = await postWebhook(at('/hang'), req, 600)
    assert.equal(r.status, null)
    assert.match(r.error ?? '', /^Timed out after 0\.6s$/)
    assert.ok(Date.now() - started < 3000)
  })
})
