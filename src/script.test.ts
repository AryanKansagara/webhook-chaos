// Runs the exported bash script for real (bash + curl + openssl) against the demo handlers on a local port.
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { test } from 'node:test'
import { createDemo, type DemoId } from '../api/_lib/demos.ts'
import { buildScript } from './script.ts'

const secret = 'whsec_local_script_0123456789abcdef'
const hasTools = process.platform !== 'win32' && ['bash', 'curl', 'openssl'].every((t) => spawnSync('which', [t]).status === 0)

async function runAgainst(id: DemoId) {
  const demo = createDemo(id, secret)
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = []
    for await (const c of req) chunks.push(c as Buffer)
    const headers = new Headers()
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') headers.set(k, v)
    const out = await demo.handle(new Request('http://local/webhook', { method: 'POST', headers, body: Buffer.concat(chunks) }))
    res.writeHead(out.status, { 'content-type': 'application/json' }).end(await out.text())
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/webhook`
  const child = spawn('bash', ['-s', url], { env: { ...process.env, STRIPE_WEBHOOK_SECRET: secret } })
  let stdout = ''
  child.stdout.on('data', (d) => (stdout += d))
  child.stdin.end(buildScript(Math.floor(Date.now() / 1000)))
  const code = await new Promise<number | null>((r) => child.on('close', r))
  server.close()
  return { code, stdout, ledger: demo.ledger }
}

test('exported script: robust handler passes all 15 deliveries', { skip: !hasTools }, async () => {
  const r = await runAgainst('robust')
  assert.equal(r.code, 0, r.stdout)
  assert.match(r.stdout, /15 passed, 0 failed/)
  assert.equal(r.ledger.paidInvoices, 2) // the lifecycle payment once, plus the one signed during rotation
  assert.deepEqual(Object.values(r.ledger.subscriptions), ['canceled', 'canceled'])
})

test('exported script: naive handler fails rotation and replay, and its state is wrong', { skip: !hasTools }, async () => {
  const r = await runAgainst('naive')
  assert.equal(r.code, 1, r.stdout)
  assert.match(r.stdout, /FAIL {2}got 400 {2}want 2xx .* two v1 signatures/)
  assert.match(r.stdout, /FAIL {2}got 200 {2}want 4xx .* signed 10 minutes ago/)
  assert.match(r.stdout, /PASS {2}got 400 {2}want 4xx .* amount_paid edited/)
  assert.match(r.stdout, /1 responses took 3s or longer/)
  assert.equal(r.ledger.paidInvoices, 3) // duplicate counted twice, replay accepted
})
