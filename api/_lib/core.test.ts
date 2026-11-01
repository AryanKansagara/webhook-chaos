import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { test } from 'node:test'
import { runChaos, CHECK_IDS, type Send } from './chaos.ts'
import { createDemo, type DemoId } from './demos.ts'
import { checkTargetUrl, isBlockedIp } from './net.ts'
import { API_VERSION, buildScenario, parseSignatureHeader, serialize, signatureHeader, verifySignature } from './stripe.ts'
import { POST, rateLimited } from '../run.ts'

const secret = 'whsec_test_0123456789abcdefABCDEF'
const now = () => Math.floor(Date.now() / 1000)

test('signature matches an independent node:crypto HMAC (stripe-node algorithm)', async () => {
  const body = '{\n  "id": "evt_1"\n}'
  const header = await signatureHeader(body, [secret], 1700000000)
  const p = parseSignatureHeader(header)
  assert.equal(p.t, 1700000000)
  assert.equal(p.v1[0], createHmac('sha256', secret).update(`1700000000.${body}`).digest('hex'))
  assert.equal(p.v0.length, 1)
})

test('verifySignature: valid, rotation, mismatch, stale, missing', async () => {
  const body = '{"a":1}'
  const t = now()
  assert.equal((await verifySignature(body, await signatureHeader(body, [secret], t), secret)).ok, true)
  const rotated = await signatureHeader(body, ['whsec_old_secret_xxxxxxxxxx', secret], t)
  assert.equal((await verifySignature(body, rotated, secret)).ok, true)
  const r1 = await verifySignature(body + ' ', await signatureHeader(body, [secret], t), secret)
  assert.equal(r1.ok === false && r1.reason, 'mismatch')
  const r2 = await verifySignature(body, await signatureHeader(body, [secret], t - 301), secret)
  assert.equal(r2.ok === false && r2.reason, 'stale')
  const r3 = await verifySignature(body, null, secret)
  assert.equal(r3.ok === false && r3.reason, 'missing_header')
  const r4 = await verifySignature(body, `t=${t},v0=abc`, secret)
  assert.equal(r4.ok === false && r4.reason, 'no_signature')
})

test('scenario events look like Stripe events with consistent ids', () => {
  const sc = buildScenario(now())
  for (const e of [...sc.lifecycle, ...sc.reorder]) {
    assert.deepEqual(Object.keys(e), ['id', 'object', 'api_version', 'created', 'data', 'livemode', 'pending_webhooks', 'request', 'type'])
    assert.match(e.id, /^evt_1[A-Za-z0-9]{23}$/)
    assert.equal(e.api_version, API_VERSION)
    assert.equal(e.livemode, false)
    assert.equal(e.data.object.livemode, false)
    assert.equal(e.data.object.customer, sc.customer)
  }
  assert.deepEqual(sc.lifecycle.map((e) => e.type), [
    'customer.subscription.created', 'invoice.paid', 'customer.subscription.updated', 'invoice.payment_failed', 'customer.subscription.deleted',
  ])
  const inv = sc.lifecycle[1].data.object as unknown as { parent: { subscription_details: { subscription: string } } }
  assert.equal(inv.parent.subscription_details.subscription, sc.subA)
  assert.ok(sc.lifecycle[2].data.previous_attributes)
  assert.match(serialize(sc.lifecycle[0]), /^\{\n {2}"id"/)
})

function demoSend(id: DemoId) {
  const demo = createDemo(id, secret)
  const send: Send = async ({ body, headers }) => {
    const res = await demo.handle(new Request('https://demo.invalid/', { method: 'POST', headers, body }))
    return { status: res.status, ms: 0, body: await res.text() }
  }
  return { send, observe: () => demo.ledger }
}
const verdicts = (r: Awaited<ReturnType<typeof runChaos>>) => Object.fromEntries(r.checks.map((c) => [c.id, c.verdict]))
const fast = CHECK_IDS.filter((id) => id !== 'latency')

test('robust demo passes every check', async () => {
  const r = await runChaos({ secret, checks: fast, ...demoSend('robust') })
  assert.equal(r.score, 100, JSON.stringify(verdicts(r)))
})

test('naive demo: HTTP looks fine but duplicates, ordering and replay are wrong', async () => {
  const d = demoSend('naive')
  const r = await runChaos({ secret, checks: fast, ...d })
  const v = verdicts(r)
  assert.equal(v.baseline, 'pass')
  assert.equal(v.duplicate, 'fail')
  assert.equal(v.out_of_order, 'fail')
  assert.equal(v.stale_timestamp, 'fail')
  assert.equal(v.bad_signature, 'pass')
  assert.equal(v.tampered_body, 'pass')
  assert.equal(v.missing_header, 'pass')
  assert.equal(d.observe().subscriptions[r.subB], 'active')
})

test('re-parsing demo rejects authentic events (stripe-node #341)', async () => {
  const r = await runChaos({ secret, checks: ['baseline', 'bad_signature'], ...demoSend('reparsed') })
  assert.deepEqual(verdicts(r), { baseline: 'fail', bad_signature: 'pass' })
  assert.match(r.checks[0].deliveries[0].body, /No signatures found matching/)
})

test('latency check flags slow responses; unreachable endpoints stop after 3 failures', async () => {
  const slow: Send = async () => ({ status: 200, ms: 4000, body: '' })
  const r = await runChaos({ secret, checks: ['baseline', 'latency'], send: slow })
  assert.equal(verdicts(r).latency, 'warn')
  let calls = 0
  const down: Send = async () => (calls++, { status: null, ms: 1, body: '', error: 'ECONNREFUSED' })
  await runChaos({ secret, checks: fast, send: down })
  assert.equal(calls, 3)
})

test('isBlockedIp covers private, loopback, link-local, CGNAT, metadata and mapped IPv6', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0',
    '::1', '::', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:a9fe:a9fe', '64:ff9b::7f00:1', '2002:7f00:1::', 'not-an-ip'])
    assert.equal(isBlockedIp(ip), true, ip)
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '::ffff:8.8.8.8']) assert.equal(isBlockedIp(ip), false, ip)
})

test('checkTargetUrl rejects unsafe targets', async () => {
  const pub = async () => [{ address: '93.184.215.14', family: 4 }]
  const priv = async () => [{ address: '93.184.215.14', family: 4 }, { address: '10.0.0.5', family: 4 }]
  assert.equal((await checkTargetUrl('https://example.com/hook', pub)).hostname, 'example.com')
  for (const bad of ['http://example.com/', 'https://localhost/', 'https://127.0.0.1/', 'https://[::ffff:127.0.0.1]/',
    'https://2130706433/', 'https://u:p@example.com/', 'https://example.com:22/', 'ftp://x.com', 'nope', 'https://metadata/'])
    await assert.rejects(checkTargetUrl(bad, pub), bad)
  await assert.rejects(checkTargetUrl('https://rebind.example/', priv), /private/)
})

const post = (body: unknown, headers: Record<string, string> = {}) =>
  POST(new Request('https://x/api/run', { method: 'POST', headers: { 'content-type': 'application/json', 'x-real-ip': String(Math.random()), ...headers }, body: JSON.stringify(body) }))

test('POST /api/run validates input and never echoes the secret', async () => {
  assert.equal((await post({ target: 'robust', checks: [] })).status, 400)
  assert.equal((await post({ target: 'evil', checks: ['baseline'] })).status, 400)
  assert.equal((await post({ target: 'url', url: 'https://example.com', secret: 'sk_test_123', checks: ['baseline'] })).status, 400)
  const r = await post({ target: 'url', url: 'http://169.254.169.254/latest', secret, checks: ['baseline'] })
  assert.equal(r.status, 400)
  assert.ok(!(await r.text()).includes(secret))
  const ok = await post({ target: 'robust', checks: ['baseline', 'duplicate'] })
  assert.equal(ok.status, 200)
  const json = (await ok.json()) as { score: number; demo: { actual: unknown; expected: unknown } }
  assert.equal(json.score, 100)
  assert.deepEqual(json.demo.actual, json.demo.expected)
  const wrongType = await POST(new Request('https://x/api/run', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: '{}' }))
  assert.equal(wrongType.status, 415)
})

test('rate limit is per IP and windowed', () => {
  const ip = `rl-${Math.random()}`
  for (let i = 0; i < 8; i++) assert.equal(rateLimited(ip, 1000), false)
  assert.equal(rateLimited(ip, 1000), true)
  assert.equal(rateLimited(ip, 62_000), false)
})
