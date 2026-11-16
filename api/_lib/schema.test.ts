// Checks the synthetic events against an excerpt of Stripe's published OpenAPI schema,
// and the HMAC against the RFC 4231 reference vectors.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { runChaos, type Send } from './chaos.ts'
import { createDemo } from './demos.ts'
import { API_VERSION, buildScenario, hmacHex, maskSecret, parseSignatureHeader, payloadHashTail, signatureHeader, verifySignature } from './stripe.ts'

interface Schema { required: string[]; properties: string[]; enums: Record<string, string[]> }
const fx = JSON.parse(readFileSync(new URL('./fixtures/stripe-openapi-excerpt.json', import.meta.url), 'utf8')) as {
  api_version: string
  schemas: Record<string, Schema>
}
const now = 1_794_000_000

function conforms(value: unknown, name: string) {
  const s = fx.schemas[name]
  const v = value as Record<string, unknown>
  for (const k of s.required) assert.ok(k in v, `${name}.${k} is required by the schema`)
  for (const k of Object.keys(v)) assert.ok(s.properties.includes(k), `${name}.${k} is not in the schema`)
  for (const [k, allowed] of Object.entries(s.enums)) if (v[k] != null) assert.ok(allowed.includes(String(v[k])), `${name}.${k} = ${v[k]}`)
}

test('api_version is the one in the published OpenAPI spec', () => {
  assert.equal(API_VERSION, fx.api_version)
})

test('every generated object has the required fields and no unknown ones', () => {
  const sc = buildScenario(now)
  for (const e of [...sc.lifecycle, ...sc.reorder, sc.probe(), sc.unhandled()]) {
    conforms(e, 'event')
    conforms(e.data, 'notification_event_data')
    conforms(e.request, 'notification_event_request')
    const obj = e.data.object as Record<string, any>
    conforms(obj, obj.object)
    if (obj.object === 'subscription')
      for (const item of obj.items.data) {
        conforms(item, 'subscription_item')
        conforms(item.price, 'price')
        conforms(item.price.recurring, 'recurring')
        assert.equal(item.subscription, obj.id)
      }
    if (obj.object === 'invoice') {
      assert.equal(obj.lines.data.length, obj.lines.total_count)
      for (const line of obj.lines.data) {
        conforms(line, 'line_item')
        assert.equal(line.invoice, obj.id)
      }
      assert.equal(obj.lines.data.reduce((sum: number, l: { amount: number }) => sum + l.amount, 0), obj.total)
      assert.equal(obj.amount_paid + obj.amount_remaining, obj.amount_due)
    }
  }
})

test('keys follow Stripe ordering: id, object, then alphabetical', () => {
  const sc = buildScenario(now)
  const check = (v: unknown, path: string) => {
    if (Array.isArray(v)) return v.forEach((x, i) => check(x, `${path}[${i}]`))
    if (!v || typeof v !== 'object') return
    const keys = Object.keys(v)
    const rest = keys.filter((k) => k !== 'id' && k !== 'object')
    assert.deepEqual(rest, [...rest].sort(), path)
    assert.deepEqual(keys, [...keys.filter((k) => k === 'id'), ...keys.filter((k) => k === 'object'), ...rest], path)
    for (const k of keys) check((v as Record<string, unknown>)[k], `${path}.${k}`)
  }
  for (const e of [...sc.lifecycle, ...sc.reorder, sc.probe(), sc.unhandled()]) check(e, e.type)
})

test('HMAC-SHA256 matches RFC 4231 test cases 1 and 2', async () => {
  assert.equal(await hmacHex('\x0b'.repeat(20), 'Hi There'), 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7')
  assert.equal(await hmacHex('Jefe', 'what do ya want for nothing?'), '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843')
})

test('payload hash tail is the last 4 bytes of SHA-256 over UTF-8', async () => {
  const body = '{"description": "1 × Pro"}'
  assert.equal(await payloadHashTail(body), createHash('sha256').update(body, 'utf8').digest('hex').slice(-8))
})

test('the example header from the Stripe docs parses (docs.stripe.com/webhooks, "Verify manually")', () => {
  const p = parseSignatureHeader(
    't=1798765432,v1=5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd,v1=38c9f77a6fdb86d7f67e427e6076f1e38e244eb8ddc7a90f7f9dd4478d5bb2c2,' +
    'v0=6ffbb59b2300aae63f272406069a9788598b792a944a07aba816edb039989a39,secret=whsec_****************************PzVt,destination=we_1TN7mG6oEAX7HoXLZoZugElv,payload=a25aefc6',
  )
  assert.equal(p.t, 1798765432)
  assert.equal(p.v1.length, 2)
  assert.equal(p.v0.length, 1)
  assert.deepEqual(p.unknown, [])
  assert.deepEqual(p.meta, { secret: 'whsec_****************************PzVt', destination: 'we_1TN7mG6oEAX7HoXLZoZugElv', payload: 'a25aefc6' })
})

test('generated headers carry the same entries as the documented one, and both demos still parse them', async () => {
  const s = 'whsec_abcdefghijklmnopqrstuvwxyz012345'
  const h = await signatureHeader('{}', ['whsec_old', s], 1798765432, 'we_1TN7mG6oEAX7HoXLZoZugElv')
  assert.deepEqual(h.split(',').map((e) => e.split('=')[0]), ['t', 'v1', 'v1', 'v0', 'secret', 'destination', 'payload'])
  const p = parseSignatureHeader(h)
  assert.equal(p.meta.secret, maskSecret(s))
  assert.equal(p.meta.secret!.length, s.length)
  assert.equal(p.meta.secret, 'whsec_****************************2345')
  assert.equal(p.meta.payload, await payloadHashTail('{}'))
  assert.equal((await verifySignature('{}', h, s, { now: 1798765432 })).ok, true)
})

test('header debug metadata: first value wins, bad payload hash ignored, v1 untouched', () => {
  const p = parseSignatureHeader('t=1794000000,v1=aa,v1=bb,v0=cc,secret=whsec_****abcd,secret=other,destination=we_123,payload=DEADBEEF,foo=1')
  assert.deepEqual(p.v1, ['aa', 'bb'])
  assert.deepEqual(p.meta, { secret: 'whsec_****abcd', destination: 'we_123', payload: 'deadbeef' })
  assert.deepEqual(p.unknown, ['foo'])
  assert.deepEqual(parseSignatureHeader('t=1,v1=aa,payload=xyz').meta, {})
})

const secret = 'whsec_test_0123456789abcdefABCDEF'
test('secret rolling: a handler that reads only the first v1 drops authentic events', async () => {
  for (const [id, verdict] of [['naive', 'fail'], ['robust', 'pass']] as const) {
    const demo = createDemo(id, secret)
    const send: Send = async ({ body, headers }) => {
      const res = await demo.handle(new Request('https://demo.invalid/', { method: 'POST', headers, body }))
      return { status: res.status, ms: 0, body: await res.text() }
    }
    const r = await runChaos({ secret, checks: ['rotated_secret'], send, observe: () => demo.ledger })
    assert.equal(r.checks[0].verdict, verdict, id)
    assert.equal(parseSignatureHeader('t=1,' + 'v1=a,v1=b').v1.length, 2)
    assert.equal(demo.ledger.paidInvoices, verdict === 'pass' ? 1 : 0)
    assert.equal(r.authentic.length, 1)
  }
})

test('unhandled event type: 2xx passes, an error status fails', async () => {
  const strict: Send = async ({ body }) => ({ status: JSON.parse(body).type === 'customer.updated' ? 400 : 200, ms: 0, body: 'Unhandled event type' })
  const r = await runChaos({ secret, checks: ['baseline', 'unknown_type'], send: strict })
  assert.deepEqual(r.checks.map((c) => c.verdict), ['pass', 'fail'])
  const lenient: Send = async () => ({ status: 200, ms: 0, body: '' })
  assert.equal((await runChaos({ secret, checks: ['unknown_type'], send: lenient })).checks[0].verdict, 'pass')
})
