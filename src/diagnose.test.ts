import assert from 'node:assert/strict'
import { test } from 'node:test'
import { buildScenario, serialize, signatureHeader } from '../api/_lib/stripe.ts'
import { diagnose } from './diagnose.ts'

const secret = 'whsec_debugger_0123456789abcdef'
const now = 1_800_000_000
const body = serialize(buildScenario(now).lifecycle[1])
const titles = (d: Awaited<ReturnType<typeof diagnose>>) => d.findings.map((f) => f.title).join(' | ')

test('valid example matches', async () => {
  const d = await diagnose({ body, header: await signatureHeader(body, [secret], now), secrets: secret, now })
  assert.equal(d.match, true, titles(d))
})

test('detects a re-serialized body', async () => {
  const header = await signatureHeader(body, [secret], now)
  const d = await diagnose({ body: JSON.stringify(JSON.parse(body)), header, secrets: secret, now })
  assert.equal(d.match, false)
  assert.match(titles(d), /pretty-printed/)
})

test('detects trailing newline, stale timestamp, wrong key type, rotation', async () => {
  const header = await signatureHeader(body, [secret], now)
  assert.match(titles(await diagnose({ body: body + '\n', header, secrets: secret, now })), /without the trailing newline/)
  const stale = await diagnose({ body, header, secrets: secret, now: now + 900 })
  assert.equal(stale.match, false)
  assert.match(titles(stale), /15 min old/)
  assert.match(titles(await diagnose({ body, header, secrets: 'sk_test_abc', now })), /API key/)
  const rotated = await signatureHeader(body, ['whsec_old_0123456789abcdef', secret], now)
  const r = await diagnose({ body, header: rotated, secrets: `whsec_nope_000000000000\n${secret}`, now })
  assert.equal(r.match, true)
  assert.match(titles(r), /2 v1 signatures.*matches secret #2/)
})

test('wrong secret points at the secret; missing v1 explains v0', async () => {
  const header = await signatureHeader(body, [secret], now)
  assert.match(titles(await diagnose({ body, header, secrets: 'whsec_other_secret_000000', now })), /does not match/)
  assert.match(titles(await diagnose({ body, header: `t=${now},v0=abc`, secrets: secret, now })), /No v1/)
  assert.match(titles(await diagnose({ body, header: `Stripe-Signature: ${header}`, secrets: secret, now })), /Signature matches/)
})
