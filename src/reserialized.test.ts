// Runs the debugger against bodies that real toolchains produced from one signed event.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { payloadHashTail } from '../api/_lib/stripe.ts'
import { diagnose, guessSerializer } from './diagnose.ts'

const fx = JSON.parse(readFileSync(new URL('./fixtures/reserialized.json', import.meta.url), 'utf8')) as {
  t: number; secret: string; header: string; original: string
  python: string; python_sorted: string; go_map: string; jq_sorted: string; jq_compact: string
}
const run = (body: string, header = fx.header, secrets = fx.secret) => diagnose({ body, header, secrets, now: fx.t + 5 })
const titles = (d: Awaited<ReturnType<typeof run>>) => d.findings.map((f) => `${f.title}: ${f.detail}`).join(' | ')

test('the original bytes verify', async () => {
  assert.equal((await run(fx.original)).match, true)
})

test('Python json.dumps output is recognised and traced back to the signed bytes', async () => {
  assert.match(fx.python, /\\u00d7/, 'fixture should contain an escaped non-ASCII character')
  const d = await run(fx.python)
  assert.equal(d.match, false)
  assert.match(titles(d), /pretty-printed JSON.*json\.dumps\(\).*request\.get_data\(\)/)
})

test('sorted-key output (Python sort_keys, Go map, jq -S) is traced back via Stripe key order', async () => {
  for (const body of [fx.python_sorted, fx.go_map, fx.jq_sorted]) {
    const d = await run(body)
    assert.equal(d.match, false)
    assert.match(titles(d), /restoring Stripe's key order/)
  }
  assert.match(guessSerializer(fx.python_sorted) ?? '', /json\.dumps.*keys sorted/)
})

test('compact output (jq -c, JSON.stringify) is named', async () => {
  const d = await run(fx.jq_compact.trimEnd())
  assert.match(titles(d), /pretty-printed JSON.*compact JSON/)
  assert.equal(guessSerializer('{"a":"<b>"}'), 'It is compact JSON, as JSON.stringify(req.body) writes it after express.json() or a similar body parser.')
  assert.match(guessSerializer('{"a":"\\u003cb\\u003e"}') ?? '', /Go encoding\/json/)
  assert.match(guessSerializer('{"a":"https:\\/\\/x"}') ?? '', /PHP/)
  assert.equal(guessSerializer(fx.original), null)
})

test('header payload= field separates a changed body from a wrong secret', async () => {
  const tail = await payloadHashTail(fx.original)
  const header = `${fx.header},payload=${tail},destination=we_1TestDestination`
  const changed = await run(fx.original.replace('"attempt_count": 1', '"attempt_count": 2'), header)
  assert.match(titles(changed), /Body differs from what Stripe signed/)
  assert.doesNotMatch(titles(changed), /secret is the likely culprit/)
  const wrongSecret = await run(fx.original, header, 'whsec_some_other_endpoint_secret_0000')
  assert.match(titles(wrongSecret), /byte-for-byte what Stripe signed/)
  assert.doesNotMatch(titles(wrongSecret), /Signature does not match/)
  assert.equal((await run(fx.original, header)).match, true)
})

test('header secret= mask is compared by length and last four characters', async () => {
  const mask = `whsec_${'*'.repeat(fx.secret.length - 10)}${fx.secret.slice(-4)}`
  const header = `${fx.header},secret=${mask},destination=we_1TestDestination`
  const d = await run(fx.original, header, 'whsec_fixture_5Qm2xT8bLr0VnKc3AAAA')
  assert.match(titles(d), /Wrong signing secret for this destination.*dashboard\.stripe\.com\/webhooks\/we_1TestDestination/)
  const short = await run(fx.original, header, fx.secret.slice(0, -1))
  assert.match(titles(short), /Wrong signing secret/)
  assert.doesNotMatch(titles(await run(fx.original, header)), /Wrong signing secret/)
})

test('a header pasted with quotes or a BOM-prefixed body is still diagnosed', async () => {
  assert.equal((await run(fx.original, `"${fx.header}"`)).match, true)
  assert.match(titles(await run('﻿' + fx.original)), /byte order mark/)
})
