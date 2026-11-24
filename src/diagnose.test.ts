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
  assert.match(titles(await diagnose({ body, header, secrets: 'whsec_other_secret_000000', now })), /Wrong signing secret for this destination \| Body is byte-for-byte/)
  const bare = await signatureHeader(body, [secret], now, false)
  assert.match(titles(await diagnose({ body, header: bare, secrets: 'whsec_other_secret_000000', now })), /does not match/)
  assert.match(titles(await diagnose({ body, header: `t=${now},v0=abc`, secrets: secret, now })), /No v1/)
  assert.match(titles(await diagnose({ body, header: `Stripe-Signature: ${header}`, secrets: secret, now })), /Signature matches/)
})

// stripe-node's parseHeader compares keys and signatures as written (src/Webhooks.ts), so these headers cannot verify
// there either; the debugger must not say they would. The comparison against the library's own parser is in api/_lib/schema.test.ts.
test('a header with whitespace after a comma is rejected, and the whitespace finding says why', async () => {
  const good = await signatureHeader(body, [secret], now, false)
  assert.equal((await diagnose({ body, header: good, secrets: secret, now })).match, true)
  const spaced = good.replace(',v1=', ', v1=')
  assert.notEqual(spaced, good)
  const d = await diagnose({ body, header: spaced, secrets: secret, now })
  assert.equal(d.match, false, titles(d))
  const f = d.findings.find((x) => x.title === 'Whitespace inside the header')!
  assert.equal(f.level, 'bad')
  assert.match(f.detail, /" v1"/)
  assert.match(f.detail, /No signatures found with expected scheme/)
  assert.doesNotMatch(titles(d), /Signature matches/)
  // The same holds when the header is pasted with its name, or inside quotes.
  assert.equal((await diagnose({ body, header: `Stripe-Signature: ${spaced}`, secrets: secret, now })).match, false)
  assert.equal((await diagnose({ body, header: `"${spaced}"`, secrets: secret, now })).match, false)
})

test('whitespace anywhere around a key, an = or a v1 value is never reported as verifying', async () => {
  const t = now
  const v1 = (await signatureHeader(body, [secret], t, false)).split('v1=')[1]
  for (const header of [`t=${t},  v1=${v1}`, `t=${t},\tv1=${v1}`, `t=${t},\nv1=${v1}`, `t=${t},v1 =${v1}`, `t=${t},v1= ${v1}`, `t =${t},v1=${v1}`,
    `v1=${v1}, t=${t}`, `t=${t}, v1=${v1}, v0=ab`]) {
    const d = await diagnose({ body, header, secrets: secret, now })
    assert.equal(d.match, false, JSON.stringify(header))
    assert.ok(d.findings.some((f) => f.title === 'Whitespace inside the header'), JSON.stringify(header))
  }
  // Padding the library does tolerate: around the timestamp value, before a comma after t, and before debug entries.
  for (const header of [`t= ${t},v1=${v1}`, `t=${t} ,v1=${v1}`, `t=${t},v1=${v1}, payload=${(await diagnose({ body, header: `t=${t},v1=${v1}`, secrets: secret, now })).bodyHash}`]) {
    const d = await diagnose({ body, header, secrets: secret, now })
    assert.equal(d.match, true, `${JSON.stringify(header)}: ${titles(d)}`)
    assert.ok(!d.findings.some((f) => f.title === 'Whitespace inside the header'), JSON.stringify(header))
  }
})

test('during a secret roll, a v1 after a space is ignored: it only warns while another v1 still verifies', async () => {
  const t = now
  const rolled = await signatureHeader(body, ['whsec_old_0123456789abcdef', secret], t, false)
  const [first, second] = rolled.split(',').filter((e) => e.startsWith('v1='))
  const onlySecondPadded = `t=${t},${second}, ${first}`
  const ok = await diagnose({ body, header: onlySecondPadded, secrets: secret, now })
  assert.equal(ok.match, true, titles(ok))
  assert.equal(ok.findings.find((f) => f.title === 'Whitespace inside the header')!.level, 'warn')
  const bad = await diagnose({ body, header: `t=${t},${first}, ${second}`, secrets: secret, now })
  assert.equal(bad.match, false, titles(bad))
})

test('a v1 value with whitespace around it does not match, and says so', async () => {
  const t = now
  const v1 = (await signatureHeader(body, [secret], t, false)).split('v1=')[1]
  const d = await diagnose({ body, header: `t=${t},v1=${v1} ,v0=ab`, secrets: secret, now })
  assert.equal(d.match, false)
  assert.ok(d.findings.some((f) => f.title === 'Whitespace inside the header' && f.level === 'warn'))
})
