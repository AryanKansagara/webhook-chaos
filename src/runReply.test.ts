import assert from 'node:assert/strict'
import { test } from 'node:test'
import { runChaos } from '../api/_lib/chaos.ts'
import { readRunReply } from './runReply.ts'

const ok = { ok: true, status: 200 }
const message = (res: { ok: boolean; status: number }, json: unknown) => {
  try {
    readRunReply(res, json)
  } catch (e) {
    return (e as Error).message
  }
  return null
}

test('a real engine report, after a JSON round trip, is accepted unchanged', async () => {
  const send = async () => ({ status: 200, ms: 4, body: '{"received":true}' })
  const r = await runChaos({ secret: 'whsec_' + 'a'.repeat(32), checks: ['baseline', 'latency'], send })
  const reply = JSON.parse(JSON.stringify({ target: 'url', score: r.score, checks: r.checks }))
  assert.deepEqual(readRunReply(ok, reply), reply)
})

test('a demo report keeps its ledger', async () => {
  const ledger = { subscriptions: { sub_1: 'canceled' }, paidInvoices: 1, failedPayments: 0 }
  const reply = { target: 'robust', score: 100, checks: [], demo: { actual: ledger, expected: ledger, subA: 'sub_1', subB: 'sub_2' } }
  assert.equal(readRunReply(ok, reply), reply)
  assert.match(message(ok, { ...reply, demo: { ...reply.demo, actual: null } })!, /^Unexpected response \(HTTP 200\)\.$/)
})

test('a 2xx reply that is not a report is an error, never a report', () => {
  const unexpected = /^Unexpected response \(HTTP 200\)\.$/
  for (const json of [undefined, null, 0, 'ok', true, [], {}, { score: 1 }, { target: 'x', score: 1 }, { target: 'x', score: 'high', checks: [] },
    { target: 'x', score: NaN, checks: [] }, { target: 'x', score: 1, checks: {} }, { target: 'x', score: 1, checks: [null] },
    { target: 'x', score: 1, checks: [{ id: 'baseline', title: 't', summary: 's', verdict: 'great', deliveries: [] }] },
    { target: 'x', score: 1, checks: [{ id: 'unknown', title: 't', summary: 's', verdict: 'pass', deliveries: [] }] },
    { target: 'x', score: 1, checks: [{ id: 'baseline', title: 't', summary: 's', verdict: 'pass' }] },
    { target: 'x', score: 1, checks: [{ id: 'baseline', title: 't', summary: 's', verdict: 'pass', deliveries: [{ label: 'l' }] }] },
    { target: 'x', score: 1, checks: [], demo: {} },
  ])
    assert.match(message(ok, json) ?? 'accepted', unexpected, JSON.stringify(json))
})

test('a 2xx reply that carries an error message shows that message', () => {
  assert.equal(message(ok, { error: 'Maintenance window.' }), 'Maintenance window.')
  assert.equal(message(ok, { error: '' }), 'Unexpected response (HTTP 200).')
  assert.equal(message(ok, { error: 42 }), 'Unexpected response (HTTP 200).')
})

test('error statuses keep their messages', () => {
  const bad = (status: number) => ({ ok: false, status })
  assert.equal(message(bad(429), { error: 'Too many runs. Try again in a minute.' }), 'Too many runs. Try again in a minute.')
  assert.equal(message(bad(502), undefined), 'Unexpected response (HTTP 502).')
  assert.equal(message(bad(503), {}), 'HTTP 503')
  assert.equal(message(bad(500), null), 'HTTP 500')
  assert.equal(message(bad(500), []), 'HTTP 500')
  assert.equal(message(bad(500), { error: '' }), 'HTTP 500')
  assert.equal(message(bad(500), { error: { nested: true } }), 'HTTP 500')
  assert.equal(message(bad(400), { error: 'Invalid JSON.' }), 'Invalid JSON.')
})
