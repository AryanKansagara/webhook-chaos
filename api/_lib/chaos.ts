// Chaos checks: builds deliveries, sends them through an injected `send`, grades the replies.
import { buildScenario, randomSecret, serialize, signatureHeader, type StripeEvent } from './stripe.ts'

export type CheckId =
  | 'baseline'
  | 'duplicate'
  | 'out_of_order'
  | 'bad_signature'
  | 'stale_timestamp'
  | 'tampered_body'
  | 'missing_header'
  | 'latency'

export const CHECKS: { id: CheckId; title: string; expect: string; why: string }[] = [
  { id: 'baseline', title: 'Valid delivery, in order', expect: '2xx for each', why: 'Five correctly signed lifecycle events. Failures here usually mean the body was parsed before verification.' },
  { id: 'duplicate', title: 'Duplicate delivery', expect: '2xx, processed once', why: 'Stripe delivers at least once. The same event id arrives again with a fresh signature.' },
  { id: 'out_of_order', title: 'Out-of-order delivery', expect: '2xx, final state canceled', why: 'Stripe does not guarantee order: customer.subscription.deleted arrives before the earlier .updated.' },
  { id: 'bad_signature', title: 'Forged signature', expect: '4xx', why: 'Signed with a different secret. Accepting it lets anyone mark invoices paid.' },
  { id: 'stale_timestamp', title: 'Replayed (stale) timestamp', expect: '4xx', why: 'Correctly signed, but t is 10 minutes old (tolerance is 300s). Accepting it allows replay attacks.' },
  { id: 'tampered_body', title: 'Tampered body', expect: '4xx', why: 'Signed, then amount_paid edited in transit.' },
  { id: 'missing_header', title: 'Missing Stripe-Signature', expect: '4xx', why: 'No signature header at all. Some handlers skip verification when the header is absent.' },
  { id: 'latency', title: 'Response time', expect: '< 3s each', why: 'Stripe expects a quick 2xx. Do slow work after acknowledging (queue it).' },
]
export const CHECK_IDS = CHECKS.map((c) => c.id)
export const SLOW_MS = 3000
export const MAX_DELIVERIES = 20
const STALE_BY = 600

export interface Outgoing { body: string; headers: Record<string, string> }
export interface Reply { status: number | null; ms: number; body: string; error?: string }
export type Send = (req: Outgoing) => Promise<Reply>
export type Verdict = 'pass' | 'warn' | 'fail' | 'skip'
export interface Delivery extends Reply { label: string; type: string; eventId: string }
export interface CheckResult { id: CheckId; title: string; verdict: Verdict; summary: string; deliveries: Delivery[] }

/** Response shape returned by POST /api/run (shared with the client). */
export interface RunResponse {
  target: string
  score: number
  checks: CheckResult[]
  demo?: { actual: Ledger; expected: Ledger; subA: string; subB: string }
}

// ---------------------------------------------------------------- ledger (what an endpoint "did")

export interface Ledger { subscriptions: Record<string, string>; paidInvoices: number; failedPayments: number }
export const emptyLedger = (): Ledger => ({ subscriptions: {}, paidInvoices: 0, failedPayments: 0 })

/** The business logic of a typical integration: mirror subscription status, count payments. */
export function applyEvent(l: Ledger, e: StripeEvent): void {
  const obj = e.data.object
  if (e.type.startsWith('customer.subscription.')) l.subscriptions[obj.id] = String(obj.status)
  else if (e.type === 'invoice.paid') l.paidInvoices++
  else if (e.type === 'invoice.payment_failed') l.failedPayments++
}

/** Correct end state: each authentic event applied exactly once, in true order. */
export function expectedLedger(events: StripeEvent[]): Ledger {
  const l = emptyLedger()
  const unique = [...new Map(events.map((e) => [e.id, e])).values()].sort((a, b) => a.created - b.created)
  for (const e of unique) applyEvent(l, e)
  return l
}

// ---------------------------------------------------------------- runner

type Mode = 'valid' | 'bad_signature' | 'stale' | 'tampered' | 'missing'

const is2xx = (s: number | null) => s !== null && s >= 200 && s < 300
const is4xx = (s: number | null) => s !== null && s >= 400 && s < 500
const describe = (d: Delivery) => (d.status === null ? d.error ?? 'no response' : `HTTP ${d.status}`)

export const BASE_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'user-agent': 'Stripe/1.0 (+https://stripe.com/docs/webhooks) WebhookChaos/1.0',
  accept: '*/*; q=0.5, application/xml',
  'cache-control': 'no-cache',
}

export interface RunOptions {
  secret: string
  checks: CheckId[]
  send: Send
  /** Demo targets expose their ledger so duplicate/ordering bugs become visible. */
  observe?: () => Ledger
  now?: () => number
}

export interface RunResult { score: number; checks: CheckResult[]; authentic: StripeEvent[]; subA: string; subB: string }

export async function runChaos(opts: RunOptions): Promise<RunResult> {
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000))
  const on = new Set(opts.checks)
  const sc = buildScenario(now())
  const authentic: StripeEvent[] = []
  const all: Delivery[] = []
  let failuresInARow = 0

  const deliver = async (label: string, event: StripeEvent, mode: Mode = 'valid'): Promise<Delivery> => {
    const base = { label, type: event.type, eventId: event.id }
    if (all.length >= MAX_DELIVERIES || failuresInARow >= 3) {
      return { ...base, status: null, ms: 0, body: '', error: 'Skipped: endpoint unreachable or delivery cap reached' }
    }
    let body = serialize(event)
    const t = mode === 'stale' ? now() - STALE_BY : now()
    const headers: Record<string, string> = { ...BASE_HEADERS }
    if (mode !== 'missing') headers['stripe-signature'] = await signatureHeader(body, [mode === 'bad_signature' ? randomSecret() : opts.secret], t)
    if (mode === 'tampered') body = body.replace(/"amount_paid": \d+/, '"amount_paid": 1')
    const reply = await opts.send({ body, headers })
    failuresInARow = reply.status === null ? failuresInARow + 1 : 0
    if (mode === 'valid') authentic.push(event)
    const d = { ...base, ...reply }
    all.push(d)
    return d
  }

  const results: CheckResult[] = []
  const add = (id: CheckId, verdict: Verdict, summary: string, deliveries: Delivery[]) =>
    results.push({ id, title: CHECKS.find((c) => c.id === id)!.title, verdict, summary, deliveries })
  const httpFail = (ds: Delivery[]) => ds.find((d) => !is2xx(d.status))

  if (on.has('baseline')) {
    const ds: Delivery[] = []
    for (const e of sc.lifecycle) ds.push(await deliver(e.type, e))
    const bad = httpFail(ds)
    if (!bad) add('baseline', 'pass', 'All five authentic events were acknowledged with 2xx.', ds)
    else
      add('baseline', 'fail', `${bad.type} got ${describe(bad)}. ${bad.status === 400 || bad.status === 401
        ? 'Authentic events are being rejected: your framework most likely parsed or re-encoded the body before verification. Verify the raw bytes.'
        : bad.status !== null && bad.status >= 300 && bad.status < 400
          ? 'Stripe treats redirects as failed deliveries. Register the final URL.'
          : 'Stripe will retry and eventually disable the endpoint. If your handler fetches these objects from the Stripe API, note that test ids from this tool do not exist in your account.'}`, ds)
  }

  if (on.has('duplicate')) {
    const paid = sc.lifecycle[1]
    const before = opts.observe?.().paidInvoices ?? 0
    const ds: Delivery[] = []
    if (!on.has('baseline')) ds.push(await deliver('Original delivery', paid))
    ds.push(await deliver('Redelivery (same event id)', paid))
    const delta = (opts.observe?.().paidInvoices ?? 0) - before
    const bad = httpFail(ds)
    if (bad) add('duplicate', 'fail', `Redelivery got ${describe(bad)}. Duplicates must still be acknowledged with 2xx, or Stripe keeps retrying.`, ds)
    else if (opts.observe && delta > (on.has('baseline') ? 0 : 1))
      add('duplicate', 'fail', 'Acknowledged, but the payment was recorded twice. Deduplicate on event.id before applying side effects.', ds)
    else
      add('duplicate', 'pass', opts.observe
        ? 'Acknowledged and processed once.'
        : 'Acknowledged with 2xx. We cannot see your database: confirm you store event.id and skip events already processed.', ds)
  }

  if (on.has('out_of_order')) {
    const [created, updated, deleted] = sc.reorder
    const ds = [
      await deliver(created.type, created),
      await deliver(`${deleted.type} (arrives early)`, deleted),
      await deliver(`${updated.type} (arrives late)`, updated),
    ]
    const status = opts.observe?.().subscriptions[sc.subB]
    const bad = httpFail(ds)
    if (bad) add('out_of_order', 'fail', `${bad.type} got ${describe(bad)}. Events can arrive in any order; never reject one because a related event has not arrived yet.`, ds)
    else if (opts.observe && status !== 'canceled')
      add('out_of_order', 'fail', `Acknowledged, but the subscription ended up "${status}" after it was deleted. The late .updated overwrote the cancellation.`, ds)
    else
      add('out_of_order', 'pass', opts.observe
        ? 'Acknowledged, and the stale update did not resurrect the canceled subscription.'
        : 'Acknowledged with 2xx. Make sure a late .updated cannot overwrite .deleted: re-fetch the object from the API or guard on state transitions.', ds)
  }

  const negative = async (id: CheckId, mode: Mode, label: string, danger: string) => {
    if (!on.has(id)) return
    const d = await deliver(label, sc.probe(), mode)
    if (is4xx(d.status)) add(id, 'pass', `Rejected with HTTP ${d.status}.`, [d])
    else if (is2xx(d.status)) add(id, 'fail', `Accepted with HTTP ${d.status}. ${danger}`, [d])
    else if (d.status !== null && d.status >= 500)
      add(id, 'warn', `Rejected, but with HTTP ${d.status}. Return 400 for verification failures; 5xx suggests an unhandled exception.`, [d])
    else add(id, 'fail', `Inconclusive: ${describe(d)}.`, [d])
  }
  await negative('bad_signature', 'bad_signature', 'Signed with the wrong secret', 'Anyone who knows your URL can forge events.')
  await negative('stale_timestamp', 'stale', `Signed, t = now - ${STALE_BY}s`, 'A captured request can be replayed forever. Enforce the 300s tolerance (the official libraries do).')
  await negative('tampered_body', 'tampered', 'amount_paid edited after signing', 'The signature is not being checked against the bytes you received.')
  await negative('missing_header', 'missing', 'No Stripe-Signature header', 'Verification is skipped when the header is absent.')

  if (on.has('latency')) {
    const timed = all.filter((d) => d.status !== null)
    const slow = timed.filter((d) => d.ms >= SLOW_MS)
    const timeouts = all.filter((d) => d.error?.startsWith('Timed out'))
    const max = Math.max(0, ...timed.map((d) => d.ms))
    if (!all.length) add('latency', 'skip', 'No deliveries to measure.', [])
    else if (timeouts.length) add('latency', 'fail', `${timeouts.length} deliveries timed out. Acknowledge first, then process asynchronously.`, timeouts)
    else if (slow.length) add('latency', 'warn', `${slow.length} of ${timed.length} responses took ≥ ${SLOW_MS / 1000}s (slowest ${max} ms). Move slow work (emails, API calls) to a queue.`, slow)
    else add('latency', 'pass', `Slowest response ${max} ms across ${timed.length} deliveries.`, [])
  }

  const graded = results.filter((r) => r.verdict !== 'skip')
  const points = graded.reduce((s, r) => s + (r.verdict === 'pass' ? 1 : r.verdict === 'warn' ? 0.5 : 0), 0)
  const score = graded.length ? Math.round((100 * points) / graded.length) : 0
  return { score, checks: results, authentic, subA: sc.subA, subB: sc.subB }
}
