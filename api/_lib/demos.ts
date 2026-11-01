// Built-in demo webhook endpoints, invoked in-process so their state is consistent within one run.
// Written the way real handlers are written, bugs included, so the report shows what they cause.
import { createHmac, timingSafeEqual } from 'node:crypto'
import { applyEvent, emptyLedger, type Ledger } from './chaos.ts'
import type { StripeEvent } from './stripe.ts'

export type DemoId = 'naive' | 'reparsed' | 'robust'
export const DEMO_IDS: DemoId[] = ['naive', 'reparsed', 'robust']

export interface Demo { handle: (req: Request) => Promise<Response>; ledger: Ledger }

const json = (status: number, body: unknown) => Response.json(body, { status })
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const hmac = (secret: string, t: string, payload: string) => createHmac('sha256', secret).update(`${t}.${payload}`).digest('hex')

/** Correct verification: raw bytes, every v1, constant-time compare, 300s tolerance. */
function verify(raw: string, header: string | null, secret: string, tolerance = 300): StripeEvent | string {
  if (!header) return 'No stripe-signature header value was provided.'
  const items = header.split(',').map((kv) => kv.split('='))
  const t = items.find(([k]) => k === 't')?.[1]
  const sigs = items.filter(([k]) => k === 'v1').map(([, v]) => v)
  if (!t || !/^\d+$/.test(t) || !sigs.length) return 'Unable to extract timestamp and signatures from header'
  const expected = Buffer.from(hmac(secret, t, raw))
  const ok = sigs.some((s) => {
    const b = Buffer.from(s)
    return b.length === expected.length && timingSafeEqual(b, expected)
  })
  if (!ok) return 'No signatures found matching the expected signature for payload.'
  if (Math.floor(Date.now() / 1000) - Number(t) > tolerance) return 'Timestamp outside the tolerance zone'
  return JSON.parse(raw) as StripeEvent
}

export function createDemo(id: DemoId, secret: string): Demo {
  const ledger = emptyLedger()

  // Verifies the HMAC, but: no timestamp tolerance, no dedupe, last-write-wins,
  // and does slow work (a dunning email) before responding.
  const naive = async (req: Request) => {
    const raw = await req.text()
    const header = req.headers.get('stripe-signature') ?? ''
    const t = /t=(\d+)/.exec(header)?.[1] ?? ''
    const v1 = /v1=([0-9a-f]+)/.exec(header)?.[1]
    if (v1 !== hmac(secret, t, raw)) return json(400, { error: 'Invalid signature' })
    const event = JSON.parse(raw) as StripeEvent
    if (event.type === 'invoice.payment_failed') await sleep(3200) // "send email" inline
    applyEvent(ledger, event)
    return json(200, { received: true })
  }

  // The classic stripe-node #341 bug: body parsed (express.json()), then re-stringified for verification.
  const reparsed = async (req: Request) => {
    const event = (await req.json()) as StripeEvent
    const result = verify(JSON.stringify(event), req.headers.get('stripe-signature'), secret)
    if (typeof result === 'string') return json(400, { error: `Webhook Error: ${result}` })
    applyEvent(ledger, result)
    return json(200, { received: true })
  }

  // Raw-body verification, dedupe by event.id, and never let an older event overwrite newer state.
  const seen = new Set<string>()
  const lastSeen = new Map<string, number>()
  const robust = async (req: Request) => {
    const result = verify(await req.text(), req.headers.get('stripe-signature'), secret)
    if (typeof result === 'string') return json(400, { error: `Webhook Error: ${result}` })
    if (seen.has(result.id)) return json(200, { received: true, duplicate: true })
    seen.add(result.id)
    const obj = result.data.object
    if (result.type.startsWith('customer.subscription.')) {
      // In production, prefer re-fetching the subscription from the API: `created` has 1s resolution.
      if (ledger.subscriptions[obj.id] === 'canceled' || result.created < (lastSeen.get(obj.id) ?? 0))
        return json(200, { received: true, ignored: 'stale' })
      lastSeen.set(obj.id, result.created)
    }
    applyEvent(ledger, result)
    return json(200, { received: true })
  }

  return { handle: { naive, reparsed, robust }[id], ledger }
}
