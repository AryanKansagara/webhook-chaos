// Stripe event building, signing and verification. Browser + Node safe (WebCrypto only).

// Current version in Stripe's published OpenAPI spec (github.com/stripe/openapi), checked 2026-11-16.
export const API_VERSION = '2026-09-30.endive'
export const DEFAULT_TOLERANCE = 300 // seconds, same default as stripe-node

export interface StripeEvent {
  id: string
  object: 'event'
  api_version: string
  created: number
  data: { object: Record<string, unknown> & { id: string; object: string }; previous_attributes?: Record<string, unknown> }
  livemode: false
  pending_webhooks: number
  request: { id: string | null; idempotency_key: string | null }
  type: string
}

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
const enc = new TextEncoder()

function randomChars(n: number): string {
  let s = ''
  for (const b of crypto.getRandomValues(new Uint8Array(n))) s += ALPHABET[b % ALPHABET.length]
  return s
}

/** Ids shaped like Stripe's: `sub_1Mow…` (24 chars) for most objects, short ones for cus_/si_/req_. */
export function stripeId(prefix: string, short = false): string {
  return short ? `${prefix}_${randomChars(14)}` : `${prefix}_1${randomChars(23)}`
}

export function randomSecret(): string {
  return `whsec_${randomChars(32)}`
}

/** Stripe delivers pretty-printed JSON (2-space indent). Re-serializing it changes the bytes. */
export function serialize(event: StripeEvent): string {
  return JSON.stringify(event, null, 2)
}

// ---------------------------------------------------------------- signing

export async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(message)))
  return Array.from(sig, (b) => b.toString(16).padStart(2, '0')).join('')
}

/** v1 = hex(HMAC-SHA256(secret, `${t}.${payload}`)) — the secret string (incl. `whsec_`) is the key. */
export function computeSignature(payload: string, secret: string, t: number): Promise<string> {
  return hmacHex(secret, `${t}.${payload}`)
}

/** A secret as the header's `secret=` entry shows it: same length, only the prefix and last four visible. */
export const maskSecret = (s: string) => `whsec_${'*'.repeat(Math.max(0, s.length - 10))}${s.slice(-4)}`

/**
 * Builds the header the way Stripe documents it for sandbox events:
 * `t=…,v1=…[,v1=…],v0=…,secret=whsec_***abcd,destination=we_…,payload=<sha256 suffix>`.
 * One v1 per active secret (oldest first), a fake v0, then the optional debugging entries.
 * Pass `destination: false` for the bare `t=…,v1=…` form.
 */
export async function signatureHeader(payload: string, secrets: string[], t: number, destination: string | false = stripeId('we')): Promise<string> {
  const parts = [`t=${t}`]
  for (const s of secrets) parts.push(`v1=${await computeSignature(payload, s, t)}`)
  if (destination)
    parts.push(
      `v0=${await computeSignature(payload, randomSecret(), t)}`,
      `secret=${maskSecret(secrets[secrets.length - 1])}`,
      `destination=${destination}`,
      `payload=${await payloadHashTail(payload)}`,
    )
  return parts.join(',')
}

export interface ParsedHeader {
  t: number | null
  v1: string[]
  v0: string[]
  unknown: string[]
  hasWhitespace: boolean
  /** Debug metadata newer Stripe headers carry (read by stripe-node for its error messages). */
  meta: { secret?: string; destination?: string; payload?: string }
}

const META_KEYS = ['secret', 'destination', 'payload']

/**
 * Same rules as stripe-node's `parseHeader` (src/Webhooks.ts): split on `,`, split each item on `=`, and compare the key
 * and the signature value exactly as written. Nothing is trimmed, so `t=1, v1=aa` (a space after the comma) has no v1 key
 * at all. Only the timestamp value is trimmed (stripe-node reads it with parseInt, which skips leading whitespace).
 * Keep every v1, ignore other schemes.
 * The debugging entries are read the way stripe-node's `getSignatureDebugMetadata` reads them: split on `,` plus any
 * whitespace, first value wins, over-long values are dropped.
 */
export function parseSignatureHeader(header: string): ParsedHeader {
  const out: ParsedHeader = { t: null, v1: [], v0: [], unknown: [], hasWhitespace: /\s/.test(header), meta: {} }
  for (const item of header.split(',')) {
    const [key, value = ''] = item.split('=')
    if (key === 't') out.t = /^\d+$/.test(value.trim()) ? Number(value.trim()) : null
    else if (key === 'v1') out.v1.push(value)
    else if (key === 'v0') out.v0.push(value)
    else if (key.trim() && !META_KEYS.includes(key.trim())) out.unknown.push(key)
  }
  for (const item of header.split(/,\s*/)) {
    const eq = item.indexOf('=')
    const key = item.slice(0, eq)
    if (eq === -1 || (key !== 'secret' && key !== 'destination' && key !== 'payload')) continue
    // First value wins and over-long values are dropped, as in stripe-node's getSignatureDebugMetadata.
    const full = item.slice(eq + 1).trim()
    const okPayload = key !== 'payload' || /^[0-9a-fA-F]{8}$/.test(full)
    if (out.meta[key] === undefined && full && full.length <= 100 && okPayload) out.meta[key] = key === 'payload' ? full.toLowerCase() : full
  }
  return out
}

/** Last 4 bytes of SHA-256(payload) as hex: the value of the header's `payload=` debug field. */
export async function payloadHashTail(payload: string): Promise<string> {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(payload)))
  return Array.from(hash.slice(-4), (b) => b.toString(16).padStart(2, '0')).join('')
}

/** Constant-time for equal-length inputs. */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

export type VerifyResult =
  | { ok: true; t: number; age: number }
  | { ok: false; reason: 'missing_header' | 'malformed' | 'no_signature' | 'mismatch' | 'stale'; message: string; age?: number }

/** Mirrors stripe-node's verifyHeader: signature check first, then one-sided timestamp tolerance. */
export async function verifySignature(
  payload: string,
  header: string | null | undefined,
  secret: string,
  opts: { tolerance?: number; now?: number } = {},
): Promise<VerifyResult> {
  const tolerance = opts.tolerance ?? DEFAULT_TOLERANCE
  const now = opts.now ?? Math.floor(Date.now() / 1000)
  if (!header) return { ok: false, reason: 'missing_header', message: 'No stripe-signature header value was provided.' }
  const p = parseSignatureHeader(header)
  if (p.t === null) return { ok: false, reason: 'malformed', message: 'Unable to extract timestamp and signatures from header' }
  if (!p.v1.length) return { ok: false, reason: 'no_signature', message: 'No signatures found with expected scheme' }
  const expected = await computeSignature(payload, secret, p.t)
  const age = now - p.t
  if (!p.v1.some((s) => safeEqual(expected, s)))
    return { ok: false, reason: 'mismatch', message: 'No signatures found matching the expected signature for payload.', age }
  if (tolerance > 0 && age > tolerance) return { ok: false, reason: 'stale', message: 'Timestamp outside the tolerance zone', age }
  return { ok: true, t: p.t, age }
}

// ---------------------------------------------------------------- events

export function makeEvent(
  type: string,
  object: StripeEvent['data']['object'],
  created: number,
  opts: { previous?: Record<string, unknown>; fromApi?: boolean } = {},
): StripeEvent {
  return {
    id: stripeId('evt'),
    object: 'event',
    api_version: API_VERSION,
    created,
    data: opts.previous ? { object, previous_attributes: opts.previous } : { object },
    livemode: false,
    pending_webhooks: 1,
    // Events caused by an API call carry the request id; automatic ones (billing) have nulls.
    request: opts.fromApi ? { id: stripeId('req', true), idempotency_key: crypto.randomUUID() } : { id: null, idempotency_key: null },
    type,
  }
}

interface Plan { price: string; product: string; amount: number }

function subscriptionItems(subId: string, itemId: string, plan: Plan, created: number, periodStart: number) {
  const periodEnd = periodStart + 30 * 86400
  return {
    object: 'list',
    data: [
      {
        id: itemId,
        object: 'subscription_item',
        created,
        current_period_end: periodEnd,
        current_period_start: periodStart,
        discounts: [],
        metadata: {},
        price: {
          id: plan.price,
          object: 'price',
          active: true,
          billing_scheme: 'per_unit',
          created: created - 86400,
          currency: 'usd',
          custom_unit_amount: null,
          livemode: false,
          lookup_key: null,
          metadata: {},
          nickname: null,
          product: plan.product,
          recurring: { interval: 'month', interval_count: 1, meter: null, usage_type: 'licensed' },
          tax_behavior: 'unspecified',
          tiers_mode: null,
          transform_quantity: null,
          type: 'recurring',
          unit_amount: plan.amount,
          unit_amount_decimal: String(plan.amount),
        },
        quantity: 1,
        subscription: subId,
        tax_rates: [],
      },
    ],
    has_more: false,
    total_count: 1,
    url: `/v1/subscription_items?subscription=${subId}`,
  }
}

interface SubFields { status: string; plan: Plan; latestInvoice: string; canceledAt?: number | null; reason?: string | null }

function subscription(id: string, customer: string, itemId: string, created: number, f: SubFields) {
  return {
    id,
    object: 'subscription',
    application: null,
    application_fee_percent: null,
    automatic_tax: { disabled_reason: null, enabled: false, liability: null },
    billing_cycle_anchor: created,
    billing_cycle_anchor_config: null,
    billing_mode: { flexible: null, type: 'classic' },
    billing_schedules: [],
    billing_thresholds: null,
    cancel_at: null,
    cancel_at_period_end: false,
    canceled_at: f.canceledAt ?? null,
    cancellation_details: { comment: null, feedback: null, reason: f.reason ?? null },
    collection_method: 'charge_automatically',
    created,
    currency: 'usd',
    customer,
    days_until_due: null,
    default_payment_method: null,
    default_source: null,
    default_tax_rates: [],
    description: null,
    discounts: [],
    ended_at: f.canceledAt ?? null,
    invoice_settings: { account_tax_ids: null, issuer: { type: 'self' } },
    items: subscriptionItems(id, itemId, f.plan, created, created),
    latest_invoice: f.latestInvoice,
    livemode: false,
    metadata: {},
    next_pending_invoice_item_invoice: null,
    on_behalf_of: null,
    pause_collection: null,
    payment_settings: { payment_method_options: null, payment_method_types: null, save_default_payment_method: 'off' },
    pending_invoice_item_interval: null,
    pending_setup_intent: null,
    pending_update: null,
    schedule: null,
    start_date: created,
    status: f.status,
    test_clock: null,
    transfer_data: null,
    trial_end: null,
    trial_settings: { end_behavior: { missing_payment_method: 'create_invoice' } },
    trial_start: null,
  }
}

function invoice(id: string, customer: string, subId: string, created: number, amount: number, paid: boolean, reason: string) {
  const periodStart = created - (reason === 'subscription_create' ? 0 : 30 * 86400)
  const line = {
    id: stripeId('il'),
    object: 'line_item',
    amount,
    currency: 'usd',
    description: reason === 'manual' ? 'Annual plan' : `1 × ${amount === 1500 ? 'Starter' : 'Pro'} (at $${(amount / 100).toFixed(2)} / month)`,
    discount_amounts: [],
    discountable: true,
    discounts: [],
    invoice: id,
    livemode: false,
    metadata: {},
    parent: null,
    period: { end: periodStart + 30 * 86400, start: periodStart },
    pretax_credit_amounts: [],
    pricing: { price_details: null, type: 'price_details', unit_amount_decimal: String(amount) },
    quantity: 1,
    quantity_decimal: '1',
    subscription: subId,
    subtotal: amount,
    taxes: [],
  }
  return {
    id,
    object: 'invoice',
    account_country: 'US',
    account_name: 'Acme Test Co',
    account_tax_ids: null,
    amount_due: amount,
    amount_overpaid: 0,
    amount_paid: paid ? amount : 0,
    amount_paid_off_stripe: 0,
    amount_remaining: paid ? 0 : amount,
    amount_shipping: 0,
    application: null,
    attempt_count: 1,
    attempted: true,
    auto_advance: !paid,
    automatic_tax: { disabled_reason: null, enabled: false, liability: null, provider: null, status: null },
    automatically_finalizes_at: null,
    billing_reason: reason,
    collection_method: 'charge_automatically',
    created,
    currency: 'usd',
    custom_fields: null,
    customer,
    customer_address: null,
    customer_email: 'jenny.rosen@example.com',
    customer_name: 'Jenny Rosen',
    customer_phone: null,
    customer_shipping: null,
    customer_tax_exempt: 'none',
    customer_tax_ids: [],
    default_payment_method: null,
    default_source: null,
    default_tax_rates: [],
    description: null,
    discounts: [],
    due_date: null,
    effective_at: created,
    ending_balance: 0,
    footer: null,
    from_invoice: null,
    hosted_invoice_url: `https://invoice.stripe.com/i/acct_test/test_${id.slice(3)}`,
    invoice_pdf: `https://pay.stripe.com/invoice/acct_test/test_${id.slice(3)}/pdf`,
    issuer: { type: 'self' },
    last_finalization_error: null,
    latest_revision: null,
    lines: { object: 'list', data: [line], has_more: false, total_count: 1, url: `/v1/invoices/${id}/lines` },
    livemode: false,
    metadata: {},
    next_payment_attempt: paid ? null : created + 3 * 86400,
    number: `ACME-${String(created % 10000).padStart(4, '0')}`,
    on_behalf_of: null,
    parent: { quote_details: null, subscription_details: { metadata: {}, subscription: subId }, type: 'subscription_details' },
    payment_settings: { default_mandate: null, payment_method_options: null, payment_method_types: null },
    period_end: created,
    period_start: periodStart,
    post_payment_credit_notes_amount: 0,
    pre_payment_credit_notes_amount: 0,
    receipt_number: null,
    rendering: null,
    shipping_cost: null,
    shipping_details: null,
    starting_balance: 0,
    statement_descriptor: null,
    status: paid ? 'paid' : 'open',
    status_transitions: { finalized_at: created, marked_uncollectible_at: null, paid_at: paid ? created : null, voided_at: null },
    subtotal: amount,
    subtotal_excluding_tax: amount,
    test_clock: null,
    total: amount,
    total_discount_amounts: [],
    total_excluding_tax: amount,
    total_pretax_credit_amounts: [],
    total_taxes: [],
    webhooks_delivered_at: created,
  }
}

export interface Scenario {
  customer: string
  /** Subscription A lifecycle, in true order. */
  lifecycle: StripeEvent[]
  /** Subscription B, true order: created, updated, deleted. Delivered out of order by the tester. */
  reorder: StripeEvent[]
  subA: string
  subB: string
  /** Fresh invoice.paid events for the negative (should-be-rejected) and rotation probes. */
  probe: () => StripeEvent
  /** An authentic event of a type billing handlers rarely subscribe to on purpose. */
  unhandled: () => StripeEvent
}

/** One customer, two subscriptions, consistent ids. Event `created` values are in the recent past. */
export function buildScenario(now: number): Scenario {
  const customer = stripeId('cus', true)
  const starter: Plan = { price: stripeId('price'), product: stripeId('prod', true), amount: 1500 }
  const pro: Plan = { price: stripeId('price'), product: stripeId('prod', true), amount: 4900 }
  const t0 = now - 120

  const subA = stripeId('sub')
  const itemA = stripeId('si', true)
  const inv1 = stripeId('in')
  const inv2 = stripeId('in')
  const a = (status: string, plan: Plan, latest: string, extra: Partial<SubFields> = {}) =>
    subscription(subA, customer, itemA, t0, { status, plan, latestInvoice: latest, ...extra })
  const lifecycle = [
    makeEvent('customer.subscription.created', a('active', starter, inv1), t0, { fromApi: true }),
    makeEvent('invoice.paid', invoice(inv1, customer, subA, t0, starter.amount, true, 'subscription_create'), t0 + 1),
    makeEvent('customer.subscription.updated', a('active', pro, inv1), t0 + 20, {
      fromApi: true,
      previous: { items: subscriptionItems(subA, itemA, starter, t0, t0) },
    }),
    makeEvent('invoice.payment_failed', invoice(inv2, customer, subA, t0 + 40, pro.amount, false, 'subscription_cycle'), t0 + 40),
    makeEvent('customer.subscription.deleted', a('canceled', pro, inv2, { canceledAt: t0 + 60, reason: 'payment_failed' }), t0 + 60),
  ]

  const subB = stripeId('sub')
  const itemB = stripeId('si', true)
  const inv3 = stripeId('in')
  const b = (status: string, plan: Plan, extra: Partial<SubFields> = {}) =>
    subscription(subB, customer, itemB, t0 + 5, { status, plan, latestInvoice: inv3, ...extra })
  const reorder = [
    makeEvent('customer.subscription.created', b('active', starter), t0 + 5, { fromApi: true }),
    makeEvent('customer.subscription.updated', b('active', pro), t0 + 30, {
      fromApi: true,
      previous: { items: subscriptionItems(subB, itemB, starter, t0 + 5, t0 + 5) },
    }),
    makeEvent('customer.subscription.deleted', b('canceled', pro, { canceledAt: t0 + 50, reason: 'cancellation_requested' }), t0 + 50, {
      fromApi: true,
    }),
  ]

  const probe = () => {
    const inv = stripeId('in')
    return makeEvent('invoice.paid', invoice(inv, customer, subA, now - 5, 99900, true, 'manual'), now - 5)
  }
  const unhandled = () =>
    makeEvent('customer.updated', {
      id: customer,
      object: 'customer',
      address: null,
      balance: 0,
      created: t0 - 86400,
      currency: 'usd',
      default_source: null,
      delinquent: true,
      description: null,
      discount: null,
      email: 'jenny.rosen@example.com',
      invoice_prefix: 'ACME',
      invoice_settings: { custom_fields: null, default_payment_method: null, footer: null, rendering_options: null },
      livemode: false,
      metadata: {},
      name: 'Jenny Rosen',
      next_invoice_sequence: 3,
      phone: null,
      preferred_locales: [],
      shipping: null,
      tax_exempt: 'none',
      test_clock: null,
    }, now - 4, { previous: { delinquent: false } })
  return { customer, lifecycle, reorder, subA, subB, probe, unhandled }
}
