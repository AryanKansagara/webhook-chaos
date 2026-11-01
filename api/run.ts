import { CHECK_IDS, expectedLedger, runChaos, type Ledger, type RunResponse, type Send } from './_lib/chaos.ts'
import { createDemo, DEMO_IDS, type DemoId } from './_lib/demos.ts'
import { checkTargetUrl, clean, postWebhook, TIMEOUT_MS } from './_lib/net.ts'
import { randomSecret } from './_lib/stripe.ts'

export const config = { runtime: 'nodejs', maxDuration: 90 }
export type { RunResponse }

const RUN_BUDGET_MS = 75_000
const SECRET_RE = /^whsec_[A-Za-z0-9_+/=-]{16,256}$/

// Per-instance only: each serverless instance keeps its own window, so this is a speed bump, not a quota.
const RATE = { limit: 8, windowMs: 60_000 }
const hits = new Map<string, number[]>()
export function rateLimited(ip: string, now = Date.now()): boolean {
  const recent = (hits.get(ip) ?? []).filter((t) => now - t < RATE.windowMs)
  const limited = recent.length >= RATE.limit
  if (!limited) recent.push(now)
  if (hits.size > 10_000) hits.clear()
  hits.set(ip, recent)
  return limited
}

const error = (status: number, message: string) => Response.json({ error: message }, { status, headers: { 'cache-control': 'no-store' } })

export async function POST(request: Request): Promise<Response> {
  if (!request.headers.get('content-type')?.startsWith('application/json')) return error(415, 'Expected application/json.')
  const ip = request.headers.get('x-real-ip') ?? request.headers.get('x-forwarded-for')?.split(',')[0].trim() ?? 'unknown'
  if (rateLimited(ip)) return error(429, 'Too many runs. Try again in a minute.')

  const text = await request.text()
  if (text.length > 8192) return error(413, 'Request too large.')
  let input: { target?: unknown; url?: unknown; secret?: unknown; checks?: unknown }
  try {
    input = JSON.parse(text)
  } catch {
    return error(400, 'Invalid JSON.')
  }
  if (!input || typeof input !== 'object') return error(400, 'Invalid JSON.')

  const checks = Array.isArray(input.checks) ? CHECK_IDS.filter((id) => (input.checks as unknown[]).includes(id)) : []
  if (!checks.length) return error(400, 'Select at least one check.')

  const target = input.target
  let send: Send
  let secret: string
  let observe: (() => Ledger) | undefined

  if (DEMO_IDS.includes(target as DemoId)) {
    secret = randomSecret()
    const demo = createDemo(target as DemoId, secret)
    observe = () => demo.ledger
    send = async ({ body, headers }) => {
      const start = performance.now()
      const res = await demo.handle(new Request('https://demo.invalid/webhook', { method: 'POST', headers, body }))
      return { status: res.status, body: clean(await res.text()), ms: Math.round(performance.now() - start) }
    }
  } else if (target === 'url') {
    if (typeof input.secret !== 'string' || !SECRET_RE.test(input.secret.trim()))
      return error(400, 'Signing secret must look like whsec_… (copy it from your test-mode endpoint or `stripe listen`).')
    if (typeof input.url !== 'string' || input.url.length > 2048) return error(400, 'Enter your endpoint URL.')
    let url: URL
    try {
      url = await checkTargetUrl(input.url.trim())
    } catch (e) {
      return error(400, (e as Error).message)
    }
    secret = input.secret.trim()
    const deadline = Date.now() + RUN_BUDGET_MS
    send = async (req) => {
      const left = deadline - Date.now()
      if (left < 1000) return { status: null, ms: 0, body: '', error: 'Skipped: run time budget exhausted' }
      return postWebhook(url, req, Math.min(TIMEOUT_MS, left))
    }
  } else {
    return error(400, 'Unknown target.')
  }

  // The secret lives only in this closure for the duration of the run; it is never logged or returned.
  const result = await runChaos({ secret, checks, send, observe })
  const body: RunResponse = { target: target === 'url' ? 'url' : String(target), score: result.score, checks: result.checks }
  if (observe) body.demo = { actual: observe(), expected: expectedLedger(result.authentic), subA: result.subA, subB: result.subB }
  return Response.json(body, { headers: { 'cache-control': 'no-store' } })
}
