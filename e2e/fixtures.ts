import { test as base, expect } from '@playwright/test'
import { POST } from '../api/run.ts'
import { runChaos, CHECK_IDS, type Outgoing, type Reply } from '../api/_lib/chaos.ts'
import { createDemo } from '../api/_lib/demos.ts'
import { checkTargetUrl } from '../api/_lib/net.ts'

// Hosts the app tries to reach (web fonts). They are blocked, never fetched: tests must not depend on the network.
const EXPECTED_BLOCKED = ['fonts.googleapis.com', 'fonts.gstatic.com']

/** What a test's "user endpoint" does with one delivery. It runs in this process; nothing is sent anywhere. */
export type Endpoint = (req: Outgoing, secret: string) => Promise<Reply>

/** Replaces the POST /api/run reply entirely (API failure tests). */
export type Override = { status: number; contentType?: string; body: string } | 'abort'

export interface Api {
  /** Every request body the page sent to /api/run, parsed. */
  calls: Record<string, unknown>[]
  /** Answers target:"url" runs. Without it, url runs are only forwarded to the real handler when it rejects them. */
  endpoint?: Endpoint
  override?: Override
  /** Holds every reply back until called; lets a test look at the page while a run is in flight. */
  hold?: Promise<void>
}

let ipCounter = 0

export const test = base.extend<{ api: Api; blocked: string[]; pageErrors: Error[] }>({
  blocked: [async ({ context }, use) => {
    const blocked: string[] = []
    await context.route(/^(?!https?:\/\/127\.0\.0\.1[:/]).*/, (route) => {
      const url = route.request().url()
      // data: and blob: URLs are not network requests.
      if (/^(data|blob):/.test(url)) return route.continue()
      blocked.push(new URL(url).host)
      return route.abort('blockedbyclient')
    })
    await use(blocked)
  }, { auto: true }],

  // The production build served by `vite preview` has no /api/run, so every test gets this stand-in. Demo targets
  // run through the real handler (api/run.ts) in this process, so the page renders genuine engine output. A url
  // target is answered by `api.endpoint` through the real engine (runChaos), or, when no endpoint is set, only
  // forwarded to the real handler if it will reject the input without touching the network.
  api: [async ({ page }, use) => {
    const api: Api = { calls: [] }
    await page.route('**/api/run', async (route) => {
      const req = route.request()
      const text = req.postData() ?? ''
      const input = JSON.parse(text) as Record<string, unknown>
      api.calls.push(input)
      await api.hold
      if (api.override === 'abort') return route.abort('failed')
      if (api.override) {
        return route.fulfill({ status: api.override.status, contentType: api.override.contentType ?? 'application/json', body: api.override.body })
      }
      const headers = { 'content-type': 'application/json', 'x-real-ip': `203.0.113.${(ipCounter++ % 250) + 1}-${Math.random()}` }

      if (input.target === 'url' && api.endpoint) {
        const endpoint = api.endpoint
        const secret = String(input.secret)
        const checks = CHECK_IDS.filter((id) => (input.checks as string[]).includes(id))
        const result = await runChaos({ secret, checks, send: (r) => endpoint(r, secret) })
        return route.fulfill({ json: { target: 'url', score: result.score, checks: result.checks } })
      }
      if (input.target === 'url') {
        // Never let the real handler resolve a public hostname or connect: only forward inputs it refuses up front.
        const refusedUpFront = await checkTargetUrl(String(input.url), async () => []).then(
          () => false,
          (e: Error) => !e.message.startsWith('Could not resolve'),
        )
        const secretOk = /^whsec_[A-Za-z0-9_+/=-]{16,256}$/.test(String(input.secret).trim())
        if (secretOk && !refusedUpFront) throw new Error(`E2E guard: refusing to forward ${String(input.url)} to the real handler`)
      }
      const res = await POST(new Request('https://e2e.invalid/api/run', { method: 'POST', headers, body: text }))
      return route.fulfill({ status: res.status, contentType: 'application/json', body: await res.text() })
    })
    await use(api)
  }, { auto: true }],

  pageErrors: [async ({ page, blocked }, use) => {
    const errors: Error[] = []
    page.on('pageerror', (e) => errors.push(e))
    await use(errors)
    // After the test: nothing threw, and nothing outside the known font hosts was requested.
    expect(errors, 'uncaught page errors').toEqual([])
    expect(blocked.filter((h) => !EXPECTED_BLOCKED.includes(h)), 'unexpected external requests').toEqual([])
  }, { auto: true }],
})

/** A "your endpoint" that verifies like the robust demo (raw bytes, every v1, 300s tolerance, dedupe). */
export const robustEndpoint = (): Endpoint => {
  const handlers = new Map<string, ReturnType<typeof createDemo>>()
  return async ({ body, headers }, secret) => {
    const demo = handlers.get(secret) ?? createDemo('robust', secret)
    handlers.set(secret, demo)
    const start = performance.now()
    const res = await demo.handle(new Request('https://endpoint.invalid/webhook', { method: 'POST', headers, body }))
    return { status: res.status, body: await res.text(), ms: Math.round(performance.now() - start) }
  }
}

export { expect }
