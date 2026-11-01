import { useEffect, useState } from 'react'
import { CHECKS, SLOW_MS, type CheckId, type CheckResult, type Ledger, type RunResponse, type Verdict } from '../api/_lib/chaos.ts'

type Target = 'naive' | 'reparsed' | 'robust' | 'url'

const TARGETS: { id: Target; title: string; desc: string }[] = [
  { id: 'naive', title: 'Naive demo', desc: 'Verifies the HMAC, but skips the timestamp check, never dedupes, lets the last event win, and sends email before responding.' },
  { id: 'reparsed', title: 'Re-parsing demo', desc: 'Parses JSON first, then verifies JSON.stringify(body). The classic stripe-node #341 bug.' },
  { id: 'robust', title: 'Robust demo', desc: 'Raw body, constant-time compare, 300s tolerance, dedupe by event.id, ignores stale updates.' },
  { id: 'url', title: 'Your endpoint', desc: 'Send signed test events to your own HTTPS endpoint.' },
]

const BADGE: Record<Verdict, string> = { pass: 'good', warn: 'warn', fail: 'bad', skip: 'info' }
const FINDING: Record<Verdict, string> = { pass: 'good', warn: 'warn', fail: 'bad', skip: '' }

export function ChaosTab({ autorun }: { autorun: number }) {
  const [target, setTarget] = useState<Target>('naive')
  const [url, setUrl] = useState('')
  const [secret, setSecret] = useState('')
  const [checks, setChecks] = useState<Set<CheckId>>(new Set(CHECKS.map((c) => c.id)))
  const [running, setRunning] = useState(false)
  const [report, setReport] = useState<RunResponse | null>(null)
  const [error, setError] = useState('')

  async function run(t: Target = target) {
    setRunning(true)
    setError('')
    setReport(null)
    try {
      const res = await fetch('/api/run', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(t === 'url' ? { target: t, url, secret, checks: [...checks] } : { target: t, checks: [...checks] }),
      })
      const json = await res.json().catch(() => ({ error: `Unexpected response (HTTP ${res.status}).` }))
      if (!res.ok) throw new Error(json.error ?? `HTTP ${res.status}`)
      setReport(json as RunResponse)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setRunning(false)
    }
  }

  useEffect(() => {
    if (!autorun) return
    setTarget('naive')
    run('naive')
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autorun])

  const toggle = (id: CheckId) => setChecks((s) => {
    const n = new Set(s)
    if (n.has(id)) n.delete(id)
    else n.add(id)
    return n
  })
  const canRun = !running && checks.size > 0 && (target !== 'url' || (url.trim() && secret.trim()))

  return (
    <>
      <div className="grid cols-2">
        <div className="panel">
          <h2>1. Target</h2>
          <div className="choices" role="radiogroup" aria-label="Target">
            {TARGETS.map((t) => (
              <label key={t.id} className={`choice${target === t.id ? ' on' : ''}`}>
                <input type="radio" name="target" checked={target === t.id} onChange={() => setTarget(t.id)} />
                <span>
                  <strong>{t.title}</strong>
                  <span className="muted small">{t.desc}</span>
                </span>
              </label>
            ))}
          </div>
          {target === 'url' && (
            <div className="stack">
              <label className="field">
                <span>Endpoint URL</span>
                <input type="url" inputMode="url" placeholder="https://your-app.com/api/webhooks/stripe" value={url} onChange={(e) => setUrl(e.target.value)} autoComplete="off" spellCheck={false} />
              </label>
              <label className="field">
                <span>Signing secret (test mode)</span>
                <input type="password" placeholder="whsec_…" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="off" spellCheck={false} />
              </label>
              <div className="finding warn small">
                <strong>Use a test-mode endpoint.</strong> Your secret is sent over HTTPS to this tool's server function, used only to sign
                this run's requests, and then discarded. It is never stored or logged. Every event has <code>livemode: false</code> and
                synthetic ids that do not exist in your account. HTTPS only; private and internal addresses are refused.
              </div>
            </div>
          )}
        </div>

        <div className="panel">
          <h2>2. Checks</h2>
          <div className="checks">
            {CHECKS.map((c) => (
              <label key={c.id} className="check">
                <input type="checkbox" checked={checks.has(c.id)} onChange={() => toggle(c.id)} />
                <span>
                  <strong>{c.title}</strong> <span className="badge info">{c.expect}</span>
                  <span className="muted small">{c.why}</span>
                </span>
              </label>
            ))}
          </div>
        </div>
      </div>

      <div className="row run-row">
        <button className="btn" disabled={!canRun} onClick={() => run()}>
          {running ? 'Running…' : `Run ${checks.size} check${checks.size === 1 ? '' : 's'}`}
        </button>
        {running && <span className="muted small">{target === 'naive' ? 'The naive endpoint sends email before responding, so this takes a few seconds.' : 'Delivering events one at a time…'}</span>}
        {error && <span className="badge bad" role="alert">{error}</span>}
      </div>

      {report && <Report report={report} />}
    </>
  )
}

function Report({ report }: { report: RunResponse }) {
  const graded = report.checks.filter((c) => c.verdict !== 'skip')
  const count = (v: Verdict) => graded.filter((c) => c.verdict === v).length
  const all = report.checks.flatMap((c) => c.deliveries).filter((d) => d.status !== null)
  const slowest = Math.max(0, ...all.map((d) => d.ms))
  const tone = report.score >= 90 ? 'good' : report.score >= 60 ? 'warn' : 'bad'
  return (
    <section aria-live="polite">
      <div className="stats">
        <div className="stat">
          <div className="label">Score</div>
          <div className={`value tone-${tone}`}>{report.score}<span className="muted small"> / 100</span></div>
          <div className="bar"><span style={{ width: `${report.score}%`, background: `var(--${tone})` }} /></div>
        </div>
        <div className="stat"><div className="label">Passed</div><div className="value">{count('pass')}<span className="muted small"> / {graded.length}</span></div></div>
        <div className="stat"><div className="label">Failed · warnings</div><div className="value">{count('fail')} · {count('warn')}</div></div>
        <div className="stat"><div className="label">Slowest response</div><div className={`value${slowest >= SLOW_MS ? ' tone-warn' : ''}`}>{slowest} ms</div></div>
      </div>

      {report.demo && <LedgerTable demo={report.demo} />}

      <div className="panel">
        <h2>Results</h2>
        {report.checks.map((c) => <CheckRow key={c.id} c={c} />)}
      </div>

      <Fixes failed={report.checks.filter((c) => c.verdict !== 'pass').map((c) => c.id)} />
    </section>
  )
}

function CheckRow({ c }: { c: CheckResult }) {
  return (
    <div className={`finding ${FINDING[c.verdict]}`}>
      <div className="row">
        <span className={`badge ${BADGE[c.verdict]}`}>{c.verdict.toUpperCase()}</span>
        <strong>{c.title}</strong>
      </div>
      <p className="summary">{c.summary}</p>
      {c.deliveries.length > 0 && (
        <details open={c.verdict === 'fail'}>
          <summary className="muted small">{c.deliveries.length} deliver{c.deliveries.length === 1 ? 'y' : 'ies'}</summary>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Delivery</th><th>Status</th><th>Latency</th><th>Response</th></tr></thead>
              <tbody>
                {c.deliveries.map((d, i) => (
                  <tr key={i}>
                    <td><div>{d.label}</div><code className="muted small">{d.eventId}</code></td>
                    <td><span className={`badge ${d.status === null ? 'bad' : d.status < 300 ? 'good' : d.status < 500 ? 'warn' : 'bad'}`}>{d.status ?? 'ERR'}</span></td>
                    <td className="mono">{d.ms} ms</td>
                    <td><code className="snippet">{d.error ?? (d.body || '(empty)')}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </div>
  )
}

function LedgerTable({ demo }: { demo: NonNullable<RunResponse['demo']> }) {
  const { actual, expected } = demo
  const rows: [string, (l: Ledger) => string | number][] = [
    [`Subscription ${demo.subA.slice(0, 12)}… status`, (l) => l.subscriptions[demo.subA] ?? '—'],
    [`Subscription ${demo.subB.slice(0, 12)}… status (reordered)`, (l) => l.subscriptions[demo.subB] ?? '—'],
    ['Invoice payments recorded', (l) => l.paidInvoices],
    ['Failed payments recorded', (l) => l.failedPayments],
  ]
  return (
    <div className="panel">
      <h2>What the endpoint's database ended up with</h2>
      <p className="muted small">2xx responses are not enough. This is the state the demo endpoint recorded, compared with applying each authentic event exactly once in true order.</p>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Record</th><th>This endpoint</th><th>Correct</th></tr></thead>
          <tbody>
            {rows.map(([label, get]) => {
              const a = get(actual)
              const e = get(expected)
              return (
                <tr key={label}>
                  <td>{label}</td>
                  <td><span className={`badge ${a === e ? 'good' : 'bad'}`}>{a}</span></td>
                  <td className="mono">{e}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------- fixes

const FRAMEWORKS: { id: string; label: string; code: string }[] = [
  {
    id: 'express', label: 'Express', code: `// Register the webhook route BEFORE app.use(express.json()),
// or express.json() consumes and re-encodes the body.
app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  let event
  try {
    // req.body is a Buffer of the exact bytes Stripe sent
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET)
  } catch (err) {
    return res.status(400).send(\`Webhook Error: \${err.message}\`)
  }
  await queue.add(event)          // fast, durable hand-off
  res.json({ received: true })    // acknowledge quickly
})`,
  },
  {
    id: 'next', label: 'Next.js (App Router)', code: `// app/api/webhooks/stripe/route.ts
export async function POST(req: Request) {
  const body = await req.text() // raw string. Never req.json() before verifying
  const sig = req.headers.get('stripe-signature') ?? ''
  let event: Stripe.Event
  try {
    event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!)
  } catch (err) {
    return new Response(\`Webhook Error: \${(err as Error).message}\`, { status: 400 })
  }
  await queue.add(event)
  return Response.json({ received: true })
}`,
  },
  {
    id: 'hono', label: 'Hono', code: `app.post('/webhooks/stripe', async (c) => {
  const body = await c.req.text()
  const sig = c.req.header('stripe-signature') ?? ''
  let event: Stripe.Event
  try {
    // Async + SubtleCrypto works on Node, Workers, Bun and Deno
    event = await stripe.webhooks.constructEventAsync(body, sig, c.env.STRIPE_WEBHOOK_SECRET,
      undefined, Stripe.createSubtleCryptoProvider())
  } catch (err) {
    return c.text(\`Webhook Error: \${(err as Error).message}\`, 400)
  }
  await queue.add(event)
  return c.json({ received: true })
})`,
  },
  {
    id: 'fastify', label: 'Fastify', code: `// Encapsulated plugin: only this route gets the raw-buffer parser
fastify.register(async (app) => {
  app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (_req, body, done) => done(null, body))
  app.post('/webhooks/stripe', async (req, reply) => {
    let event
    try {
      event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET)
    } catch (err) {
      return reply.code(400).send(\`Webhook Error: \${err.message}\`)
    }
    await queue.add(event)
    return { received: true }
  })
})`,
  },
  {
    id: 'flask', label: 'Flask', code: `@app.post("/webhooks/stripe")
def stripe_webhook():
    payload = request.get_data()  # raw bytes. Not request.json
    sig = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, os.environ["STRIPE_WEBHOOK_SECRET"])
    except (ValueError, stripe.SignatureVerificationError):
        return "", 400
    enqueue(event)
    return {"received": True}`,
  },
  {
    id: 'django', label: 'Django', code: `@csrf_exempt
@require_POST
def stripe_webhook(request):
    try:
        event = stripe.Webhook.construct_event(
            request.body,  # raw bytes
            request.headers.get("Stripe-Signature", ""),
            settings.STRIPE_WEBHOOK_SECRET,
        )
    except (ValueError, stripe.SignatureVerificationError):
        return HttpResponse(status=400)
    enqueue(event)
    return HttpResponse(status=200)`,
  },
]

const IDEMPOTENCY = `-- Deduplicate on event.id before any side effect (inside the same transaction)
CREATE TABLE stripe_events (id text PRIMARY KEY, processed_at timestamptz DEFAULT now());

INSERT INTO stripe_events (id) VALUES ($1) ON CONFLICT DO NOTHING;
-- 0 rows inserted → already processed: return 200 and stop.`

const ORDERING = `// Never trust delivery order. Treat the event as a signal and read current state:
const sub = await stripe.subscriptions.retrieve(event.data.object.id)
await db.subscriptions.upsert({ id: sub.id, status: sub.status })
// Or, at minimum, never move a canceled subscription back to active.`

const ADVICE: Partial<Record<CheckId, string>> = {
  baseline: 'Verify the raw request bytes. See your framework below.',
  duplicate: 'Store processed event ids and skip repeats (snippet below).',
  out_of_order: 'Re-fetch the object or guard state transitions (snippet below).',
  bad_signature: 'Always call constructEvent and return 400 when it throws.',
  stale_timestamp: 'Use the official library defaults (300s tolerance); never pass tolerance 0.',
  tampered_body: 'Verify the exact bytes you then parse, not a re-encoded copy.',
  missing_header: 'Treat a missing Stripe-Signature as a verification failure (400).',
  latency: 'Enqueue the event and return 2xx; do emails and API calls in a worker.',
}

function Fixes({ failed }: { failed: CheckId[] }) {
  const [fw, setFw] = useState(FRAMEWORKS[0].id)
  const code = FRAMEWORKS.find((f) => f.id === fw)!.code
  return (
    <div className="panel">
      <h2>How to fix</h2>
      {failed.length > 0 ? (
        <ul className="advice">
          {failed.map((id) => <li key={id}><strong>{CHECKS.find((c) => c.id === id)!.title}:</strong> {ADVICE[id]}</li>)}
        </ul>
      ) : (
        <p className="muted">Everything passed. Reference implementations below for your team.</p>
      )}
      <div className="tabs scroll" role="tablist">
        {FRAMEWORKS.map((f) => (
          <button key={f.id} role="tab" aria-selected={fw === f.id} onClick={() => setFw(f.id)}>{f.label}</button>
        ))}
      </div>
      <Code code={code} />
      <div className="grid cols-2">
        <div><h3>Idempotency</h3><Code code={IDEMPOTENCY} /></div>
        <div><h3>Ordering</h3><Code code={ORDERING} /></div>
      </div>
    </div>
  )
}

export function Code({ code }: { code: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="code">
      <button className="btn ghost copy" onClick={() => navigator.clipboard.writeText(code).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) })}>
        {copied ? 'Copied' : 'Copy'}
      </button>
      <pre><code>{code}</code></pre>
    </div>
  )
}
