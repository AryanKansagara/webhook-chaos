import { useState } from 'react'
import { Shell } from './Shell.tsx'
import { BackToHome } from './router.tsx'
import { ChaosTab } from './ChaosTab.tsx'
import { diagnose, type Diagnosis } from './diagnose.ts'
import { go } from './router.tsx'
import { buildScenario, randomSecret, serialize, signatureHeader } from '../api/_lib/stripe.ts'

type Tab = 'chaos' | 'debugger'

export default function Tool() {
  const [tab, setTab] = useState<Tab>('chaos')
  const [autorun, setAutorun] = useState(0)

  return (
    <Shell name="Webhook Chaos" tagline="Stripe webhook reliability tester" icon="bolt">
      <BackToHome />
      <section className="hero">
        <h1>Find out if your Stripe webhook will survive production</h1>
        <p>
          Chaos tests fire signed, duplicated, reordered, forged, and stale events at a demo endpoint or your own HTTPS
          URL and score how the handler responds. The signature debugger runs entirely in your browser when a verify
          call fails and you need to know whether the body, header, or secret is wrong.
        </p>
        <div className="row" style={{ marginTop: 16 }}>
          <button
            className="btn"
            onClick={() => {
              setTab('chaos')
              setAutorun((n) => n + 1)
            }}
          >
            Run naive demo
          </button>
          <button className="btn ghost" onClick={() => setTab('debugger')}>
            Open signature debugger
          </button>
          <button className="btn ghost" onClick={() => go('/docs')}>
            How it works
          </button>
        </div>
      </section>

      <div className="tabs" role="tablist" aria-label="Tools">
        <button role="tab" aria-selected={tab === 'chaos'} onClick={() => setTab('chaos')}>
          Chaos tests
        </button>
        <button role="tab" aria-selected={tab === 'debugger'} onClick={() => setTab('debugger')}>
          Signature debugger
        </button>
      </div>

      {tab === 'chaos' ? <ChaosTab autorun={autorun} /> : <DebuggerTab />}
    </Shell>
  )
}

type Example = 'valid' | 'reparsed' | 'secret' | 'env' | 'stale'
const EXAMPLES: [Example, string][] = [
  ['valid', 'Valid'],
  ['reparsed', 'Re-serialized body'],
  ['secret', 'Wrong secret'],
  ['env', 'Secret with a stray space'],
  ['stale', 'Replayed an hour later'],
]

function DebuggerTab() {
  const [body, setBody] = useState('')
  const [header, setHeader] = useState('')
  const [secrets, setSecrets] = useState('')
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<Diagnosis | null>(null)

  async function run(input = { body, header, secrets }) {
    setRunning(true)
    try {
      setResult(await diagnose({ ...input, now: Math.floor(Date.now() / 1000) }))
    } finally {
      setRunning(false)
    }
  }

  // Fills the form with a freshly signed synthetic event, broken in one specific way.
  async function example(kind: Example) {
    const now = Math.floor(Date.now() / 1000)
    const secret = randomSecret()
    const raw = serialize(buildScenario(now).lifecycle[1])
    const input = {
      body: kind === 'reparsed' ? JSON.stringify(JSON.parse(raw)) : raw,
      header: await signatureHeader(raw, [secret], kind === 'stale' ? now - 3600 : now),
      secrets: kind === 'secret' ? randomSecret() : kind === 'env' ? `${secret} ` : secret,
    }
    setBody(input.body)
    setHeader(input.header)
    setSecrets(input.secrets)
    await run(input)
  }

  return (
    <section className="panel">
      <h2>Signature debugger</h2>
      <p className="muted small" style={{ marginTop: 0 }}>
        Paste the raw request body, the <code>Stripe-Signature</code> header, and your endpoint signing secret(s).
        Diagnosis uses WebCrypto in this tab — nothing is sent to the server.
      </p>

      <div className="row" style={{ marginBottom: 16 }}>
        <span className="muted small">Try an example:</span>
        {EXAMPLES.map(([kind, label]) => (
          <button key={kind} className="btn ghost" disabled={running} onClick={() => void example(kind)}>{label}</button>
        ))}
      </div>

      <div className="grid cols-2">
        <label className="field" style={{ marginTop: 0 }}>
          <span>Raw body</span>
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            spellCheck={false}
            placeholder={'{\n  "id": "evt_…",\n  …\n}'}
            aria-label="Raw webhook body"
          />
        </label>
        <div className="stack">
          <label className="field" style={{ marginTop: 0 }}>
            <span>Stripe-Signature header</span>
            <input
              value={header}
              onChange={(e) => setHeader(e.target.value)}
              spellCheck={false}
              autoComplete="off"
              placeholder="t=1700000000,v1=5257a8…"
              aria-label="Stripe-Signature header"
            />
          </label>
          <label className="field">
            <span>Signing secret(s)</span>
            <textarea
              value={secrets}
              onChange={(e) => setSecrets(e.target.value)}
              spellCheck={false}
              autoComplete="off"
              placeholder={'whsec_…\n(one per line while rotating)'}
              style={{ minHeight: 120 }}
              aria-label="Signing secrets"
            />
          </label>
        </div>
      </div>

      <div className="row run-row">
        <button className="btn" disabled={running || (!body && !header)} onClick={() => void run()}>
          {running ? 'Diagnosing…' : 'Diagnose'}
        </button>
        {result && (
          <span className={`badge ${result.match ? 'good' : 'bad'}`}>
            {result.match ? 'Would verify' : 'Would reject'}
          </span>
        )}
      </div>

      {result && (
        <div aria-live="polite">
          {result.expected && (
            <p className="muted small mono">
              Expected v1 (secret #1): <code className="snippet">{result.expected}</code>
            </p>
          )}
          <p className="muted small mono">
            {result.parsed.t != null && <>t={result.parsed.t} ({new Date(result.parsed.t * 1000).toISOString().replace('.000', '')}) · </>}
            {result.parsed.v1.length} v1 · {new TextEncoder().encode(body).length} body bytes · SHA-256 ends in {result.bodyHash}
            {result.parsed.meta.destination && <> · destination {result.parsed.meta.destination}</>}
          </p>
          {result.findings.map((f, i) => (
            <div key={i} className={`finding ${f.level}`}>
              <div className="row">
                <span className={`badge ${f.level === 'info' ? 'info' : f.level}`}>{f.level}</span>
                <strong>{f.title}</strong>
              </div>
              <p className="summary" style={{ margin: '6px 0 0' }}>{f.detail}</p>
            </div>
          ))}
        </div>
      )}
    </section>
  )
}
