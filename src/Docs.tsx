import { Shell } from './Shell.tsx'
import { BackToHome, go } from './router.tsx'
import { CHECKS, SLOW_MS } from '../api/_lib/chaos.ts'
import { API_VERSION, DEFAULT_TOLERANCE } from '../api/_lib/stripe.ts'

const SOURCES: { what: string; href: string; label: string }[] = [
  { what: 'Signature scheme, header entries (t, v1, v0, secret, destination, payload), 5 minute tolerance, retries, ordering, duplicates, secret rolling', href: 'https://docs.stripe.com/webhooks', label: 'docs.stripe.com/webhooks' },
  { what: `Event and object fields, required lists and enums; API version ${API_VERSION}`, href: 'https://github.com/stripe/openapi/blob/master/openapi/spec3.json', label: 'stripe/openapi spec3.json (MIT)' },
  { what: 'Header parsing rules, error messages, and how the secret= and payload= entries are compared', href: 'https://github.com/stripe/stripe-node/blob/master/src/Webhooks.ts', label: 'stripe-node Webhooks.ts (MIT)' },
  { what: 'HMAC-SHA256 reference vectors used in the tests', href: 'https://www.rfc-editor.org/rfc/rfc4231', label: 'RFC 4231' },
]

export default function Docs() {
  return (
    <Shell name="Webhook Chaos" tagline="Stripe webhook reliability tester" icon="bolt">
      <BackToHome />
      <section className="hero">
        <h1>How it works</h1>
        <p>
          What each check sends, how a run is graded, what the signature debugger looks for, and where the reference
          data comes from. Everything here was checked against the sources at the bottom on 16 November 2026.
        </p>
        <div className="row" style={{ marginTop: 16 }}>
          <button className="btn" onClick={() => go('/app')}>Open the tool</button>
        </div>
      </section>

      <section className="panel">
        <h2>The checks</h2>
        <p className="muted small">
          One run builds a single customer with two subscriptions and sends at most 15 deliveries, one at a time. Every
          event has <code>livemode: false</code>, API version <code>{API_VERSION}</code>, and ids that exist in no
          Stripe account. Bodies are 2-space indented JSON with <code>id</code> and <code>object</code> first and the
          other keys in alphabetical order, as Stripe sends them.
        </p>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Check</th><th>Passes when</th><th>What is sent and why</th></tr></thead>
            <tbody>
              {CHECKS.map((c) => (
                <tr key={c.id}><td><strong>{c.title}</strong></td><td>{c.expect}</td><td>{c.why}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <h2>Scoring</h2>
        <p>
          Each selected check is worth the same: a pass counts 1, a warning 0.5, a failure 0. The score is the total
          divided by the number of graded checks, times 100, rounded. A warning means the outcome was right but the
          manner was not: a verification failure answered with 5xx instead of 400, or a response
          of {SLOW_MS / 1000} seconds or more.
        </p>
        <p>
          The {SLOW_MS / 1000} second line is this tool's own threshold. Stripe does not publish a number; it asks for a
          2xx "before any complex logic that could cause a timeout". Deliveries from this site are cut off after 10
          seconds, and a run stops early after three unreachable deliveries in a row.
        </p>
        <p>
          For the demo handlers the tool can also read the handler's records, so duplicates and ordering are graded on
          what was stored, not on status codes. For your own endpoint it cannot see your database: a 2xx passes, and
          the summary tells you what to confirm by hand.
        </p>
      </section>

      <section className="panel">
        <h2>The signature</h2>
        <p>
          Stripe signs <code>{'<t>.<raw body>'}</code> with HMAC-SHA256, using the endpoint's signing secret (the whole
          string, including <code>whsec_</code>) as the key, and sends the hex digest as a <code>v1</code> entry in
          the <code>Stripe-Signature</code> header. A sandbox header looks like this, on one line:
        </p>
        <div className="code"><pre><code>{`t=1798765432,
v1=5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd,
v0=6ffbb59b2300aae63f272406069a9788598b792a944a07aba816edb039989a39,
secret=whsec_****************************PzVt,
destination=we_1TN7mG6oEAX7HoXLZoZugElv,
payload=a25aefc6`}</code></pre></div>
        <ul className="advice">
          <li><strong>t</strong> is when Stripe signed, not when the event happened. Official libraries reject a signature older than {DEFAULT_TOLERANCE} seconds; a tolerance of 0 turns that check off.</li>
          <li><strong>v1</strong> can appear more than once. While a secret is being rolled (the old one can stay active for up to 7 days) there is one per active secret, and any match is enough.</li>
          <li><strong>v0</strong> is a fake scheme added to sandbox events. Ignore it.</li>
          <li><strong>secret, destination, payload</strong> are optional debugging entries: a masked copy of the newest secret, the endpoint id, and the last 8 hex digits of the SHA-256 of the signed body. Handlers must tolerate entries they do not know.</li>
        </ul>
        <p>Chaos deliveries carry all of these entries, so a handler that splits the header by position or count is caught by the first check.</p>
      </section>

      <section className="panel">
        <h2>The signature debugger</h2>
        <p>
          Runs in your browser with WebCrypto. The body, header and secrets you paste are not sent anywhere. It
          recomputes the signature and, when it does not match, tries to say why:
        </p>
        <ul className="advice">
          <li>If the header has a <code>payload=</code> entry, the body's SHA-256 is compared with it. That settles whether the bytes changed or the secret is wrong.</li>
          <li>If the header has a <code>secret=</code> entry, each secret you paste is compared with the mask by length and last four characters.</li>
          <li>The body is re-tested after undoing common changes: a trailing newline added or removed, CRLF line endings, surrounding whitespace, a byte order mark, parsing and re-serializing (compact, or with keys sorted). When the body's formatting matches a known serializer (JSON.stringify, Python json.dumps, PHP json_encode, Go encoding/json) the finding names it.</li>
          <li>Secrets are checked for the wrong kind of key (<code>sk_</code>, <code>rk_</code>, <code>pk_</code>, <code>we_</code>) and stray whitespace.</li>
          <li>The timestamp is compared with your clock.</li>
        </ul>
        <p className="muted small">
          Limits: pretty-printing in the browser reproduces Stripe's bytes for integers and strings, which covers
          almost every event, but a number such as <code>25.0</code> comes back as <code>25</code>, so a re-serialized
          body containing one is reported as an unexplained mismatch.
        </p>
      </section>

      <section className="panel">
        <h2>Endpoints this site cannot reach</h2>
        <p>
          Chaos runs against your own endpoint are sent from a server function, which only connects to public HTTPS
          addresses on port 443 or 8443, never follows redirects, and refuses private, loopback and link-local
          ranges. Your secret is used to sign that run and is not stored or logged.
        </p>
        <p>
          For localhost, a VPN or a firewalled staging host, choose "Your endpoint" and download the script. It holds
          the same 15 deliveries and signs them on your machine with <code>openssl</code>, reading the secret
          from <code>STRIPE_WEBHOOK_SECRET</code>:
        </p>
        <div className="code"><pre><code>STRIPE_WEBHOOK_SECRET=whsec_... bash webhook-chaos.sh http://localhost:3000/webhooks/stripe</code></pre></div>
        <p className="muted small">It prints one line per delivery, then lists the invoice and subscription ids to look up in your own database.</p>
      </section>

      <section className="panel">
        <h2>What a run does not cover</h2>
        <ul className="advice">
          <li>Only snapshot events for subscriptions, invoices and customers. No thin events, Connect events or other object types.</li>
          <li>If your handler fetches each object from the Stripe API, those calls fail here because the ids are synthetic; the baseline check says so.</li>
          <li>Retries are not simulated on a clock. Stripe retries live deliveries for up to three days with exponential backoff, and sandbox deliveries three times over a few hours.</li>
          <li>The rate limit on runs is per server instance, and nothing is kept between runs: no history, no accounts.</li>
        </ul>
      </section>

      <section className="panel">
        <h2>Sources</h2>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Used for</th><th>Source</th></tr></thead>
            <tbody>
              {SOURCES.map((s) => (
                <tr key={s.href}><td>{s.what}</td><td><a href={s.href} target="_blank" rel="noreferrer">{s.label}</a></td></tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="muted small">All retrieved 16 November 2026. The events themselves are synthetic.</p>
      </section>
    </Shell>
  )
}
