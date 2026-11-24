// Signature debugger logic. Runs in the browser (WebCrypto); nothing leaves the page.
import { computeSignature, DEFAULT_TOLERANCE, parseSignatureHeader, payloadHashTail, safeEqual, type ParsedHeader } from '../api/_lib/stripe.ts'

export type Level = 'good' | 'warn' | 'bad' | 'info'
export interface Finding { level: Level; title: string; detail: string }
export interface Diagnosis { parsed: ParsedHeader; expected: string | null; match: boolean; findings: Finding[]; bodyHash: string }

const fmt = (s: number) => (Math.abs(s) < 120 ? `${s}s` : Math.abs(s) < 7200 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`)

// How other runtimes write the same JSON value. Each helper rewrites compact JSON.stringify output;
// the first alternative of the regex consumes whole string literals so only structure is touched.
const STRING = /"(?:[^"\\]|\\.)*"/.source
const spaced = (json: string) => json.replace(new RegExp(`${STRING}|[,:]`, 'g'), (m) => (m === ',' ? ', ' : m === ':' ? ': ' : m))
const escape = (re: RegExp) => (json: string) => json.replace(re, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)
const asciiOnly = escape(/[\u007f-\uffff]/g)
const htmlSafe = escape(/[<>&\u2028\u2029]/g)

/** Stripe writes `id` and `object` first and every other key alphabetically, at every level. */
const rank = (k: string) => (k === 'id' ? 0 : k === 'object' ? 1 : 2)
const reorder = (v: unknown, cmp: (a: string, b: string) => number): unknown =>
  Array.isArray(v) ? v.map((x) => reorder(x, cmp))
  : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort(cmp).map((k) => [k, reorder((v as Record<string, unknown>)[k], cmp)]))
  : v
const byName = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0)
const stripeOrder = (a: string, b: string) => rank(a) - rank(b) || byName(a, b)

const RAW = 'Verify the raw request bytes instead.'

/** Names the serializer that produced `body`, when its output is recognisable. */
export function guessSerializer(body: string): string | null {
  let parsed: unknown
  try {
    parsed = JSON.parse(body)
  } catch {
    return null
  }
  const compact = JSON.stringify(parsed)
  const sorted = JSON.stringify(reorder(parsed, byName))
  const isSorted = compact === sorted
  const php = asciiOnly(compact).replace(/\//g, '\\/')
  if (body === compact && body === htmlSafe(compact) && body === php)
    return 'It is compact JSON, as JSON.stringify(req.body) writes it after express.json() or a similar body parser (Go and PHP produce the same bytes for this payload).'
  if (body === compact) return 'It is compact JSON, as JSON.stringify(req.body) writes it after express.json() or a similar body parser.'
  if (body === spaced(compact) || body === asciiOnly(spaced(compact)))
    return `It is formatted the way Python's json.dumps() writes JSON (", " and ": " separators${isSorted ? ', keys sorted' : ''}). Use request.get_data() in Flask or request.body in Django.`
  if (body === php) return "It is formatted the way PHP's json_encode() writes JSON (escaped slashes). Read php://input or $request->getContent()."
  if (body === htmlSafe(compact))
    return 'It is formatted the way Go encoding/json writes JSON (<, > and & escaped). Read the body once with io.ReadAll and pass those bytes to webhook.ConstructEvent.'
  return null
}

/** Body transformations frameworks commonly apply, with the diagnosis each one implies. */
function variants(body: string): { body: string; title: string; detail: string }[] {
  const out = [
    { body: body.replace(/\r?\n$/, ''), title: 'Signature matches without the trailing newline', detail: 'Something appended a newline to the body you pasted or verified (copy/paste, a logger, or an editor). Verify the exact bytes received.' },
    { body: body + '\n', title: 'Signature matches with a trailing newline added', detail: 'A trailing newline was stripped from the raw body. Verify the exact bytes received.' },
    { body: body.replace(/\r\n/g, '\n'), title: 'Signature matches after converting CRLF to LF', detail: 'Line endings were changed to CRLF somewhere between the request and your verification code.' },
    { body: body.trim(), title: 'Signature matches after trimming whitespace', detail: 'Leading/trailing whitespace was added to the body before verification.' },
  ]
  if (body.charCodeAt(0) === 0xfeff)
    out.unshift({ body: body.slice(1), title: 'Signature matches without the byte order mark', detail: 'The body starts with a UTF-8 BOM that Stripe did not send. A file or editor added it; verify the bytes as received.' })
  try {
    const parsed = JSON.parse(body)
    const hint = guessSerializer(body)
    out.push(
      { body: JSON.stringify(parsed, null, 2), title: 'Signature matches the pretty-printed JSON, not this body', detail: `Stripe sends 2-space indented JSON. The body you have was parsed and re-serialized. ${hint ?? 'A typical cause is express.json() followed by JSON.stringify(req.body).'} ${RAW}` },
      { body: JSON.stringify(reorder(parsed, stripeOrder), null, 2), title: 'Signature matches after restoring Stripe\'s key order and indentation', detail: `The body was parsed and written back with its keys in a different order (a Go map, Python sort_keys=True, jq -S, or a database JSON column all do this). ${hint ?? ''} ${RAW}`.replace(/ {2,}/g, ' ') },
      { body: JSON.stringify(parsed), title: 'Signature matches compact JSON, not this body', detail: `The body was parsed and re-formatted after it arrived. ${RAW}` },
    )
  } catch { /* not JSON: only whitespace variants apply */ }
  const seen = new Set([body])
  return out.filter((v) => !seen.has(v.body) && seen.add(v.body))
}

export async function diagnose(input: { body: string; header: string; secrets: string; now: number; tolerance?: number }): Promise<Diagnosis> {
  const tolerance = input.tolerance ?? DEFAULT_TOLERANCE
  const findings: Finding[] = []
  let header = input.header.trim()
  const bodyHash = await payloadHashTail(input.body)
  if (/^(["'`]).*\1$/.test(header)) header = header.slice(1, -1).trim()
  if (/^stripe-signature\s*:/i.test(header)) {
    header = header.replace(/^stripe-signature\s*:\s*/i, '')
    findings.push({ level: 'info', title: 'Removed the "Stripe-Signature:" prefix', detail: 'Only the header value is used for verification.' })
  }
  const parsed = parseSignatureHeader(header)
  const secrets = input.secrets.split('\n').filter((s) => s.trim())
  const result = (expected: string | null, match: boolean) => ({ parsed, expected, match, findings, bodyHash })

  if (!header) return findings.push({ level: 'bad', title: 'No Stripe-Signature header', detail: 'Paste the value of the Stripe-Signature request header. If your server never received one, the request did not come from Stripe (or a proxy stripped it).' }), result(null, false)
  if (parsed.t === null) findings.push({ level: 'bad', title: 'No timestamp (t=) in header', detail: 'A Stripe-Signature header looks like t=1700000000,v1=5257a8…' })
  if (!parsed.v1.length)
    findings.push({ level: 'bad', title: 'No v1 signature in header', detail: parsed.v0.length ? 'Only v0 is present. v0 is a fake scheme Stripe adds to test events; only v1 is valid.' : 'Expected one or more v1=<hex> entries.' })
  if (parsed.v1.length > 1)
    findings.push({ level: 'info', title: `${parsed.v1.length} v1 signatures`, detail: 'The endpoint secret is being rolled: Stripe signs with every active secret. Accept the event if any v1 matches.' })
  // stripe-node compares header keys and signature values as written (parseHeader in src/Webhooks.ts), so padding
  // around a key or a v1 value makes that entry unreadable. The first branch states what the library would then do.
  const padded = parsed.unknown.filter((k) => ['t', 'v1'].includes(k.trim()))
  const named = padded.map((k) => JSON.stringify(k)).join(', ')
  if (padded.length)
    findings.push({
      level: parsed.t === null || !parsed.v1.length ? 'bad' : 'warn',
      title: 'Whitespace inside the header',
      detail: `stripe-node does not trim header items, so a key written as ${named} is not the key it looks like, and the entry is ignored. ${
        parsed.t === null ? 'No timestamp is read, so constructEvent throws "Unable to extract timestamp and signatures from header".'
        : !parsed.v1.length ? 'No v1 signature is read, so constructEvent throws "No signatures found with expected scheme".'
        : 'The remaining entries are still read.'} A space after a comma usually comes from a reformatted copy of the header; pass the value through untouched.`,
    })
  else if (parsed.v1.some((v) => v !== v.trim()))
    findings.push({ level: 'warn', title: 'Whitespace inside the header', detail: 'stripe-node compares each v1 value exactly as written, so a v1 value with a space or line break around it never matches. Pass the header value through untouched.' })
  if (!secrets.length) return findings.push({ level: 'bad', title: 'No signing secret', detail: 'Paste the endpoint signing secret (whsec_…).' }), result(null, false)

  for (const s of secrets) {
    if (s !== s.trim()) findings.push({ level: 'warn', title: 'Secret has surrounding whitespace', detail: 'Common with .env files and copy/paste. The whitespace becomes part of the HMAC key.' })
    const k = s.trim()
    if (/^(sk|rk|pk)_/.test(k)) findings.push({ level: 'bad', title: `"${k.slice(0, 8)}…" is an API key, not a signing secret`, detail: 'Webhook signatures use the endpoint signing secret (whsec_…), shown on the endpoint page or printed by `stripe listen`.' })
    else if (k.startsWith('we_')) findings.push({ level: 'bad', title: 'That is the endpoint id, not its secret', detail: 'Open the endpoint in the Dashboard and reveal the signing secret (whsec_…).' })
    else if (!k.startsWith('whsec_')) findings.push({ level: 'warn', title: 'Secret does not start with whsec_', detail: 'Stripe signing secrets always start with whsec_.' })
  }
  if (parsed.t === null || !parsed.v1.length) return result(null, false)
  const t = parsed.t
  const sign = (body: string, secret: string) => computeSignature(body, secret, t)
  const matches = async (body: string, secret: string) => {
    const sig = await sign(body, secret)
    return parsed.v1.some((v) => safeEqual(sig, v))
  }

  let match = false
  const expected = await sign(input.body, secrets[0].trim())
  for (const [i, s] of secrets.entries()) {
    if (await matches(input.body, s)) {
      match = true
      findings.push({ level: 'good', title: secrets.length > 1 ? `Signature matches secret #${i + 1}` : 'Signature matches', detail: 'The body, header and secret are consistent.' })
      break
    }
    if (s !== s.trim() && (await matches(input.body, s.trim()))) {
      findings.push({ level: 'bad', title: 'Matches only after trimming the secret', detail: 'Trim the secret when loading it from configuration.' })
      break
    }
  }

  // Stripe's own hints: the header can carry the last 8 hex digits of SHA-256(body) and a masked copy of the secret.
  const { meta } = parsed
  const bodyIntact = meta.payload ? meta.payload === bodyHash : null
  const masked = meta.secret?.includes('*') ? meta.secret : null
  const where = meta.destination ? ` (https://dashboard.stripe.com/webhooks/${encodeURIComponent(meta.destination)})` : ''
  const explainedBySecret = () => findings.some((f) => f.title.startsWith('Matches only') || f.title.startsWith('Wrong signing secret'))
  if (!match && masked) {
    const fits = secrets.map((s) => s.trim()).some((s) => s.length === masked.length && s.slice(-4) === masked.slice(-4))
    if (!fits)
      findings.push({ level: 'bad', title: 'Wrong signing secret for this destination', detail: `The header says the destination's secret is ${masked.length} characters long and looks like ${masked}. None of the secrets you pasted has that length and ending. Copy the secret from this destination's page in the Dashboard${where}.` })
  }
  if (!match && bodyIntact === true)
    findings.push({ level: 'info', title: 'Body is byte-for-byte what Stripe signed', detail: `Its SHA-256 ends in ${bodyHash}, the same as the header's payload= entry. The body is not the problem, so the secret is: each endpoint has its own, sandbox and live secrets differ, and \`stripe listen\` prints one that only works for CLI-forwarded events.` })
  if (!match && bodyIntact === false)
    findings.push({ level: 'bad', title: 'Body differs from what Stripe signed', detail: `The header's payload= field says the SHA-256 of the signed body ends in ${meta.payload}; this body's ends in ${bodyHash}. Something between Stripe and your verify call changed the bytes.` })

  if (!match) {
    let explained = bodyIntact === true
    if (!explained) outer: for (const v of variants(input.body))
      for (const s of secrets)
        if (await matches(v.body, s.trim())) {
          findings.push({ level: 'bad', title: v.title, detail: v.detail })
          explained = true
          break outer
        }
    if (!explained && bodyIntact === null && !explainedBySecret())
      findings.push({ level: 'bad', title: 'Signature does not match', detail: 'No common body transformation explains it, so the secret is the likely culprit. Each endpoint has its own secret; test and live mode secrets differ; and `stripe listen` prints a different secret (valid only for CLI-forwarded events) than the Dashboard endpoint. Also check you are verifying the event you think you are.' })
  }

  const age = input.now - t
  if (age > tolerance)
    findings.push({ level: match ? 'bad' : 'warn', title: `Timestamp is ${fmt(age)} old (tolerance ${tolerance}s)`, detail: 'Verification fails even with a valid signature. Expected when replaying a captured request; in production this points to clock drift (use NTP) or a queue that verifies late. Verify on receipt.' })
  else if (age < -tolerance) findings.push({ level: 'warn', title: `Timestamp is ${fmt(-age)} in the future`, detail: 'Your clock is behind. stripe-node only rejects old timestamps, but other libraries may reject future ones. Sync with NTP.' })
  else findings.push({ level: 'good', title: `Timestamp within tolerance (${fmt(age)} ago)`, detail: `Default tolerance is ${DEFAULT_TOLERANCE}s.` })

  return result(expected, match && age <= tolerance)
}
