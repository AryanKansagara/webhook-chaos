// Signature debugger logic. Runs in the browser (WebCrypto); nothing leaves the page.
import { computeSignature, DEFAULT_TOLERANCE, parseSignatureHeader, safeEqual, type ParsedHeader } from '../api/_lib/stripe.ts'

export type Level = 'good' | 'warn' | 'bad' | 'info'
export interface Finding { level: Level; title: string; detail: string }
export interface Diagnosis { parsed: ParsedHeader; expected: string | null; match: boolean; findings: Finding[] }

const fmt = (s: number) => (Math.abs(s) < 120 ? `${s}s` : Math.abs(s) < 7200 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`)

/** Body transformations frameworks commonly apply, with the diagnosis each one implies. */
function variants(body: string): { body: string; title: string; detail: string }[] {
  const out = [
    { body: body.replace(/\r?\n$/, ''), title: 'Signature matches without the trailing newline', detail: 'Something appended a newline to the body you pasted or verified (copy/paste, a logger, or an editor). Verify the exact bytes received.' },
    { body: body + '\n', title: 'Signature matches with a trailing newline added', detail: 'A trailing newline was stripped from the raw body. Verify the exact bytes received.' },
    { body: body.replace(/\r\n/g, '\n'), title: 'Signature matches after converting CRLF to LF', detail: 'Line endings were changed to CRLF somewhere between the request and your verification code.' },
    { body: body.trim(), title: 'Signature matches after trimming whitespace', detail: 'Leading/trailing whitespace was added to the body before verification.' },
  ]
  try {
    const parsed = JSON.parse(body)
    out.push(
      { body: JSON.stringify(parsed, null, 2), title: 'Signature matches the pretty-printed JSON, not this body', detail: 'Stripe sends 2-space indented JSON. The body you have was parsed and re-serialized (e.g. express.json() then JSON.stringify(req.body)). Verify the raw request bytes instead.' },
      { body: JSON.stringify(parsed), title: 'Signature matches compact JSON, not this body', detail: 'The body was parsed and re-formatted after it arrived. Verify the raw request bytes instead.' },
    )
  } catch { /* not JSON: only whitespace variants apply */ }
  return out.filter((v) => v.body !== body)
}

export async function diagnose(input: { body: string; header: string; secrets: string; now: number; tolerance?: number }): Promise<Diagnosis> {
  const tolerance = input.tolerance ?? DEFAULT_TOLERANCE
  const findings: Finding[] = []
  let header = input.header.trim()
  if (/^stripe-signature\s*:/i.test(header)) {
    header = header.replace(/^stripe-signature\s*:\s*/i, '')
    findings.push({ level: 'info', title: 'Removed the "Stripe-Signature:" prefix', detail: 'Only the header value is used for verification.' })
  }
  const parsed = parseSignatureHeader(header)
  const secrets = input.secrets.split('\n').filter((s) => s.trim())
  const result = (expected: string | null, match: boolean) => ({ parsed, expected, match, findings })

  if (!header) return findings.push({ level: 'bad', title: 'No Stripe-Signature header', detail: 'Paste the value of the Stripe-Signature request header. If your server never received one, the request did not come from Stripe (or a proxy stripped it).' }), result(null, false)
  if (parsed.t === null) findings.push({ level: 'bad', title: 'No timestamp (t=) in header', detail: 'A Stripe-Signature header looks like t=1700000000,v1=5257a8…' })
  if (!parsed.v1.length)
    findings.push({ level: 'bad', title: 'No v1 signature in header', detail: parsed.v0.length ? 'Only v0 is present. v0 is a fake scheme Stripe adds to test events; only v1 is valid.' : 'Expected one or more v1=<hex> entries.' })
  if (parsed.v1.length > 1)
    findings.push({ level: 'info', title: `${parsed.v1.length} v1 signatures`, detail: 'The endpoint secret is being rolled: Stripe signs with every active secret. Accept the event if any v1 matches.' })
  if (/,\s/.test(header) || /\s=|=\s/.test(header))
    findings.push({ level: 'warn', title: 'Whitespace inside the header', detail: 'stripe-node does not trim header items, so ", v1=" fails to match. Pass the header value through untouched.' })
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

  if (!match) {
    let explained = false
    outer: for (const v of variants(input.body))
      for (const s of secrets)
        if (await matches(v.body, s.trim())) {
          findings.push({ level: 'bad', title: v.title, detail: v.detail })
          explained = true
          break outer
        }
    if (!explained && !findings.some((f) => f.title.startsWith('Matches only')))
      findings.push({ level: 'bad', title: 'Signature does not match', detail: 'No common body transformation explains it, so the secret is the likely culprit. Each endpoint has its own secret; test and live mode secrets differ; and `stripe listen` prints a different secret (valid only for CLI-forwarded events) than the Dashboard endpoint. Also check you are verifying the event you think you are.' })
  }

  const age = input.now - t
  if (age > tolerance)
    findings.push({ level: match ? 'bad' : 'warn', title: `Timestamp is ${fmt(age)} old (tolerance ${tolerance}s)`, detail: 'Verification fails even with a valid signature. Expected when replaying a captured request; in production this points to clock drift (use NTP) or a queue that verifies late. Verify on receipt.' })
  else if (age < -tolerance) findings.push({ level: 'warn', title: `Timestamp is ${fmt(-age)} in the future`, detail: 'Your clock is behind. stripe-node only rejects old timestamps, but other libraries may reject future ones. Sync with NTP.' })
  else findings.push({ level: 'good', title: `Timestamp within tolerance (${fmt(age)} ago)`, detail: `Default tolerance is ${DEFAULT_TOLERANCE}s.` })

  return result(expected, match && age <= tolerance)
}
