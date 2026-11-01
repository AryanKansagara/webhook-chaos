// Outbound request safety (SSRF): https only, public IPs only (checked again at connect time), no redirects.
import { lookup, type LookupAddress } from 'node:dns'
import { request } from 'node:https'
import { BlockList, isIP } from 'node:net'
import type { Outgoing, Reply } from './chaos.ts'

export const TIMEOUT_MS = 10_000
export const BODY_CAP = 2048

const blocked = new BlockList()
for (const [net, bits] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
] as const) blocked.addSubnet(net, bits, 'ipv4')
// IPv4-mapped (::ffff:a.b.c.d) addresses are matched against the IPv4 rules above by BlockList itself.
for (const [net, bits] of [
  ['::1', 128], ['::', 96] /* unspecified + IPv4-compatible */, ['64:ff9b::', 96], ['64:ff9b:1::', 48] /* NAT64 */,
  ['100::', 64], ['2001::', 32] /* Teredo */, ['2001:db8::', 32], ['2002::', 16] /* 6to4 */,
  ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8],
] as const) blocked.addSubnet(net, bits, 'ipv6')

export function isBlockedIp(ip: string): boolean {
  const family = isIP(ip)
  return family === 0 || blocked.check(ip, family === 4 ? 'ipv4' : 'ipv6')
}

function resolveAll(host: string): Promise<LookupAddress[]> {
  return new Promise((resolve, reject) => lookup(host, { all: true }, (err, addrs) => (err ? reject(err) : resolve(addrs))))
}

/** Validates a user-supplied endpoint URL. Throws an Error with a user-facing message. */
export async function checkTargetUrl(raw: string, resolve = resolveAll): Promise<URL> {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new Error('Enter a full URL, e.g. https://example.com/webhooks/stripe')
  }
  if (url.protocol !== 'https:') throw new Error('Only https:// endpoints are allowed (Stripe requires HTTPS too).')
  if (url.username || url.password) throw new Error('URLs with credentials are not allowed.')
  if (url.port && url.port !== '8443') throw new Error('Only the default HTTPS port (443) or 8443 is allowed.')
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (host === 'localhost' || /\.(localhost|local|internal|home\.arpa)$/.test(host) || !host.includes('.') && !isIP(host))
    throw new Error('That host is not publicly reachable. Use a public URL (for local servers, a tunnel such as ngrok).')
  const addrs = isIP(host) ? [{ address: host }] : await resolve(host).catch(() => [])
  if (!addrs.length) throw new Error(`Could not resolve ${host}.`)
  if (addrs.some((a) => isBlockedIp(a.address))) throw new Error(`${host} resolves to a private or reserved address; refusing to connect.`)
  return url
}

// Re-checked at connect time so a DNS answer that changes after validation (rebinding) is still refused.
// (IP-literal hosts skip lookup entirely; checkTargetUrl already vetted those.)
const safeLookup = ((hostname: string, options: { all?: boolean }, cb: (...args: unknown[]) => void) => {
  resolveAll(hostname).then(
    (addrs) => {
      if (!addrs.length || addrs.some((a) => isBlockedIp(a.address))) return cb(new Error('Refused: resolves to a private address'))
      return options.all ? cb(null, addrs) : cb(null, addrs[0].address, addrs[0].family)
    },
    (err) => cb(err),
  )
}) as unknown as typeof lookup

export const clean = (s: string) => s.replace(/[^\P{C}\n\t]/gu, '').slice(0, BODY_CAP)

/** POST once. No redirects (node:https never follows them), capped body read, hard timeout. */
export function postWebhook(url: URL, req: Outgoing, timeoutMs = TIMEOUT_MS): Promise<Reply> {
  return new Promise((resolve) => {
    const start = performance.now()
    let settled = false
    const done = (r: Omit<Reply, 'ms'>) => {
      if (settled) return
      settled = true
      resolve({ ...r, ms: Math.round(performance.now() - start) })
    }
    const r = request(
      url,
      {
        method: 'POST',
        headers: { ...req.headers, 'content-length': Buffer.byteLength(req.body) },
        lookup: safeLookup,
        signal: AbortSignal.timeout(timeoutMs),
        agent: false,
      },
      (res) => {
        const chunks: Buffer[] = []
        let size = 0
        const finish = () => done({ status: res.statusCode ?? null, body: clean(Buffer.concat(chunks).toString('utf8')) })
        res.on('data', (c: Buffer) => {
          chunks.push(c)
          size += c.length
          if (size >= BODY_CAP) {
            finish()
            res.destroy()
          }
        })
        res.on('end', finish)
        res.on('error', finish)
      },
    )
    r.on('error', (e) =>
      done({ status: null, body: '', error: e.name === 'AbortError' || e.name === 'TimeoutError' ? `Timed out after ${timeoutMs / 1000}s` : e.message }),
    )
    r.end(req.body)
  })
}
