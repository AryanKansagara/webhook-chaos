// Reads the reply to POST /api/run. A report is only returned when it has the shape the page renders; anything else,
// whatever the HTTP status, becomes an error message, so an unexpected reply can never reach the results view.
import { CHECK_IDS, type RunResponse } from '../api/_lib/chaos.ts'

const VERDICTS = ['pass', 'warn', 'fail', 'skip']
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)
const isNumber = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v)
const isString = (v: unknown): v is string => typeof v === 'string'

const isDelivery = (d: unknown) =>
  isObject(d) && isString(d.label) && isString(d.eventId) && isString(d.body) && isNumber(d.ms) && (d.status === null || isNumber(d.status))
const isCheck = (c: unknown) =>
  isObject(c) && CHECK_IDS.includes(c.id as never) && isString(c.title) && isString(c.summary) && VERDICTS.includes(c.verdict as string) &&
  Array.isArray(c.deliveries) && c.deliveries.every(isDelivery)
const isLedger = (l: unknown) => isObject(l) && isObject(l.subscriptions) && isNumber(l.paidInvoices) && isNumber(l.failedPayments)
const isDemo = (d: unknown) => isObject(d) && isString(d.subA) && isString(d.subB) && isLedger(d.actual) && isLedger(d.expected)

export function isRunResponse(v: unknown): v is RunResponse {
  return isObject(v) && isString(v.target) && isNumber(v.score) && Array.isArray(v.checks) && v.checks.every(isCheck) && (v.demo === undefined || isDemo(v.demo))
}

/** `json` is the parsed body, or `undefined` when the body was not JSON. Throws an Error whose message is shown to the user. */
export function readRunReply(res: { ok: boolean; status: number }, json: unknown): RunResponse {
  const message = isObject(json) && isString(json.error) && json.error ? json.error : null
  if (!res.ok) throw new Error(message ?? (json === undefined ? `Unexpected response (HTTP ${res.status}).` : `HTTP ${res.status}`))
  if (isRunResponse(json)) return json
  throw new Error(message ?? `Unexpected response (HTTP ${res.status}).`)
}
