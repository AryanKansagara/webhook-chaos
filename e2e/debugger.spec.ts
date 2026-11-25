import { createHmac } from 'node:crypto'
import type { Page } from '@playwright/test'
import { test, expect, type Api } from './fixtures.ts'

// The signature debugger runs in the page (WebCrypto) and never calls the API.
//
// Stripe publishes the scheme, not a complete signed example: the signed payload is `${t}.${body}`, the signature is
// its HMAC-SHA256 with the endpoint secret as the key, hex encoded, sent as v1= in `t=…,v1=…`
// (https://docs.stripe.com/webhooks, "Verify manually"). The vectors below are therefore signed here with node:crypto
// following that description, independently of the app's own code. The header that the docs print is used as
// published, for the parts a header alone can show (entries and debugging fields).
const DOCS_HEADER =
  't=1798765432,v1=5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd,v1=38c9f77a6fdb86d7f67e427e6076f1e38e244eb8ddc7a90f7f9dd4478d5bb2c2,' +
  'v0=6ffbb59b2300aae63f272406069a9788598b792a944a07aba816edb039989a39,secret=whsec_****************************PzVt,destination=we_1TN7mG6oEAX7HoXLZoZugElv,payload=a25aefc6'

const SECRET = 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw'
const OTHER_SECRET = 'whsec_pVdBXTQ9Tn0gQc2g8mM0Yf9wqz1k4uAs'
// Two-space indented, `id` and `object` first, then alphabetical: the way Stripe writes event bodies.
const BODY = JSON.stringify(
  { id: 'evt_1NG8Du2eZvKYlo2CUI79vXWy', object: 'event', api_version: '2026-09-30.endive', created: 1798765000,
    data: { object: { id: 'in_1NG8Du2eZvKYlo2C', object: 'invoice', amount_paid: 2500 } }, livemode: false, type: 'invoice.paid' },
  null, 2,
)
const sign = (body: string, secret: string, t: number) => createHmac('sha256', secret).update(`${t}.${body}`, 'utf8').digest('hex')
const now = () => Math.floor(Date.now() / 1000)

async function open(page: Page) {
  await page.goto('/app')
  await page.getByRole('tab', { name: 'Signature debugger' }).click()
}
async function paste(page: Page, body: string, header: string, secrets: string) {
  await page.getByLabel('Raw webhook body').fill(body)
  await page.getByLabel('Stripe-Signature header').fill(header)
  await page.getByLabel('Signing secrets').fill(secrets)
  await page.getByRole('button', { name: 'Diagnose' }).click()
}
const verdict = (page: Page) => page.locator('.run-row .badge')
const titles = (page: Page) => page.locator('.finding strong').allTextContents()
const finding = (page: Page, title: string | RegExp) => page.locator('.finding', { has: page.locator('strong', { hasText: title }) })

test.afterEach(({ api }: { api: Api }) => {
  expect(api.calls, 'the debugger must not call the API').toEqual([])
})

test('empty form: nothing to diagnose, no verdict', async ({ page }) => {
  await open(page)
  await expect(page.getByRole('button', { name: 'Diagnose' })).toBeDisabled()
  await expect(verdict(page)).toHaveCount(0)
})

test('a body signed per the documented scheme verifies, and shows the expected signature and header facts', async ({ page }) => {
  await open(page)
  const t = now() - 5
  const v1 = sign(BODY, SECRET, t)
  await paste(page, BODY, `t=${t},v1=${v1}`, SECRET)
  await expect(verdict(page)).toHaveText('Would verify')
  await expect(verdict(page)).toHaveClass(/good/)
  expect(await titles(page)).toEqual(['Signature matches', expect.stringMatching(/^Timestamp within tolerance/)])
  await expect(page.locator('.mono code').first()).toHaveText(v1)
  await expect(page.getByText(/1 v1 · \d+ body bytes/)).toContainText(`t=${t}`)
  await expect(page.getByText(/body bytes/)).toContainText(`${Buffer.byteLength(BODY)} body bytes`)
})

test('the same vector with one character changed is refused, and the tampering is not blamed on the secret', async ({ page }) => {
  await open(page)
  const t = now() - 5
  const header = `t=${t},v1=${sign(BODY, SECRET, t)}`
  const tampered = [
    BODY.replace('2500', '1'),
    BODY.replace('invoice.paid', 'invoice.void'),
    BODY + ' ',
    BODY.replace('evt_1NG8', 'evt_1NG9'),
  ]
  for (const body of tampered) {
    await paste(page, body, header, SECRET)
    await expect(verdict(page)).toHaveText('Would reject')
    await expect(verdict(page)).toHaveClass(/bad/)
    await expect(finding(page, /^Signature matches$/)).toHaveCount(0)
  }
  // A last-digit change in the signature itself.
  const v1 = sign(BODY, SECRET, t)
  const flipped = v1.slice(0, -1) + (v1.endsWith('0') ? '1' : '0')
  await paste(page, BODY, `t=${t},v1=${flipped}`, SECRET)
  await expect(verdict(page)).toHaveText('Would reject')
  // The right header with another endpoint's secret.
  await paste(page, BODY, header, OTHER_SECRET)
  await expect(verdict(page)).toHaveText('Would reject')
  await expect(finding(page, 'Signature does not match')).toBeVisible()
  // And the original is still accepted afterwards: no stale state.
  await paste(page, BODY, header, SECRET)
  await expect(verdict(page)).toHaveText('Would verify')
})

test('a timestamp is part of the signature: moving t invalidates it, and an old one is refused even when signed', async ({ page }) => {
  await open(page)
  const t = now() - 5
  await paste(page, BODY, `t=${t + 1},v1=${sign(BODY, SECRET, t)}`, SECRET)
  await expect(verdict(page)).toHaveText('Would reject')

  const old = now() - 3600
  await paste(page, BODY, `t=${old},v1=${sign(BODY, SECRET, old)}`, SECRET)
  await expect(verdict(page)).toHaveText('Would reject')
  await expect(finding(page, /^Signature matches$/)).toBeVisible()
  await expect(finding(page, /^Timestamp is 60 min old \(tolerance 300s\)/)).toHaveClass(/bad/)
})

test('secret rolling: any one of several v1 values and any one of several secrets is enough', async ({ page }) => {
  await open(page)
  const t = now()
  await paste(page, BODY, `t=${t},v1=${sign(BODY, OTHER_SECRET, t)},v1=${sign(BODY, SECRET, t)}`, SECRET)
  await expect(verdict(page)).toHaveText('Would verify')
  await expect(finding(page, '2 v1 signatures')).toBeVisible()

  await paste(page, BODY, `t=${t},v1=${sign(BODY, SECRET, t)}`, `${OTHER_SECRET}\n${SECRET}`)
  await expect(verdict(page)).toHaveText('Would verify')
  await expect(finding(page, 'Signature matches secret #2')).toBeVisible()
})

test('common mistakes get named: pasted whitespace, API key, re-serialized body', async ({ page }) => {
  await open(page)
  const t = now()
  const header = `t=${t},v1=${sign(BODY, SECRET, t)}`
  await paste(page, BODY, header, `${SECRET} `)
  await expect(verdict(page)).toHaveText('Would reject')
  expect(await titles(page)).toContain('Secret has surrounding whitespace')
  expect(await titles(page)).toContain('Matches only after trimming the secret')

  await paste(page, BODY, header, 'sk_test_51Mabcdefghijklmnop')
  await expect(verdict(page)).toHaveText('Would reject')
  await expect(finding(page, /is an API key, not a signing secret/)).toBeVisible()

  await paste(page, JSON.stringify(JSON.parse(BODY)), header, SECRET)
  await expect(verdict(page)).toHaveText('Would reject')
  await expect(finding(page, 'Signature matches the pretty-printed JSON, not this body')).toBeVisible()
  await expect(finding(page, 'Signature matches the pretty-printed JSON, not this body')).toContainText('2-space indented JSON')
})

test('the header printed in the Stripe docs is read entry by entry, and a body that was not signed with it is refused', async ({ page }) => {
  await open(page)
  await paste(page, '{}', DOCS_HEADER, 'whsec_notTheSecretThatSignedThisHeader000')
  await expect(verdict(page)).toHaveText('Would reject')
  await expect(page.getByText(/2 v1 · 2 body bytes/)).toContainText('t=1798765432 (2027-01-01T01:03:52Z)')
  await expect(page.getByText(/2 v1 · 2 body bytes/)).toContainText('destination we_1TN7mG6oEAX7HoXLZoZugElv')
  // payload=a25aefc6 is the hash tail of the body Stripe signed; "{}" is not it.
  await expect(finding(page, 'Body differs from what Stripe signed')).toContainText('payload= field says')
  await expect(finding(page, 'Body differs from what Stripe signed')).toContainText('a25aefc6')
  // The docs' header is dated after today's clock in some runs and before it in others; either way it is flagged.
  await expect(finding(page, /^Timestamp is .* (old|in the future)/)).toBeVisible()
})

for (const [label, kind] of [
  ['Valid', 'verify'], ['Re-serialized body', 'reject'], ['Wrong secret', 'reject'], ['Secret with a stray space', 'reject'], ['Replayed an hour later', 'reject'],
] as const) {
  test(`example "${label}" fills the form and diagnoses it: would ${kind}`, async ({ page }) => {
    await open(page)
    await page.getByRole('button', { name: label, exact: true }).click()
    await expect(verdict(page)).toHaveText(kind === 'verify' ? 'Would verify' : 'Would reject')
    await expect(page.getByLabel('Raw webhook body')).not.toHaveValue('')
    await expect(page.getByLabel('Stripe-Signature header')).toHaveValue(/^t=\d+,v1=[0-9a-f]{64}/)
    await expect(page.getByLabel('Signing secrets')).toHaveValue(/whsec_/)
  })
}

test('the valid example is a genuine signature: it verifies under the documented scheme outside the app', async ({ page }) => {
  await open(page)
  await page.getByRole('button', { name: 'Valid', exact: true }).click()
  await expect(verdict(page)).toHaveText('Would verify')
  const body = await page.getByLabel('Raw webhook body').inputValue()
  const header = await page.getByLabel('Stripe-Signature header').inputValue()
  const secret = (await page.getByLabel('Signing secrets').inputValue()).trim()
  const t = Number(/t=(\d+)/.exec(header)![1])
  expect(header).toContain(`v1=${sign(body, secret, t)}`)
})

test('odd input never throws and never looks like a success', async ({ page }) => {
  await open(page)
  const t = now()
  const good = sign(BODY, SECRET, t)
  const odd: [string, string, string][] = [
    ['header only, no secret', `t=${t},v1=${good}`, ''],
    ['header with no v1', `t=${t}`, SECRET],
    ['header with only v0', `t=${t},v0=${good}`, SECRET],
    ['no timestamp', `v1=${good}`, SECRET],
    ['non-numeric timestamp', `t=abc,v1=${good}`, SECRET],
    ['empty v1', `t=${t},v1=`, SECRET],
    ['truncated signature', `t=${t},v1=${good.slice(0, 20)}`, SECRET],
    ['uppercase signature', `t=${t},v1=${good.toUpperCase()}`, SECRET],
    ['garbage header', '¯\\_(ツ)_/¯ ,,, ===', SECRET],
    ['whitespace-only secret', `t=${t},v1=${good}`, '   \n  '],
  ]
  for (const [name, header, secrets] of odd) {
    await page.getByLabel('Raw webhook body').fill(BODY)
    await page.getByLabel('Stripe-Signature header').fill(header)
    await page.getByLabel('Signing secrets').fill(secrets)
    await page.getByRole('button', { name: 'Diagnose' }).click()
    await expect(verdict(page), name).toHaveText('Would reject')
    await expect(page.locator('.finding.bad, .finding.warn').first(), name).toBeVisible()
  }
  // A large body and unusual characters are handled.
  await paste(page, 'é'.repeat(200_000), `t=${t},v1=${good}`, SECRET)
  await expect(verdict(page)).toHaveText('Would reject')
  await paste(page, '\u{1F4B8}\u0000 {"not":"json"', `t=${t},v1=${good}`, SECRET)
  await expect(verdict(page)).toHaveText('Would reject')
})

test('a header pasted with its name and quotes is still recognised', async ({ page }) => {
  await open(page)
  const t = now()
  await paste(page, BODY, `Stripe-Signature: t=${t},v1=${sign(BODY, SECRET, t)}`, SECRET)
  await expect(verdict(page)).toHaveText('Would verify')
  await expect(finding(page, 'Removed the "Stripe-Signature:" prefix')).toBeVisible()
  await paste(page, BODY, `"t=${t},v1=${sign(BODY, SECRET, t)}"`, SECRET)
  await expect(verdict(page)).toHaveText('Would verify')
})

// stripe-node splits the header on "," and compares each key as written, so " v1" is not "v1" and a header with a space
// after a comma carries no signature: constructEvent throws "No signatures found with expected scheme"
// (parseHeader in https://github.com/stripe/stripe-node/blob/master/src/Webhooks.ts). The debugger must not say "Would verify".
test('a header with a space after a comma is not reported as verifying', async ({ page }) => {
  await open(page)
  const t = now()
  await paste(page, BODY, `t=${t}, v1=${sign(BODY, SECRET, t)}`, SECRET)
  await expect(finding(page, 'Whitespace inside the header')).toBeVisible()
  await expect(finding(page, 'Whitespace inside the header')).toContainText('No signatures found with expected scheme')
  await expect(finding(page, 'Whitespace inside the header')).toHaveClass(/bad/)
  await expect(verdict(page)).toHaveText('Would reject')
  await expect(verdict(page)).toHaveClass(/bad/)
  await expect(page.locator('.finding.good')).toHaveCount(0)
})

test('whitespace in the header: entries stripe-node cannot read are rejected, padding it tolerates still verifies', async ({ page }) => {
  await open(page)
  const t = now()
  const v1 = sign(BODY, SECRET, t)
  const cases: [string, string, 'Would verify' | 'Would reject'][] = [
    ['tab after the comma', `t=${t},\tv1=${v1}`, 'Would reject'],
    ['space before the = of v1', `t=${t},v1 =${v1}`, 'Would reject'],
    ['space after the = of v1', `t=${t},v1= ${v1}`, 'Would reject'],
    ['space before the = of t', `t =${t},v1=${v1}`, 'Would reject'],
    ['t after a space', `v1=${v1}, t=${t}`, 'Would reject'],
    ['space before the comma after v1', `t=${t},v1=${v1} ,v0=00`, 'Would reject'],
    ['space after the = of t', `t= ${t},v1=${v1}`, 'Would verify'],
    ['space before the comma after t', `t=${t} ,v1=${v1}`, 'Would verify'],
    ['canonical', `t=${t},v1=${v1}`, 'Would verify'],
  ]
  for (const [name, header, expected] of cases) {
    await paste(page, BODY, header, SECRET)
    await expect(verdict(page), name).toHaveText(expected)
    if (expected === 'Would reject') await expect(finding(page, 'Whitespace inside the header'), name).toBeVisible()
    else await expect(finding(page, 'Whitespace inside the header'), name).toHaveCount(0)
  }
})

test('a secret roll with a space before the second v1 reads only the first v1, as stripe-node does', async ({ page }) => {
  await open(page)
  const t = now()
  const mine = sign(BODY, SECRET, t)
  const theirs = sign(BODY, OTHER_SECRET, t)
  await paste(page, BODY, `t=${t},v1=${mine}, v1=${theirs}`, SECRET)
  await expect(verdict(page)).toHaveText('Would verify')
  await expect(finding(page, 'Whitespace inside the header')).toHaveClass(/warn/)
  await paste(page, BODY, `t=${t},v1=${theirs}, v1=${mine}`, SECRET)
  await expect(verdict(page)).toHaveText('Would reject')
})

test('a timestamp too large to be a date is diagnosed instead of blanking the page', async ({ page }) => {
  await open(page)
  // Dates end at t = 8640000000000; toISOString() throws for anything later.
  const cases: [string, string][] = [
    ['99999999999999', 'not a valid date'],
    ['8640000000001', 'not a valid date'],
    ['9'.repeat(400), 'not a valid date'],
    ['8640000000000', '+275760-09-13T00:00:00Z'],
    ['0', '1970-01-01T00:00:00Z'],
  ]
  for (const [t, shown] of cases) {
    await paste(page, '{}', `t=${t},v1=aa`, 'whsec_sample_secret_0123456789abcdef')
    await expect(page.getByText(/1 v1 · 2 body bytes/), t).toContainText(`(${shown})`)
    await expect(verdict(page), t).toHaveText('Would reject')
    await expect(finding(page, 'Signature does not match'), t).toBeVisible()
    await expect(finding(page, /^Timestamp is .* (old|in the future)/), t).toBeVisible()
    await expect(page.locator('.finding.good'), t).toHaveCount(0)
  }
})
