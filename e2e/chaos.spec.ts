import type { Locator, Page } from '@playwright/test'
import { test, expect, robustEndpoint, type Api, type Endpoint } from './fixtures.ts'
import { CHECKS, type CheckId, type Verdict } from '../api/_lib/chaos.ts'

// Everything here is synthetic. Demo targets run through the real handler (api/run.ts) inside the test process;
// "your endpoint" runs are answered by an in-process handler through the real engine. No test sends a request to
// a real URL (see fixtures.ts), and the page itself is stopped from reaching anything but the preview server.

const runButton = (page: Page) => page.getByRole('button', { name: /^(Run \d+ checks?|Running…)$/ })
const stat = (page: Page, label: string) => page.locator('.stat', { has: page.getByText(label, { exact: true }) }).locator('.value')
const finding = (page: Page, title: string) => page.locator('.finding', { has: page.locator('strong', { hasText: new RegExp(`^${title.replace(/[()]/g, '\\$&')}$`) }) })
const verdictOf = async (page: Page, id: CheckId) => (await finding(page, CHECKS.find((c) => c.id === id)!.title).locator('.badge').first().innerText()).trim()
const verdicts = async (page: Page, ids: CheckId[]) => Object.fromEntries(await Promise.all(ids.map(async (id) => [id, await verdictOf(page, id)])))
const alert = (page: Page) => page.getByRole('alert')
const results = (page: Page) => page.locator('section[aria-live="polite"]')

async function pickTarget(page: Page, name: RegExp) {
  await page.getByRole('radio', { name }).check()
}
async function onlyChecks(page: Page, ids: CheckId[]) {
  for (const c of CHECKS) {
    const box = page.getByRole('checkbox', { name: new RegExp(c.title.replace(/[()]/g, '\\$&')) })
    if (ids.includes(c.id)) await box.check()
    else await box.uncheck()
  }
}
async function fillEndpoint(page: Page, url = 'https://hooks.example.test/stripe', secret = 'whsec_e2e_test_secret_0123456789abcdef') {
  await pickTarget(page, /Your endpoint/)
  await page.getByLabel('Endpoint URL').fill(url)
  await page.getByLabel(/Signing secret/).fill(secret)
}
const lastCall = (api: Api) => api.calls[api.calls.length - 1]

const ALL = CHECKS.map((c) => c.id)

test.beforeEach(async ({ page }) => {
  await page.goto('/app')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Find out if your Stripe webhook will survive production')
})

// ---------------------------------------------------------------- main flow

test('the "Run naive demo" button runs every check and shows deliveries, failures and the endpoint state', async ({ page, api }) => {
  await page.getByRole('button', { name: 'Run naive demo' }).click()
  await expect(stat(page, 'Score')).toContainText('55')
  expect(lastCall(api)).toEqual({ target: 'naive', checks: ALL })

  await expect(stat(page, 'Passed')).toHaveText('5 / 10')
  await expect(stat(page, 'Failed · warnings')).toHaveText('4 · 1')
  expect(await verdicts(page, ALL)).toEqual({
    baseline: 'PASS', duplicate: 'FAIL', out_of_order: 'FAIL', rotated_secret: 'FAIL', unknown_type: 'PASS',
    bad_signature: 'PASS', stale_timestamp: 'FAIL', tampered_body: 'PASS', missing_header: 'PASS', latency: 'WARN',
  })

  // The naive handler sends its "email" before answering, so the slowest response is over the 3s line.
  const slowest = Number((await stat(page, 'Slowest response').innerText()).replace(/\D/g, ''))
  expect(slowest).toBeGreaterThanOrEqual(3000)

  // A failing check opens its deliveries: label, event id, status and response body.
  const dup = finding(page, 'Duplicate delivery')
  await expect(dup.locator('.summary')).toContainText('the payment was recorded twice')
  // The valid-delivery check already sent the original, so only the redelivery is added here.
  const rows = dup.locator('tbody tr')
  await expect(rows).toHaveCount(1)
  await expect(rows.first()).toContainText('Redelivery (same event id)')
  await expect(rows.first()).toContainText(/evt_\w+/)
  await expect(rows.first().locator('.badge')).toHaveText('200')
  await expect(rows.first()).toContainText('{"received":true}')

  // The rejected deliveries of a passing negative check are visible too once expanded.
  const forged = finding(page, 'Forged signature')
  await forged.getByText('1 delivery').click()
  await expect(forged.locator('tbody tr .badge')).toHaveText('400')
  await expect(forged.locator('tbody tr')).toContainText('Invalid signature')

  // The state the endpoint ended up with is compared with the correct one.
  const ledger = page.locator('.panel', { has: page.getByRole('heading', { name: "What the endpoint's database ended up with" }) })
  const paid = ledger.locator('tr', { hasText: 'Invoice payments recorded' })
  await expect(paid.locator('.badge')).toHaveText('3')
  await expect(paid.locator('.badge')).toHaveClass(/bad/)
  await expect(paid.locator('td').last()).toHaveText('2')
  const reordered = ledger.locator('tr', { hasText: '(reordered)' })
  await expect(reordered.locator('.badge')).toHaveText('active')
  await expect(reordered.locator('td').last()).toHaveText('canceled')

  // Advice names every check that did not pass.
  const advice = page.locator('ul.advice li')
  await expect(advice).toHaveCount(5)
  await expect(advice.filter({ hasText: 'Duplicate delivery' })).toContainText('Store processed event ids')
})

test('robust demo passes everything and its recorded state matches the correct one', async ({ page, api }) => {
  await pickTarget(page, /Robust demo/)
  await runButton(page).click()
  await expect(stat(page, 'Score')).toContainText('100')
  expect(lastCall(api)).toMatchObject({ target: 'robust' })
  await expect(stat(page, 'Passed')).toHaveText('10 / 10')
  await expect(stat(page, 'Failed · warnings')).toHaveText('0 · 0')
  expect(Object.values(await verdicts(page, ALL))).toEqual(Array(10).fill('PASS'))
  await expect(results(page).locator('.badge.bad')).toHaveCount(0)
  await expect(page.getByText('Everything passed.')).toBeVisible()
  const state = page.locator('tr', { hasText: /recorded|status/ }).locator('.badge')
  await expect(state).toHaveCount(4)
  await expect(page.locator('tr', { hasText: /recorded|status/ }).locator('.badge.bad')).toHaveCount(0)
})

test('re-parsing demo: authentic events are rejected with 400 and the report says why', async ({ page }) => {
  await pickTarget(page, /Re-parsing demo/)
  await runButton(page).click()
  await expect(stat(page, 'Score')).toContainText('50')
  expect(await verdictOf(page, 'baseline')).toBe('FAIL')
  const base = finding(page, 'Valid delivery, in order')
  await expect(base.locator('.summary')).toContainText('Authentic events are being rejected')
  await expect(base.locator('tbody tr .badge').first()).toHaveText('400')
  await expect(base.locator('tbody tr').first()).toContainText('Webhook Error')
  // It recorded nothing, which the endpoint-state table shows.
  const paid = page.locator('tr', { hasText: 'Invoice payments recorded' })
  await expect(paid.locator('.badge')).toHaveText('0')
  await expect(paid.locator('td').last()).toHaveText('2')
})

// ---------------------------------------------------------------- each check changes the result

// A single check against each demo. The same delivery gets a different verdict depending on how the handler behaves,
// which is the product: [naive, reparsed, robust].
const PER_CHECK: [CheckId, Verdict[]][] = [
  ['baseline', ['pass', 'fail', 'pass']],
  ['duplicate', ['fail', 'fail', 'pass']],
  ['out_of_order', ['fail', 'fail', 'pass']],
  ['rotated_secret', ['fail', 'fail', 'pass']],
  ['unknown_type', ['pass', 'fail', 'pass']],
  ['bad_signature', ['pass', 'pass', 'pass']],
  ['stale_timestamp', ['fail', 'pass', 'pass']],
  ['tampered_body', ['pass', 'pass', 'pass']],
  ['missing_header', ['pass', 'pass', 'pass']],
]
for (const [id, [naive, reparsed, robust]] of PER_CHECK) {
  test(`check "${id}" alone: naive ${naive}, re-parsing ${reparsed}, robust ${robust}`, async ({ page, api }) => {
    await onlyChecks(page, [id])
    await expect(runButton(page)).toHaveText('Run 1 check')
    const seen: Verdict[] = []
    for (const [target, name] of [['naive', /Naive demo/], ['reparsed', /Re-parsing demo/], ['robust', /Robust demo/]] as const) {
      await pickTarget(page, name)
      await runButton(page).click()
      await expect(stat(page, 'Score')).toBeVisible()
      expect(lastCall(api)).toEqual({ target, checks: [id] })
      await expect(page.locator('section[aria-live="polite"] .finding')).toHaveCount(1)
      seen.push((await verdictOf(page, id)).toLowerCase() as Verdict)
      // One graded check: the score is all or nothing.
      await expect(stat(page, 'Score')).toContainText(seen.at(-1) === 'pass' ? '100' : '0')
    }
    expect(seen).toEqual([naive, reparsed, robust])
  })
}

test('check "latency" is skipped alone, warns for the slow naive demo and passes for the robust one', async ({ page }) => {
  await onlyChecks(page, ['latency'])
  await pickTarget(page, /Robust demo/)
  await runButton(page).click()
  await expect(finding(page, 'Response time').locator('.badge').first()).toHaveText('SKIP')
  await expect(finding(page, 'Response time').locator('.summary')).toHaveText('No deliveries to measure.')
  // Nothing was graded, so the score is not a success.
  await expect(stat(page, 'Score')).toContainText('0')
  await expect(stat(page, 'Passed')).toHaveText('0 / 0')

  await onlyChecks(page, ['baseline', 'latency'])
  await runButton(page).click()
  await expect(stat(page, 'Score')).toContainText('100')
  await expect(finding(page, 'Response time').locator('.summary')).toContainText('Slowest response')

  await pickTarget(page, /Naive demo/)
  await runButton(page).click()
  await expect(finding(page, 'Response time').locator('.badge').first()).toHaveText('WARN')
  await expect(finding(page, 'Response time').locator('.summary')).toContainText('took ≥ 3s')
  await expect(stat(page, 'Score')).toContainText('75')
})

test('the check list drives what is sent, and zero checks cannot be run', async ({ page, api }) => {
  await expect(runButton(page)).toHaveText('Run 10 checks')
  await page.getByRole('checkbox', { name: /Duplicate delivery/ }).uncheck()
  await expect(runButton(page)).toHaveText('Run 9 checks')
  await onlyChecks(page, [])
  await expect(runButton(page)).toHaveText('Run 0 checks')
  await expect(runButton(page)).toBeDisabled()
  await onlyChecks(page, ['baseline', 'duplicate'])
  await pickTarget(page, /Robust demo/)
  await runButton(page).click()
  await expect(stat(page, 'Score')).toContainText('100')
  expect(lastCall(api)).toEqual({ target: 'robust', checks: ['baseline', 'duplicate'] })
  await expect(results(page).locator('.finding')).toHaveCount(2)
  expect(api.calls).toHaveLength(1)
})

// ---------------------------------------------------------------- your endpoint (stubbed)

test('your endpoint: fields are required, the run is stubbed, and the secret is not shown back', async ({ page, api }) => {
  await pickTarget(page, /Your endpoint/)
  await expect(runButton(page)).toBeDisabled()
  await page.getByLabel('Endpoint URL').fill('https://hooks.example.test/stripe')
  await expect(runButton(page)).toBeDisabled()
  await page.getByLabel(/Signing secret/).fill('   ')
  await expect(runButton(page)).toBeDisabled()
  const secret = 'whsec_e2e_test_secret_0123456789abcdef'
  await page.getByLabel(/Signing secret/).fill(secret)
  await expect(runButton(page)).toBeEnabled()

  api.endpoint = robustEndpoint()
  await runButton(page).click()
  await expect(stat(page, 'Score')).toContainText('100')
  expect(lastCall(api)).toEqual({ target: 'url', url: 'https://hooks.example.test/stripe', secret, checks: ALL })
  // No demo state to compare, and the report says so instead of claiming the database is right.
  await expect(page.getByRole('heading', { name: "What the endpoint's database ended up with" })).toHaveCount(0)
  await expect(finding(page, 'Duplicate delivery').locator('.summary')).toContainText('We cannot see your database')
  // Typed into a password field, but not repeated anywhere in the report.
  expect(await results(page).innerText()).not.toContain(secret)
  expect(await results(page).innerHTML()).not.toContain(secret)
})

test('your endpoint that accepts everything: forged, replayed, tampered and unsigned requests are failures', async ({ page, api }) => {
  await fillEndpoint(page)
  api.endpoint = async () => ({ status: 200, ms: 4, body: 'ok' })
  await runButton(page).click()
  await expect(stat(page, 'Score')).toContainText('60')
  const v = await verdicts(page, ALL)
  expect(v).toMatchObject({ baseline: 'PASS', rotated_secret: 'PASS', bad_signature: 'FAIL', stale_timestamp: 'FAIL', tampered_body: 'FAIL', missing_header: 'FAIL' })
  await expect(finding(page, 'Forged signature').locator('.summary')).toContainText('Accepted with HTTP 200')
  await expect(finding(page, 'Missing Stripe-Signature').locator('.summary')).toContainText('Verification is skipped when the header is absent')
})

test('your endpoint that is down: errors are shown per delivery, the run stops early and nothing passes', async ({ page, api }) => {
  await fillEndpoint(page)
  let calls = 0
  api.endpoint = async () => (calls++, { status: null, ms: 0, body: '', error: 'connect ECONNREFUSED' })
  await runButton(page).click()
  await expect(finding(page, 'Valid delivery, in order')).toBeVisible()
  expect(await verdictOf(page, 'baseline')).toBe('FAIL')
  // Three unreachable deliveries in a row end the run: the rest are skipped, not counted as passes.
  expect(calls).toBe(3)
  const rows = finding(page, 'Valid delivery, in order').locator('tbody tr')
  await expect(rows).toHaveCount(5)
  await expect(rows.first().locator('.badge')).toHaveText('ERR')
  await expect(rows.first()).toContainText('connect ECONNREFUSED')
  await expect(rows.last()).toContainText('Skipped: endpoint unreachable')
  await expect(stat(page, 'Score')).toHaveText(/^0 \/ 100$/)
  // Every delivery-based check failed. Nothing answered, so there is no response time to judge: that check is skipped, not passed.
  for (const id of ALL.filter((i) => i !== 'latency')) expect(await verdictOf(page, id), id).toBe('FAIL')
  expect(await verdictOf(page, 'latency')).toBe('SKIP')
  await expect(finding(page, 'Response time').locator('.summary')).toHaveText('No response received from the endpoint, so there is nothing to time.')
  await expect(stat(page, 'Passed')).toHaveText('0 / 9')
  await expect(page.locator('.badge.good')).toHaveCount(0)
})

test('your endpoint that is down: the response-time check alone with the baseline is skipped and the score is 0', async ({ page, api }) => {
  await fillEndpoint(page)
  api.endpoint = async () => ({ status: null, ms: 0, body: '', error: 'connect ECONNREFUSED' })
  await onlyChecks(page, ['baseline', 'latency'])
  await runButton(page).click()
  await expect(stat(page, 'Score')).toBeVisible()
  expect(await verdicts(page, ['baseline', 'latency'])).toEqual({ baseline: 'FAIL', latency: 'SKIP' })
  await expect(stat(page, 'Score')).toHaveText(/^0 \/ 100$/)
  await expect(stat(page, 'Passed')).toHaveText('0 / 1')
})

test('your endpoint that answers 500 to a bad signature gets a warning, and 302 on valid events a hint', async ({ page, api }) => {
  await fillEndpoint(page)
  const robust = robustEndpoint()
  const flaky: Endpoint = async (req, secret) => {
    const r = await robust(req, secret)
    return r.status !== null && r.status >= 400 ? { ...r, status: 500 } : r
  }
  api.endpoint = flaky
  await runButton(page).click()
  await expect(stat(page, 'Score')).toContainText('80')
  expect(await verdictOf(page, 'bad_signature')).toBe('WARN')
  await expect(finding(page, 'Forged signature').locator('.summary')).toContainText('Rejected, but with HTTP 500')

  api.endpoint = async () => ({ status: 302, ms: 3, body: '' })
  await runButton(page).click()
  await expect(finding(page, 'Valid delivery, in order').locator('.summary')).toContainText('Stripe treats redirects as failed deliveries')
})

// ---------------------------------------------------------------- failures and bad input

test('while a run is in flight the button is disabled and the previous report is gone', async ({ page, api }) => {
  await pickTarget(page, /Robust demo/)
  await runButton(page).click()
  await expect(stat(page, 'Score')).toContainText('100')
  let release!: () => void
  api.hold = new Promise<void>((r) => (release = r))
  await runButton(page).click()
  await expect(page.getByRole('button', { name: 'Running…' })).toBeDisabled()
  await expect(stat(page, 'Score')).toHaveCount(0)
  release()
  await expect(stat(page, 'Score')).toContainText('100')
  await expect(runButton(page)).toBeEnabled()
})

const API_FAILURES: [string, NonNullable<Api['override']>, RegExp][] = [
  ['500 with a JSON error', { status: 500, body: JSON.stringify({ error: 'Run failed on the server.' }) }, /^Run failed on the server\.$/],
  ['429 rate limit', { status: 429, body: JSON.stringify({ error: 'Too many runs. Try again in a minute.' }) }, /Too many runs\. Try again in a minute\./],
  ['502 with an HTML page', { status: 502, contentType: 'text/html', body: '<html>Bad gateway</html>' }, /^Unexpected response \(HTTP 502\)\.$/],
  ['error without a message', { status: 503, body: '{}' }, /^HTTP 503$/],
  ['200 that is not JSON', { status: 200, contentType: 'text/html', body: '<!doctype html><title>x</title>' }, /^Unexpected response \(HTTP 200\)\.$/],
  ['200 with an empty body', { status: 200, body: '' }, /^Unexpected response \(HTTP 200\)\.$/],
  ['200 with JSON null', { status: 200, body: 'null' }, /^Unexpected response \(HTTP 200\)\.$/],
  ['200 with JSON that is not a report', { status: 200, body: '{"score":1}' }, /^Unexpected response \(HTTP 200\)\.$/],
  ['200 with a report whose checks are not a list', { status: 200, body: JSON.stringify({ target: 'robust', score: 100, checks: 'none' }) }, /^Unexpected response \(HTTP 200\)\.$/],
  ['200 with an unknown check id', { status: 200, body: JSON.stringify({ target: 'robust', score: 0, checks: [{ id: 'nope', title: 'x', verdict: 'fail', summary: 'x', deliveries: [] }] }) }, /^Unexpected response \(HTTP 200\)\.$/],
  ['200 carrying an error message', { status: 200, body: JSON.stringify({ error: 'Maintenance window.' }) }, /^Maintenance window\.$/],
  ['500 with JSON null', { status: 500, body: 'null' }, /^HTTP 500$/],
  ['dropped connection', 'abort', /fetch|network|Failed/i],
]
for (const [name, override, message] of API_FAILURES) {
  test(`API failure (${name}) shows a message and no results`, async ({ page, api }) => {
    api.override = override
    await pickTarget(page, /Robust demo/)
    await runButton(page).click()
    await expect(alert(page)).toHaveText(message)
    await expect(alert(page)).toHaveClass(/bad/)
    await expect(stat(page, 'Score')).toHaveCount(0)
    await expect(page.locator('.badge.good')).toHaveCount(0)
    await expect(page.getByRole('heading', { name: 'Results' })).toHaveCount(0)
    // The user can try again, and a successful run clears the message.
    await expect(runButton(page)).toBeEnabled()
    api.override = undefined
    await runButton(page).click()
    await expect(stat(page, 'Score')).toContainText('100')
    await expect(alert(page)).toHaveCount(0)
  })
}

// These go through the real handler; its rejections happen before any DNS lookup or connection.
const BAD_INPUT: [string, string, string, RegExp][] = [
  ['a secret that is not a whsec_ value', 'https://hooks.example.test/stripe', 'sk_test_123', /Signing secret must look like whsec_/],
  ['a too-short secret', 'https://hooks.example.test/stripe', 'whsec_short', /Signing secret must look like whsec_/],
  ['plain http', 'http://hooks.example.test/stripe', 'whsec_e2e_test_secret_0123456789abcdef', /Only https:\/\/ endpoints are allowed/],
  ['not a URL', 'not a url', 'whsec_e2e_test_secret_0123456789abcdef', /Enter a full URL/],
  ['localhost', 'https://localhost/webhook', 'whsec_e2e_test_secret_0123456789abcdef', /not publicly reachable/],
  ['a loopback address', 'https://127.0.0.1/webhook', 'whsec_e2e_test_secret_0123456789abcdef', /private or reserved address/],
  ['the cloud metadata address', 'https://169.254.169.254/latest/meta-data', 'whsec_e2e_test_secret_0123456789abcdef', /private or reserved address/],
  ['an IPv4-mapped IPv6 loopback', 'https://[::ffff:127.0.0.1]/', 'whsec_e2e_test_secret_0123456789abcdef', /private or reserved address/],
  ['a decimal-encoded loopback', 'https://2130706433/', 'whsec_e2e_test_secret_0123456789abcdef', /private or reserved address/],
  ['credentials in the URL', 'https://user:pass@8.8.8.8/', 'whsec_e2e_test_secret_0123456789abcdef', /credentials are not allowed/],
  ['a non-standard port', 'https://10.0.0.5:22/', 'whsec_e2e_test_secret_0123456789abcdef', /Only the default HTTPS port/],
]
for (const [name, url, secret, message] of BAD_INPUT) {
  test(`bad input (${name}) is refused with a clear message and no results`, async ({ page, api }) => {
    await fillEndpoint(page, url, secret)
    await runButton(page).click()
    await expect(alert(page)).toHaveText(message)
    await expect(stat(page, 'Score')).toHaveCount(0)
    expect(api.calls).toHaveLength(1)
    // The secret the user typed is not echoed back in the message.
    expect(await alert(page).innerText()).not.toContain(secret)
  })
}

// ---------------------------------------------------------------- report, fixes, script

test('the report can be copied as Markdown, and it matches what is on screen', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await page.getByRole('button', { name: 'Run naive demo' }).click()
  await expect(stat(page, 'Score')).toContainText('55')
  await page.getByRole('button', { name: 'Copy report as Markdown' }).click()
  await expect(page.getByRole('button', { name: 'Copied' })).toBeVisible()
  const md = await page.evaluate(() => navigator.clipboard.readText())
  expect(md).toContain('## Stripe webhook chaos run: 55/100')
  expect(md).toContain('Target: naive demo')
  expect(md).toContain('| Duplicate delivery | FAIL |')
  expect(md).toContain('| Forged signature | PASS |')
  expect(md).toContain('| Response time | WARN |')
  expect(md).toContain('### To fix')
  // Response bodies stay out of the report.
  expect(md).not.toContain('received')
})

test('"How to fix" lists the failed checks and switches between framework snippets', async ({ page }) => {
  await page.getByRole('button', { name: 'Run naive demo' }).click()
  const fixes = page.locator('.panel', { has: page.getByRole('heading', { name: 'How to fix' }) })
  await expect(fixes.locator('ul.advice li')).toHaveCount(5)
  await expect(fixes.locator('pre').first()).toContainText('express.raw')
  await fixes.getByRole('tab', { name: 'Flask' }).click()
  await expect(fixes.getByRole('tab', { name: 'Flask' })).toHaveAttribute('aria-selected', 'true')
  await expect(fixes.locator('pre').first()).toContainText('request.get_data()')
  await expect(fixes.locator('pre').first()).not.toContainText('express.raw')
})

test('the local script is a download that reads the secret from the environment', async ({ page }) => {
  await pickTarget(page, /Your endpoint/)
  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download webhook-chaos.sh' }).click()])
  expect(download.suggestedFilename()).toBe('webhook-chaos.sh')
  const text = await (await import('node:fs/promises')).readFile((await download.path())!, 'utf8')
  expect(text.startsWith('#!')).toBe(true)
  expect(text).toContain('STRIPE_WEBHOOK_SECRET')
  expect(text).not.toMatch(/whsec_[A-Za-z0-9]{16,}/)
})
