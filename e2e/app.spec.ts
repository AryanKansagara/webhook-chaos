import { test, expect } from './fixtures.ts'
import { CHECKS } from '../api/_lib/chaos.ts'

test('landing page leads to the tool, and the tool leads back', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Prove your Stripe webhook')
  await expect(page.getByText('Ten checks, from duplicates and reordering')).toBeVisible()
  await page.getByRole('button', { name: 'Try this' }).first().click()
  await expect(page).toHaveURL(/\/app$/)
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Find out if your Stripe webhook will survive production')
  // Nothing runs on its own and nothing is claimed before a run.
  await expect(page.getByText('Score', { exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: 'Back to home' }).click()
  await expect(page).toHaveURL(/\/$/)
})

test('deep links work for the tool and the docs (SPA fallback)', async ({ page }) => {
  for (const path of ['/app', '/app/', '/docs', '/docs/anything', '/nope']) {
    const res = await page.goto(path)
    expect(res?.status(), path).toBe(200)
    await expect(page.locator('#root > *').first(), path).toBeVisible()
  }
  await page.goto('/nope')
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Prove your Stripe webhook')
})

test('docs list every check the tool runs, and link to the tool', async ({ page }) => {
  await page.goto('/app')
  await page.getByRole('button', { name: 'How it works' }).click()
  await expect(page).toHaveURL(/\/docs$/)
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('How it works')
  const rows = page.locator('section', { has: page.getByRole('heading', { name: 'The checks' }) }).locator('tbody tr')
  await expect(rows).toHaveCount(CHECKS.length)
  for (const [i, c] of CHECKS.entries()) await expect(rows.nth(i)).toContainText(c.title)
  await expect(page.getByRole('heading', { name: 'Scoring' })).toBeVisible()
  await page.getByRole('button', { name: 'Open the tool' }).click()
  await expect(page).toHaveURL(/\/app$/)
})

test('the theme choice survives a reload; nothing else is stored', async ({ page }) => {
  await page.goto('/app')
  const mode = () => page.evaluate(() => document.documentElement.dataset.themeMode)
  const first = await mode()
  expect(['light', 'dark']).toContain(first)
  const other = first === 'dark' ? 'light' : 'dark'
  await page.getByRole('button', { name: /^Switch to (light|dark) theme$/ }).click()
  expect(await mode()).toBe(other)
  await page.reload()
  expect(await mode()).toBe(other)
  expect(await page.evaluate(() => localStorage.getItem('themeMode'))).toBe(other)
  // The theme is the only thing the app stores: no secrets, no run history.
  expect(await page.evaluate(() => Object.keys(localStorage))).toEqual(['themeMode'])
  expect(await page.evaluate(() => Object.keys(sessionStorage))).toEqual([])
  await page.getByRole('button', { name: /^Switch to (light|dark) theme$/ }).click()
  await page.reload()
  expect(await mode()).toBe(first)
})

test('a run is not remembered across a reload, as the README says', async ({ page }) => {
  await page.goto('/app')
  await page.getByRole('radio', { name: /Robust demo/ }).check()
  await page.getByRole('button', { name: /^Run 10 checks$/ }).click()
  await expect(page.getByText('Score', { exact: true })).toBeVisible()
  await page.reload()
  await expect(page.getByText('Score', { exact: true })).toHaveCount(0)
  await expect(page.getByRole('radio', { name: /Naive demo/ })).toBeChecked()
})

test('the page makes no request outside the preview server except the font hosts, which are blocked', async ({ page, blocked }) => {
  const requested: string[] = []
  page.on('request', (r) => requested.push(new URL(r.url()).host))
  await page.goto('/app')
  await page.getByRole('radio', { name: /Robust demo/ }).check()
  await page.getByRole('button', { name: /^Run 10 checks$/ }).click()
  await expect(page.getByText('Score', { exact: true })).toBeVisible()
  const hosts = new Set(requested.filter((h) => !h.startsWith('127.0.0.1')))
  for (const h of hosts) expect(['fonts.googleapis.com', 'fonts.gstatic.com'], h).toContain(h)
  // Whatever tried to leave the machine was stopped by the test harness.
  for (const h of blocked) expect(['fonts.googleapis.com', 'fonts.gstatic.com'], h).toContain(h)
})
