import { chromium } from 'playwright-core'
import { mkdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const baseUrl = process.env.ZORIX_SCREENSHOT_URL || 'http://127.0.0.1:3000'
const outputDir = fileURLToPath(new URL('../../docs/screenshots/', import.meta.url))
await mkdir(outputDir, { recursive: true })

const repository = 'https://github.com/example/security-demo'
const currentFindings = [
  { rule_id: 'os-system-call', file: 'src/worker.py', line: 42, severity: 'ERROR',
    message: 'Potential command injection via os.system()' },
  { rule_id: 'innerhtml-assignment', file: 'web/dashboard.ts', line: 18,
    severity: 'ERROR', message: 'Direct innerHTML assignment can lead to XSS' },
]
const scans = [
  { id: '11111111-1111-4111-8111-111111111111', repository,
    affected_file: '(repository)', status: 'completed', finding_count: 2,
    findings: currentFindings, commit_sha: 'a'.repeat(40), file_count: 12,
    created_at: '2026-10-27T12:00:00' },
  { id: '22222222-2222-4222-8222-222222222222', repository,
    affected_file: '(repository)', status: 'completed', finding_count: 1,
    findings: [currentFindings[0]], commit_sha: 'b'.repeat(40), file_count: 12,
    created_at: '2026-10-26T12:00:00' },
]

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium',
  headless: true,
  args: ['--no-sandbox'],
})

try {
  const publicContext = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 })
  const signIn = await publicContext.newPage()
  await signIn.goto(baseUrl, { waitUntil: 'networkidle' })
  await signIn.screenshot({ path: path.join(outputDir, '01-sign-in.png'), fullPage: true })
  await publicContext.close()

  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 })
  await context.addInitScript(() => {
    localStorage.setItem('zorix_token', 'screenshot-demo-token')
    localStorage.setItem('zorix_email', 'analyst@example.com')
  })
  await context.route('**/api/**', async route => {
    const url = new URL(route.request().url())
    const pathname = url.pathname
    let response
    if (pathname === '/api/analysis/results') {
      response = { results: scans, total: scans.length }
    } else if (pathname.includes('/compare/')) {
      response = { introduced: [currentFindings[1]], resolved: [], introduced_count: 1,
        resolved_count: 0, unchanged_count: 1,
        note: 'Changes in static findings require manual review; they do not prove a vulnerability was fixed or introduced.' }
    } else if (pathname.includes('/findings/') && pathname.endsWith('/review')) {
      response = { finding_index: 0, status: 'investigating', note: 'Tracing user input to the command boundary.' }
    } else if (pathname.startsWith('/api/analysis/results/')) {
      response = { reviews: [{ finding_index: 0, status: 'investigating',
        note: 'Tracing user input to the command boundary.' }] }
    } else {
      response = { detail: 'Screenshot fixture does not implement this request' }
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) })
  })

  const page = await context.newPage()
  await page.goto(baseUrl, { waitUntil: 'networkidle' })
  await page.getByText('Potential command injection via os.system()').waitFor()
  await page.screenshot({ path: path.join(outputDir, '02-scan-overview.png'), fullPage: true })
  await page.locator('.details').screenshot({ path: path.join(outputDir, '03-finding-review.png') })

  await page.getByLabel('Compare with a scan of this repository').selectOption(scans[1].id)
  await page.getByRole('button', { name: 'Compare findings' }).click()
  await page.getByText('1 introduced · 0 resolved · 1 unchanged').waitFor()
  await page.locator('.details').screenshot({ path: path.join(outputDir, '04-scan-comparison.png') })

  await page.getByLabel('Scan scope').selectOption('file')
  await page.locator('.scan-form').screenshot({ path: path.join(outputDir, '05-file-scan-form.png') })
  await context.close()

  const mobileContext = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 1 })
  await mobileContext.addInitScript(() => {
    localStorage.setItem('zorix_token', 'screenshot-demo-token')
    localStorage.setItem('zorix_email', 'analyst@example.com')
  })
  await mobileContext.route('**/api/**', async route => {
    const pathname = new URL(route.request().url()).pathname
    const response = pathname === '/api/analysis/results'
      ? { results: scans, total: scans.length }
      : { reviews: [] }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) })
  })
  const mobile = await mobileContext.newPage()
  await mobile.goto(baseUrl, { waitUntil: 'networkidle' })
  await mobile.getByText('Potential command injection via os.system()').waitFor()
  await mobile.screenshot({ path: path.join(outputDir, '06-mobile-evidence.png'), fullPage: true })
  await mobileContext.close()
} finally {
  await browser.close()
}

console.log(`Saved Zorix UI screenshots to ${outputDir}`)
