import { chromium } from 'playwright-core'
import { mkdir, readFile, rm } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const baseUrl = process.env.ZORIX_SCREENSHOT_URL || 'http://127.0.0.1:3000'
const outputDir = fileURLToPath(new URL('../../docs/screenshots/', import.meta.url))
await mkdir(outputDir, { recursive: true })

const repository = 'https://github.com/example/security-demo'
const rulesSha256 = createHash('sha256').update(
  await readFile(new URL('../../security/semgrep_rules.yaml', import.meta.url)),
).digest('hex')
const currentFindings = [
  { rule_id: 'os-system-call', file: 'src/worker.py', line: 42, severity: 'ERROR',
    message: 'Potential command injection via os.system()' },
  { rule_id: 'innerhtml-assignment', file: 'web/dashboard.ts', line: 18,
    severity: 'ERROR', message: 'Direct innerHTML assignment can lead to XSS' },
]
const scans = [
  { id: '11111111-1111-4111-8111-111111111111', repository,
    affected_file: '(repository)', status: 'completed', finding_count: 2,
    findings: currentFindings, commit_sha: 'a'.repeat(40), rules_sha256: rulesSha256, file_count: 12,
    created_at: '2026-10-27T12:00:00' },
  { id: '22222222-2222-4222-8222-222222222222', repository,
    affected_file: '(repository)', status: 'completed', finding_count: 1,
    findings: [currentFindings[0]], commit_sha: 'b'.repeat(40), rules_sha256: rulesSha256, file_count: 12,
    created_at: '2026-10-26T12:00:00' },
]

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM_PATH || (existsSync('/usr/bin/chromium') ? '/usr/bin/chromium' : chromium.executablePath()),
  headless: true,
  args: ['--no-sandbox'],
})

try {
  const publicContext = await browser.newContext({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1, reducedMotion: 'reduce' })
  const signIn = await publicContext.newPage()
  await signIn.goto(baseUrl, { waitUntil: 'networkidle' })
  await signIn.screenshot({ path: path.join(outputDir, '01-sign-in.png') })
  await publicContext.close()

  const context = await browser.newContext({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1, reducedMotion: 'reduce' })
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
    } else if (pathname.endsWith('/history')) {
      response = { events: [{ id: 'sample-review-event', status: 'investigating',
        note: 'Tracing user input to the command boundary.', event_type: 'review_saved',
        created_at: '2026-10-27T12:00:00' }] }
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
  await page.screenshot({ path: path.join(outputDir, '02-scan-overview.png') })
  await page.getByLabel('Review status').first().selectOption('investigating')
  await page.getByLabel('Review note').first().fill('Tracing user input to the command boundary.')
  await page.getByRole('button', { name: 'View review history' }).first().click()
  await page.getByRole('list', { name: 'Review history for finding 1' }).waitFor()
  await page.locator('.details').scrollIntoViewIfNeeded()
  await page.screenshot({ path: path.join(outputDir, '03-finding-review.png') })

  await page.getByLabel('Compare with a scan of this repository').selectOption(scans[1].id)
  await page.getByRole('button', { name: 'Compare findings' }).click()
  await page.getByText('1 introduced · 0 resolved · 1 unchanged').waitFor()
  await page.screenshot({ path: path.join(outputDir, '04-scan-comparison.png') })

  await page.getByLabel('Scan scope').selectOption('file')
  await page.locator('.scan-form').scrollIntoViewIfNeeded()
  await page.screenshot({ path: path.join(outputDir, '05-file-scan-form.png') })
  await page.getByRole('button', { name: /completed · 12 file\(s\) · 1 potential finding\(s\)/ }).click()
  await page.locator('.details').scrollIntoViewIfNeeded()
  await page.screenshot({ path: path.join(outputDir, '06-scan-history.png') })
  await context.close()

  await rm(path.join(outputDir, '06-mobile-evidence.png'), { force: true })
} finally {
  await browser.close()
}

for (const name of ['01-sign-in.png', '02-scan-overview.png', '03-finding-review.png',
  '04-scan-comparison.png', '05-file-scan-form.png', '06-scan-history.png']) {
  const png = await readFile(path.join(outputDir, name))
  if (png.readUInt32BE(16) !== 1920 || png.readUInt32BE(20) !== 1080) {
    throw new Error(`${name} must be 1920 x 1080`)
  }
}

console.log(`Saved Zorix UI screenshots to ${outputDir}`)
