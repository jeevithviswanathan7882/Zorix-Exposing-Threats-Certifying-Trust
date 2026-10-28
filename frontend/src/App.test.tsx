import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import App from './App'

afterEach(() => {
  cleanup()
  localStorage.clear()
  vi.unstubAllGlobals()
})

describe('Zorix frontend', () => {
  it('shows sign in and registration without a token', () => {
    render(<App />)
    expect(screen.getByRole('heading', { name: 'Sign in' })).toBeTruthy()
    expect(screen.getByText('New here? Create an account')).toBeTruthy()
  })

  it('returns to sign in when an existing session expires', async () => {
    localStorage.setItem('zorix_token', 'expired-token')
    localStorage.setItem('zorix_email', 'analyst@example.com')
    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: false, status: 401, json: async () => ({ detail: 'Invalid token' }),
    })))
    render(<App />)
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Sign in' })).toBeTruthy())
    expect(screen.getByRole('alert').textContent).toContain('Session expired')
    expect(localStorage.getItem('zorix_token')).toBeNull()
  })

  it('clears a per-scan GitHub token across sign out and sign in', async () => {
    localStorage.setItem('zorix_token', 'first-session')
    localStorage.setItem('zorix_email', 'analyst@example.com')
    vi.stubGlobal('fetch', vi.fn(async (url: string) => ({
      ok: true,
      json: async () => url.endsWith('/auth/login') ? { access_token: 'second-session' } : { results: [] },
    })))
    render(<App />)
    fireEvent.change(screen.getByLabelText('GitHub token (optional)'), { target: { value: 'private-token' } })
    fireEvent.click(screen.getByRole('button', { name: /Sign out/ }))
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'ExamplePassword123!' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    await waitFor(() => expect(screen.getByLabelText('GitHub token (optional)')).toBeTruthy())
    expect((screen.getByLabelText('GitHub token (optional)') as HTMLInputElement).value).toBe('')
  })

  it('shows recorded evidence without calling it a confirmed exploit', async () => {
    localStorage.setItem('zorix_token', 'test-token')
    localStorage.setItem('zorix_email', 'analyst@example.com')
    const fetchMock = vi.fn(async (url: string, _options?: RequestInit) => ({
      ok: true,
      json: async () => url.includes('/findings/0/review')
        ? { finding_index: 0, status: 'false_positive', note: 'Safe input' }
        : url.endsWith('/analysis/results/scan-1') ? { reviews: [] } : { results: [{
        id: 'scan-1', repository: 'https://github.com/example/project',
        affected_file: 'app.py', status: 'completed', finding_count: 1,
        commit_sha: null, file_count: 1,
        created_at: '2026-01-01T00:00:00',
        findings: [{ rule_id: 'os-system-call', file: 'app.py', line: 2,
          severity: 'ERROR', message: 'Potential command injection' }],
      }] },
    }))
    vi.stubGlobal('fetch', fetchMock)
    render(<App />)
    await waitFor(() => expect(screen.getByText('Potential command injection')).toBeTruthy())
    const navigation = screen.getByRole('navigation', { name: 'Main navigation' })
    expect(navigation.querySelector('a[href="#new-scan"]')).toBeTruthy()
    expect(navigation.querySelector('a[href="#scan-history"]')).toBeTruthy()
    expect(navigation.querySelector('a[href="#evidence"]')).toBeTruthy()
    expect(screen.getByText('Not performed')).toBeTruthy()
    expect(screen.getByText('os-system-call')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Download SARIF' })).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Review status'), { target: { value: 'false_positive' } })
    fireEvent.change(screen.getByLabelText('Review note'), { target: { value: 'Safe input' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save review' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(call =>
      call[0] === '/api/analysis/results/scan-1/findings/0/review' && call[1]?.method === 'PUT'
    )).toBe(true))
  })

  it('submits a pinned repository scan by default', async () => {
    localStorage.setItem('zorix_token', 'test-token')
    const fetchMock = vi.fn(async (url: string, _options?: RequestInit) => ({
      ok: true,
      json: async () => url.endsWith('/analysis/repository')
        ? { status: 'completed', findings: [], analysis_id: 'scan-2' }
        : { results: [] },
    }))
    vi.stubGlobal('fetch', fetchMock)
    render(<App />)
    fireEvent.change(screen.getByLabelText('GitHub repository URL'), {
      target: { value: 'https://github.com/example/project' },
    })
    fireEvent.change(screen.getByLabelText('GitHub token (optional)'), {
      target: { value: 'temporary-token' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Run static scan' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(call =>
      call[0] === '/api/analysis/repository')).toBe(true))
    const request = fetchMock.mock.calls.find(call => call[0] === '/api/analysis/repository')
    expect(JSON.parse(String(request?.[1]?.body)).github_token).toBe('temporary-token')
    await waitFor(() => expect((screen.getByLabelText('GitHub token (optional)') as HTMLInputElement).value).toBe(''))
  })

  it('shows changes between scans of the same scope', async () => {
    localStorage.setItem('zorix_token', 'test-token')
    vi.stubGlobal('fetch', vi.fn(async (url: string) => ({
      ok: true,
      json: async () => url.includes('/compare/')
        ? { introduced: [], resolved: [], introduced_count: 1, resolved_count: 0,
            unchanged_count: 2, note: 'Manual review required' }
        : url.includes('/analysis/results/') ? { reviews: [] }
        : { results: ['new', 'old'].map(id => ({
            id, repository: 'https://github.com/example/project', affected_file: '(repository)',
            status: 'completed', finding_count: 0, findings: [], file_count: 2,
            commit_sha: 'a'.repeat(40), created_at: '2026-01-01T00:00:00',
          })) },
    })))
    render(<App />)
    const baseline = await screen.findByLabelText('Compare with a scan of this repository')
    fireEvent.change(baseline, { target: { value: 'old' } })
    fireEvent.click(screen.getByRole('button', { name: 'Compare findings' }))
    await waitFor(() => expect(screen.getByText('1 introduced · 0 resolved · 2 unchanged')).toBeTruthy())
  })
})
