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

  it('shows recorded evidence without calling it a confirmed exploit', async () => {
    localStorage.setItem('zorix_token', 'test-token')
    localStorage.setItem('zorix_email', 'analyst@example.com')
    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: true,
      json: async () => ({ results: [{
        id: 'scan-1', repository: 'https://github.com/example/project',
        affected_file: 'app.py', status: 'completed', finding_count: 1,
        commit_sha: null, file_count: 1,
        created_at: '2026-01-01T00:00:00',
        findings: [{ rule_id: 'os-system-call', file: 'app.py', line: 2,
          severity: 'ERROR', message: 'Potential command injection' }],
      }] }),
    })))
    render(<App />)
    await waitFor(() => expect(screen.getByText('Potential command injection')).toBeTruthy())
    expect(screen.getByText('Not performed')).toBeTruthy()
    expect(screen.getByText('os-system-call')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Download SARIF' })).toBeTruthy()
  })

  it('submits a pinned repository scan by default', async () => {
    localStorage.setItem('zorix_token', 'test-token')
    const fetchMock = vi.fn(async (url: string) => ({
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
    fireEvent.click(screen.getByRole('button', { name: 'Run static scan' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(call =>
      call[0] === '/api/analysis/repository')).toBe(true))
  })
})
