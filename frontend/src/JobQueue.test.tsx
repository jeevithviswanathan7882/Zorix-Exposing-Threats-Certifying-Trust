import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import JobQueue from './JobQueue'

afterEach(() => { cleanup(); localStorage.clear(); vi.unstubAllGlobals() })

it('refreshes evidence when a submitted job completes', async () => {
  localStorage.setItem('zorix_token', 'token')
  const onFinished = vi.fn()
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ jobs: [
    { id: 'job-1', repository: 'https://github.com/example/project', affected_file: 'app.py', state: 'completed', error: null },
  ] }) })))
  render(<JobQueue token="token" latestJob="job-1" onFinished={onFinished} onError={vi.fn()} />)
  await waitFor(() => expect(onFinished).toHaveBeenCalledTimes(1))
})

it('cancels a queued job through the authenticated API', async () => {
  localStorage.setItem('zorix_token', 'token')
  const fetchMock = vi.fn(async (_url: string, _options?: RequestInit) => ({ ok: true, json: async () => ({ jobs: [
    { id: 'job-1', repository: 'https://github.com/example/project', affected_file: 'app.py', state: 'queued', error: null },
  ] }) }))
  vi.stubGlobal('fetch', fetchMock)
  render(<JobQueue token="token" latestJob="job-1" onFinished={vi.fn()} onError={vi.fn()} />)
  fireEvent.click(await screen.findByRole('button', { name: 'Cancel queued scan' }))
  await waitFor(() => expect(fetchMock.mock.calls.some(call => call[0] === '/api/jobs/job-1/cancel' && call[1]?.method === 'POST')).toBe(true))
})
