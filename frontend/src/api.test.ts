import { afterEach, expect, it, vi } from 'vitest'
import { request } from './api'

afterEach(() => { localStorage.clear(); vi.unstubAllGlobals() })

it.each([200, 401])('discards an old-session response (%s) without signing out the new user', async status => {
  localStorage.setItem('zorix_token', 'old-session')
  vi.stubGlobal('fetch', vi.fn(async () => {
    localStorage.setItem('zorix_token', 'new-session')
    return { ok: status === 200, status, json: async () => ({ results: ['private old-session data'] }) }
  }))
  await expect(request('/analysis/results', 'old-session')).rejects.toHaveProperty('name', 'AbortError')
  expect(localStorage.getItem('zorix_token')).toBe('new-session')
})
