export const API = '/api'

export async function request<T>(path: string, token?: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options?.headers,
    },
  })
  const body = await response.json().catch(() => ({}))
  if (token && localStorage.getItem('zorix_token') !== token) {
    throw new DOMException('Session changed; request discarded', 'AbortError')
  }
  if (token && response.status === 401) {
    localStorage.removeItem('zorix_token')
    window.dispatchEvent(new Event('zorix:session-expired'))
    throw new Error('Session expired. Sign in again.')
  }
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`)
  return body as T
}
