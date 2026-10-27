import { FormEvent, useCallback, useEffect, useState } from 'react'
import './App.css'

type Finding = { rule_id: string; file: string; line: number | null; severity: string; message: string }
type Scan = {
  id: string
  repository: string
  affected_file: string
  status: string
  finding_count: number
  findings: Finding[]
  commit_sha: string | null
  file_count: number
  created_at: string
}
type ScanResponse = { status: string; error?: string; findings: Finding[]; analysis_id: string }

const API = '/api'

async function request<T>(path: string, token?: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options?.headers,
    },
  })
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`)
  return body as T
}

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('zorix_token') || '')
  const [email, setEmail] = useState(localStorage.getItem('zorix_email') || '')
  const [password, setPassword] = useState('')
  const [registering, setRegistering] = useState(false)
  const [repoUrl, setRepoUrl] = useState('')
  const [affectedFile, setAffectedFile] = useState('')
  const [scanScope, setScanScope] = useState<'repository' | 'file'>('repository')
  const [scans, setScans] = useState<Scan[]>([])
  const [selected, setSelected] = useState<Scan | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const loadScans = useCallback(async (preferLatest = false) => {
    if (!token) return
    try {
      const data = await request<{ results: Scan[] }>('/analysis/results', token)
      setScans(data.results)
      setSelected(current => (preferLatest ? data.results[0] : data.results.find(item => item.id === current?.id) || data.results[0]) || null)
    } catch (err) {
      setError((err as Error).message)
    }
  }, [token])

  useEffect(() => { void loadScans() }, [loadScans])

  const signIn = async (event: FormEvent) => {
    event.preventDefault()
    setBusy(true); setError(''); setNotice('')
    try {
      if (registering) await request('/auth/register', undefined, {
        method: 'POST', body: JSON.stringify({ email, password }),
      })
      const data = await request<{ access_token: string }>('/auth/login', undefined, {
        method: 'POST', body: JSON.stringify({ email, password }),
      })
      localStorage.setItem('zorix_token', data.access_token)
      localStorage.setItem('zorix_email', email)
      setToken(data.access_token)
      setPassword('')
    } catch (err) { setError((err as Error).message) }
    finally { setBusy(false) }
  }

  const startScan = async (event: FormEvent) => {
    event.preventDefault()
    setBusy(true); setError(''); setNotice('')
    try {
      const result = await request<ScanResponse>(scanScope === 'repository' ? '/analysis/repository' : '/analysis/analyze', token, {
        method: 'POST',
        body: JSON.stringify(scanScope === 'repository'
          ? { repo_url: repoUrl }
          : { repo_url: repoUrl, affected_file: affectedFile }),
      })
      await loadScans(true)
      setNotice(result.status === 'completed'
        ? `Scan complete: ${result.findings.length} potential finding(s). Review the evidence before reporting.`
        : `Scan ${result.status}: ${result.error || 'Check scanner configuration.'}`)
    } catch (err) { setError((err as Error).message) }
    finally { setBusy(false) }
  }

  const downloadReport = async (id: string, format: 'html' | 'sarif') => {
    setError('')
    try {
      const response = await fetch(`${API}/analysis/reports/${id}/${format}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!response.ok) throw new Error(`Report request failed (${response.status})`)
      const url = URL.createObjectURL(await response.blob())
      const link = document.createElement('a')
      link.href = url
      link.download = `zorix-${id}.${format}`
      link.click()
      URL.revokeObjectURL(url)
    } catch (err) { setError((err as Error).message) }
  }

  const signOut = () => {
    localStorage.removeItem('zorix_token')
    localStorage.removeItem('zorix_email')
    setToken(''); setScans([]); setSelected(null); setError('')
  }

  if (!token) return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="brand">ZORIX<span> / SECURITY VALIDATION</span></div>
        <h1>{registering ? 'Create an account' : 'Sign in'}</h1>
        <p>Inspect GitHub source with real static analysis and review the evidence.</p>
        <form onSubmit={signIn}>
          <label>Email<input type="email" value={email} onChange={e => setEmail(e.target.value)} required /></label>
          <label>Password<input type="password" value={password} onChange={e => setPassword(e.target.value)} minLength={registering ? 8 : 1} required /></label>
          {error && <div className="error" role="alert">{error}</div>}
          <button disabled={busy}>{busy ? 'Working…' : registering ? 'Register and sign in' : 'Sign in'}</button>
        </form>
        <button className="text-button" onClick={() => { setRegistering(!registering); setError('') }}>
          {registering ? 'Already have an account? Sign in' : 'New here? Create an account'}
        </button>
      </div>
    </div>
  )

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">ZORIX<span> / SECURITY VALIDATION</span></div>
        <div className="account"><span>{email}</span><button className="text-button" onClick={signOut}>Sign out</button></div>
      </header>
      <main>
        <div className="intro">
          <div><span className="eyebrow">Repository analysis</span><h1>Review evidence. Verify risk.</h1>
          <p>Scan a bounded GitHub repository or one source file with Semgrep. Findings are potential issues, not confirmed exploits or CVSS scores.</p></div>
          <div className="count"><strong>{scans.length}</strong><span>your scans</span></div>
        </div>
        {error && <div className="error" role="alert">{error}</div>}
        {notice && <div className="notice" role="status">{notice}</div>}
        <section className="panel">
          <h2>New scan</h2>
          <form className="scan-form" onSubmit={startScan}>
            <label>Scan scope<select value={scanScope} onChange={e => setScanScope(e.target.value as 'repository' | 'file')}>
              <option value="repository">Repository at pinned commit</option>
              <option value="file">One source file</option>
            </select></label>
            <label>GitHub repository URL<input type="url" placeholder="https://github.com/owner/repository" value={repoUrl} onChange={e => setRepoUrl(e.target.value)} required /></label>
            {scanScope === 'file' && <label>Affected file path<input placeholder="app/auth.py" value={affectedFile} onChange={e => setAffectedFile(e.target.value)} required /></label>}
            <button disabled={busy}>{busy ? 'Scanning…' : 'Run static scan'}</button>
          </form>
        </section>
        <div className="columns">
          <section className="panel runs"><h2>Scan history</h2>
            {scans.length === 0 ? <p className="muted">No scans yet.</p> : scans.map(scan => (
              <button key={scan.id} className={`run ${selected?.id === scan.id ? 'active' : ''}`} onClick={() => setSelected(scan)}>
                <strong>{scan.affected_file}</strong><span>{scan.repository}</span>
                <small>{scan.status} · {scan.file_count} file(s) · {scan.finding_count} potential finding(s) · {new Date(scan.created_at).toLocaleString()}</small>
              </button>
            ))}
          </section>
          <section className="panel details"><h2>Evidence</h2>
            {selected ? <>
              <p className="muted">Scan ID: {selected.id}</p>
              {selected.commit_sha && <p className="muted">Commit: <code>{selected.commit_sha}</code></p>}
              <div className="summary"><span>Status: <strong>{selected.status}</strong></span><span>Findings: <strong>{selected.finding_count}</strong></span><span>Validation: <strong>Not performed</strong></span></div>
              <button className="secondary" onClick={() => void downloadReport(selected.id, 'html')}>Download HTML report</button>
              {selected.status === 'completed' && <button className="secondary" onClick={() => void downloadReport(selected.id, 'sarif')}>Download SARIF</button>}
              {selected.findings.length === 0 ? <p className="muted">No findings recorded. This does not prove the file is secure.</p> :
                selected.findings.map((finding, index) => <article className="finding" key={`${finding.rule_id}-${index}`}>
                  <div><span className="tag">{finding.severity}</span><strong>{finding.rule_id}</strong></div>
                  <small>{finding.file}:{finding.line || '?'}</small><p>{finding.message}</p>
                </article>)}
            </> : <p className="muted">Select a scan to see its evidence.</p>}
          </section>
        </div>
      </main>
      <footer>Static analysis only · Assess repositories you are authorized to review · Manual verification required</footer>
    </div>
  )
}
