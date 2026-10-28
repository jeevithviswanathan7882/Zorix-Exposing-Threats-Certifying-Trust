import { FormEvent, useCallback, useEffect, useRef, useState } from 'react'
import './App.css'
import './Comparison.css'
import './Review.css'
import { API, request } from './api'
import JobQueue from './JobQueue'

type Finding = { rule_id: string; file: string; line: number | null; severity: string; message: string; package?: { PkgName: string; InstalledVersion: string; FixedVersion: string } }
type Scan = {
  id: string
  repository: string
  affected_file: string
  status: string
  finding_count: number
  findings: Finding[]
  commit_sha: string | null
  rules_sha256?: string | null
  imported?: boolean
  source_tools?: string[]
  artifact_sha256?: string
  file_count: number
  created_at: string
}
type Comparison = { introduced: Finding[]; resolved: Finding[]; introduced_count: number; resolved_count: number; unchanged_count: number; note: string }
type ReviewStatus = 'open' | 'investigating' | 'false_positive' | 'accepted_risk'
type Review = { finding_index: number; status: ReviewStatus; note: string }
type ReviewEvent = { id: string; status: ReviewStatus; note: string; event_type: string; created_at: string }

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('zorix_token') || '')
  const [email, setEmail] = useState(localStorage.getItem('zorix_email') || '')
  const [password, setPassword] = useState('')
  const [registering, setRegistering] = useState(false)
  const [repoUrl, setRepoUrl] = useState('')
  const [affectedFile, setAffectedFile] = useState('')
  const [githubToken, setGithubToken] = useState('')
  const [scanScope, setScanScope] = useState<'repository' | 'file'>('repository')
  const [scans, setScans] = useState<Scan[]>([])
  const [selected, setSelected] = useState<Scan | null>(null)
  const [baselineId, setBaselineId] = useState('')
  const [comparison, setComparison] = useState<Comparison | null>(null)
  const [reviews, setReviews] = useState<Record<number, Review>>({})
  const [reviewHistory, setReviewHistory] = useState<Record<string, ReviewEvent[]>>({})
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [latestJob, setLatestJob] = useState('')
  const [importReport, setImportReport] = useState('')
  const [importCommit, setImportCommit] = useState('')
  const [importFormat, setImportFormat] = useState('sarif')
  const importReadVersion = useRef(0)

  useEffect(() => {
    const expireSession = () => {
      setToken('')
      setScans([])
      setSelected(null)
      setGithubToken('')
      setPassword('')
      setNotice('')
      setImportReport('')
      importReadVersion.current += 1
      setError('Session expired. Sign in again.')
    }
    window.addEventListener('zorix:session-expired', expireSession)
    return () => window.removeEventListener('zorix:session-expired', expireSession)
  }, [])

  const loadScans = useCallback(async (preferLatest = false) => {
    if (!token) return
    try {
      const data = await request<{ results: Scan[] }>('/analysis/results', token)
      setScans(data.results)
      setSelected(current => (preferLatest ? data.results[0] : data.results.find(item => item.id === current?.id) || data.results[0]) || null)
    } catch (err) {
      if ((err as Error).name === 'AbortError') return
      setError((err as Error).message)
    }
  }, [token])

  useEffect(() => { void loadScans() }, [loadScans])
  useEffect(() => { setBaselineId(''); setComparison(null); setReviewHistory({}) }, [selected?.id])
  useEffect(() => {
    if (!selected || !token) return
    let cancelled = false
    setReviews({})
    void request<{ reviews: Review[] }>(`/analysis/results/${selected.id}`, token)
      .then(data => {
        if (!cancelled) setReviews(Object.fromEntries(data.reviews.map(review => [review.finding_index, review])))
      })
      .catch(err => { if (!cancelled) setError((err as Error).message) })
    return () => { cancelled = true }
  }, [selected?.id, token])

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
      const result = await request<{ id: string }>('/jobs', token, {
        method: 'POST', body: JSON.stringify({ repo_url: repoUrl,
          affected_file: scanScope === 'repository' ? '(repository)' : affectedFile,
          ...(githubToken ? { github_token: githubToken } : {}),
        }),
      })
      setLatestJob(result.id)
      setNotice('Scan queued. Job status updates below; completed evidence will load automatically.')
    } catch (err) { setError((err as Error).message) }
    finally { setGithubToken(''); setBusy(false) }
  }

  const downloadReport = async (id: string, format: 'html' | 'sarif' | 'json') => {
    setError('')
    try {
      const response = await fetch(`${API}/analysis/reports/${id}/${format}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (localStorage.getItem('zorix_token') !== token) return
      if (response.status === 401) {
        localStorage.removeItem('zorix_token')
        window.dispatchEvent(new Event('zorix:session-expired'))
        throw new Error('Session expired. Sign in again.')
      }
      if (!response.ok) throw new Error(`Report request failed (${response.status})`)
      const blob = await response.blob()
      if (localStorage.getItem('zorix_token') !== token) return
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `zorix-${id}.${format}`
      link.click()
      URL.revokeObjectURL(url)
    } catch (err) { setError((err as Error).message) }
  }

  const compareScans = async () => {
    if (!selected || !baselineId) return
    setError('')
    try {
      setComparison(await request<Comparison>(
        `/analysis/results/${selected.id}/compare/${baselineId}`, token,
      ))
    } catch (err) { setError((err as Error).message) }
  }

  const saveReview = async (index: number) => {
    if (!selected) return
    const review = reviews[index] || { finding_index: index, status: 'open', note: '' }
    setError(''); setNotice('')
    try {
      const saved = await request<Review>(
        `/analysis/results/${selected.id}/findings/${index}/review`, token,
        { method: 'PUT', body: JSON.stringify({ status: review.status, note: review.note }) },
      )
      setReviews(current => ({ ...current, [index]: saved }))
      setNotice('Finding review saved.')
      setReviewHistory({})
    } catch (err) { setError((err as Error).message) }
  }

  const signOut = () => {
    localStorage.removeItem('zorix_token')
    localStorage.removeItem('zorix_email')
    setToken(''); setScans([]); setSelected(null); setError(''); setNotice('')
    setGithubToken(''); setPassword(''); setRepoUrl(''); setAffectedFile('')
    setReviews({}); setComparison(null); setBaselineId('')
    setImportReport(''); setImportCommit(''); setLatestJob('')
    importReadVersion.current += 1
  }

  const importEvidence = async (event: FormEvent) => {
    event.preventDefault()
    setBusy(true); setError(''); setNotice('')
    try {
      await request('/analysis/import', token, { method: 'POST', body: JSON.stringify({
        repo_url: repoUrl, commit_sha: importCommit, report_format: importFormat,
        report: importFormat === 'nuclei' ? { results: importReport.split('\n').filter(line => line.trim()).map(line => JSON.parse(line)) }
          : importFormat === 'gitleaks' ? { findings: JSON.parse(importReport) }
          : importFormat === 'checkov' && Array.isArray(JSON.parse(importReport)) ? { reports: JSON.parse(importReport) }
          : JSON.parse(importReport),
      }) })
      setImportReport('')
      await loadScans(true)
      setNotice('Tool report imported. Repository and commit association are supplied by the uploader; review the evidence.')
    } catch (err) { setError((err as Error).message) }
    finally { setBusy(false) }
  }

  const loadReviewHistory = async (index: number) => {
    if (!selected) return
    const historyKey = `${selected.id}:${index}`
    try {
      const data = await request<{ events: ReviewEvent[] }>(
        `/analysis/results/${selected.id}/findings/${index}/history`, token,
      )
      setReviewHistory(current => ({ ...current, [historyKey]: data.events }))
    } catch (err) { setError((err as Error).message) }
  }

  if (!token) return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="brand">ZOR<span>IX</span></div>
        <div className="brand-caption">// SECURITY VALIDATION</div>
        <div className="auth-kicker">SECURE ACCESS / 01</div>
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
      <aside className="sidebar">
        <div className="sidebar-brand"><div className="brand">ZOR<span>IX</span></div><div className="brand-caption">// SECURITY VALIDATION</div></div>
        <nav aria-label="Main navigation">
          <span className="nav-caption">// CORE</span>
          <a href="#overview" className="nav-link active"><span aria-hidden="true">◈</span> Dashboard</a>
          <a href="#new-scan" className="nav-link"><span aria-hidden="true">⌕</span> New scan</a>
          <a href="#scan-history" className="nav-link"><span aria-hidden="true">▤</span> Scan history <b>{scans.length}</b></a>
          <a href="#evidence" className="nav-link"><span aria-hidden="true">◇</span> Evidence</a>
        </nav>
        <div className="sidebar-account"><span className="nav-caption">// ANALYST</span><strong>{email.split('@')[0]}</strong><small>{email}</small><button className="text-button" onClick={signOut}>⏻ Sign out</button></div>
      </aside>
      <div className="workspace">
      <header className="topbar"><div><span className="eyebrow">// ZORIX / WORKSPACE</span><strong>DASHBOARD</strong></div><div className="topbar-right"><span className="engine-badge"><i /> SEMGREP ANALYSIS</span><span className="account-email">{email}</span></div></header>
      <main id="overview">
        <div className="intro">
          <div><span className="eyebrow">// REPOSITORY ANALYSIS</span><h1>EXPOSE THREATS. <em>CERTIFY TRUST.</em></h1>
          <p>Scan GitHub source or import security tool reports. Review source, dependency, infrastructure, secret-detection, and web-testing evidence before reporting risk.</p></div>
          <div className="count"><span>TOTAL SCANS</span><strong>{String(scans.length).padStart(2, '0')}</strong><span>YOUR WORKSPACE</span></div>
        </div>
        {error && <div className="error" role="alert">{error}</div>}
        {notice && <div className="notice" role="status">{notice}</div>}
        <section className="panel" id="new-scan">
          <h2>New scan</h2>
          <form className={`scan-form ${scanScope === 'file' ? 'file-scope' : ''}`} onSubmit={startScan}>
            <label>Scan scope<select value={scanScope} onChange={e => setScanScope(e.target.value as 'repository' | 'file')}>
              <option value="repository">Repository at pinned commit</option>
              <option value="file">One source file</option>
            </select></label>
            <label>GitHub repository URL<input type="url" placeholder="https://github.com/owner/repository" value={repoUrl} onChange={e => setRepoUrl(e.target.value)} required /></label>
            {scanScope === 'file' && <label>Affected file path<input placeholder="app/auth.py" value={affectedFile} onChange={e => setAffectedFile(e.target.value)} required /></label>}
            <label>GitHub token (optional)<input type="password" autoComplete="off" value={githubToken} onChange={e => setGithubToken(e.target.value)} /></label>
            <button disabled={busy}>{busy ? 'Scanning…' : 'Run static scan'}</button>
          </form>
          <JobQueue token={token} latestJob={latestJob} onFinished={() => void loadScans(true)} onError={setError} />
        </section>
        <details className="panel import-panel">
          <summary>Import a security tool report</summary>
          <p className="muted">SARIF, Trivy, Bandit, Gitleaks, Checkov, ZAP, or Nuclei · maximum 1 MB · imported evidence requires review</p>
          <form className="scan-form" onSubmit={importEvidence}>
            <label>Import repository URL<input type="url" required value={repoUrl} onChange={e => setRepoUrl(e.target.value)} /></label>
            <label>Reported commit SHA<input required pattern="[a-fA-F0-9]{40}" value={importCommit} onChange={e => setImportCommit(e.target.value)} /></label>
            <label>Report format<select value={importFormat} onChange={e => setImportFormat(e.target.value)}><option value="sarif">SARIF 2.1.0</option><option value="trivy">Trivy JSON</option><option value="bandit">Bandit JSON</option><option value="gitleaks">Gitleaks JSON</option><option value="checkov">Checkov JSON</option><option value="zap">OWASP ZAP JSON</option><option value="nuclei">Nuclei JSONL</option></select></label>
            <label>Report JSON file<input type="file" accept=".json,.jsonl,.sarif,application/json" onChange={async e => {
              const file = e.target.files?.[0]
              const version = ++importReadVersion.current
              setImportReport('')
              if (!file) return
              if (file.size > 900000) { setError('Choose a report below 900 KB to leave room for request metadata.'); return }
              try {
                const content = await file.text()
                if (version === importReadVersion.current && localStorage.getItem('zorix_token') === token) setImportReport(content)
              } catch { setError('Could not read the report file.') }
            }} /></label>
            <button disabled={busy || !importReport}>Import report</button>
          </form>
        </details>
        <div className="columns">
          <section className="panel runs" id="scan-history"><h2>Scan history</h2>
            {scans.length === 0 ? <p className="muted">No scans yet.</p> : scans.map(scan => (
              <button key={scan.id} className={`run ${selected?.id === scan.id ? 'active' : ''}`} onClick={() => setSelected(scan)}>
                <strong>{scan.affected_file}</strong><span>{scan.repository}</span>
                <small>{scan.status} · {scan.file_count} file(s) · {scan.finding_count} potential finding(s) · {new Date(scan.created_at).toLocaleString()}</small>
              </button>
            ))}
          </section>
          <section className="panel details" id="evidence"><h2>Evidence</h2>
            {selected ? <>
              <p className="muted">Scan ID: {selected.id}</p>
              {selected.commit_sha && <p className="muted">Commit: <code>{selected.commit_sha}</code></p>}
              {selected.rules_sha256 && <p className="muted">Rules SHA-256: <code>{selected.rules_sha256}</code></p>}
              {selected.imported && <p className="muted">Imported evidence · {selected.source_tools?.join(', ')} · Commit supplied by uploader</p>}
              {selected.artifact_sha256 && <p className="muted">Artifact SHA-256: <code>{selected.artifact_sha256}</code></p>}
              <div className="summary"><span>Status: <strong>{selected.status}</strong></span><span>Findings: <strong>{selected.finding_count}</strong></span><span>Validation: <strong>Not performed</strong></span></div>
              <button className="secondary" onClick={() => void downloadReport(selected.id, 'html')}>Download HTML report</button>
              <button className="secondary" onClick={() => void downloadReport(selected.id, 'json')}>Download security JSON</button>
              {selected.status === 'completed' && <button className="secondary" onClick={() => void downloadReport(selected.id, 'sarif')}>Download SARIF</button>}
              {selected.status === 'completed' && scans.some(scan => scan.id !== selected.id && scan.repository === selected.repository && scan.affected_file === selected.affected_file && scan.status === 'completed') && <div className="comparison-controls">
                <label>Compare with a scan of this repository<select value={baselineId} onChange={e => { setBaselineId(e.target.value); setComparison(null) }}>
                  <option value="">Choose baseline scan</option>
                  {scans.filter(scan => scan.id !== selected.id && scan.repository === selected.repository && scan.affected_file === selected.affected_file && scan.status === 'completed').map(scan =>
                    <option key={scan.id} value={scan.id}>{scan.affected_file} · {new Date(scan.created_at).toLocaleString()}</option>)}
                </select></label>
                <button className="secondary" disabled={!baselineId} onClick={() => void compareScans()}>Compare findings</button>
              </div>}
              {comparison && <div className="comparison-result" role="status">
                <p>{comparison.introduced_count} introduced · {comparison.resolved_count} resolved · {comparison.unchanged_count} unchanged</p>
                <p className="muted">{comparison.note}</p>
                {comparison.introduced.map((finding, index) => <p key={`new-${index}`}>New: {finding.rule_id} in {finding.file}:{finding.line}</p>)}
                {comparison.resolved.map((finding, index) => <p key={`old-${index}`}>Gone: {finding.rule_id} in {finding.file}:{finding.line}</p>)}
              </div>}
              {selected.findings.length === 0 ? <p className="muted">No findings recorded. This does not prove the file is secure.</p> :
                selected.findings.map((finding, index) => <article className="finding" key={`${finding.rule_id}-${index}`}>
                  <div><span className="tag">{finding.severity}</span><strong>{finding.rule_id}</strong></div>
                  <small>{finding.file}{finding.line ? `:${finding.line}` : ''}</small><p>{finding.message}</p>
                  {finding.package && <p>Package: {finding.package.PkgName} · Installed: {finding.package.InstalledVersion} · Fixed: {finding.package.FixedVersion || 'Not provided'}</p>}
                  <div className="review-controls">
                    <label>Review status<select value={reviews[index]?.status || 'open'} onChange={event =>
                      setReviews(current => ({ ...current, [index]: {
                        finding_index: index, status: event.target.value as ReviewStatus,
                        note: current[index]?.note || '',
                      } }))}>
                      <option value="open">Open</option><option value="investigating">Investigating</option>
                      <option value="false_positive">False positive</option><option value="accepted_risk">Accepted risk</option>
                    </select></label>
                    <label>Review note<textarea maxLength={2000} value={reviews[index]?.note || ''} onChange={event =>
                      setReviews(current => ({ ...current, [index]: {
                        finding_index: index, status: current[index]?.status || 'open',
                        note: event.target.value,
                      } }))} /></label>
                    <button className="secondary" onClick={() => void saveReview(index)}>Save review</button>
                  </div>
                  <button className="secondary" onClick={() => void loadReviewHistory(index)}>View review history</button>
                  {reviewHistory[`${selected.id}:${index}`] && <ol aria-label={`Review history for finding ${index + 1}`}>
                    {reviewHistory[`${selected.id}:${index}`].length === 0 && <li>No review history recorded.</li>}
                    {reviewHistory[`${selected.id}:${index}`].map(event => <li key={event.id}>
                      <strong>{event.status.replace(/_/g, ' ')}</strong> · {new Date(event.created_at + (event.created_at.endsWith('Z') ? '' : 'Z')).toLocaleString()}
                      {event.event_type === 'baseline_import' && ' · Imported baseline'}
                      <p>{event.note || 'No note'}</p>
                    </li>)}
                  </ol>}
                </article>)}
            </> : <p className="muted">Select a scan to see its evidence.</p>}
          </section>
        </div>
      </main>
      <footer>Authorized assets only · Imported reports are unverified · Manual verification required</footer>
      </div>
    </div>
  )
}
