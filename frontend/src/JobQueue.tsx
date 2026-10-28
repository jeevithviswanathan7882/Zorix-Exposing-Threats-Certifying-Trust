import { useEffect, useRef, useState } from 'react'
import { request } from './api'

type Job = { id: string; repository: string; affected_file: string; state: string; error: string | null }
export default function JobQueue({ token, latestJob, onFinished, onError }: {
  token: string; latestJob: string; onFinished: () => void; onError: (message: string) => void
}) {
  const [jobs, setJobs] = useState<Job[]>([])
  const previous = useRef<Record<string, string>>({})
  const callbacks = useRef({ onFinished, onError })
  callbacks.current = { onFinished, onError }
  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout>
    if (latestJob) previous.current[latestJob] = 'queued'
    const poll = async () => {
      try {
        const data = await request<{ jobs: Job[] }>('/jobs', token)
        if (cancelled) return
        const received = data.jobs || []
        for (const job of received) {
          const wasPending = ['queued', 'running'].includes(previous.current[job.id])
          if (wasPending && job.state === 'completed') callbacks.current.onFinished()
          if (wasPending && ['failed', 'interrupted'].includes(job.state)) callbacks.current.onError(job.error || 'Scan job failed')
          previous.current[job.id] = job.state
        }
        setJobs(received)
      } catch (err) { if (!cancelled) callbacks.current.onError((err as Error).message) }
      if (!cancelled) timer = setTimeout(() => void poll(), 2000)
    }
    void poll()
    return () => { cancelled = true; clearTimeout(timer) }
  }, [token, latestJob])
  const cancel = async (job: Job) => {
    try {
      await request(`/jobs/${job.id}/cancel`, token, { method: 'POST' })
      setJobs(current => current.map(item => item.id === job.id ? { ...item, state: 'cancelled' } : item))
    } catch (err) { callbacks.current.onError((err as Error).message) }
  }
  return <details className="job-queue" open={jobs.some(job => ['queued', 'running'].includes(job.state))}>
    <summary>Background scan jobs · {jobs.filter(job => ['queued', 'running'].includes(job.state)).length} pending</summary>
    {jobs.length === 0 && <p className="muted">No background jobs yet.</p>}
    {jobs.map(job => <div className="job-row" key={job.id}>
      <span>{job.affected_file} · {job.state}</span>
      <small>{job.repository}</small>
      {job.error && <p>{job.error}</p>}
      {job.state === 'queued' && <button className="secondary" onClick={() => void cancel(job)}>Cancel queued scan</button>}
    </div>)}
  </details>
}
