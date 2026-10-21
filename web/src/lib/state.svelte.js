import { api } from './api.js'

export const app = $state({
  user: null,
  checked: false,
  overview: null,
  issues: [],
  safe: { active: false, remaining_secs: 0, timeout_secs: 30 },
  toasts: [],
  links: [],
  update: null, // latest result of GET /api/update
  epoch: 0, // bumped when state may have changed under the pages (safe-mode rollback)
})

// Record safe-mode status; when a session ends, tell pages to reload.
export function setSafe(next) {
  if (app.safe.active && !next.active) app.epoch++
  app.safe = next
}

let toastId = 0
export function toast(message, kind = 'ok') {
  const id = ++toastId
  app.toasts.push({ id, message, kind })
  setTimeout(() => (app.toasts = app.toasts.filter((t) => t.id !== id)), kind === 'error' ? 6000 : 2500)
}

// Run an API call, surface errors as toasts and apply-issues in app.issues.
export async function act(fn, success) {
  try {
    const res = await fn()
    if (res && Array.isArray(res.issues)) app.issues = res.issues
    if (success) toast(success)
    return res ?? true
  } catch (e) {
    toast(e.message, 'error')
    return null
  }
}

export async function refreshOverview() {
  try {
    const o = await api('GET', '/api/overview')
    app.overview = o
    app.issues = o.issues
    setSafe(o.safe)
    app.links = o.links
  } catch {}
}

export const issuesFor = (id) => app.issues.filter((i) => i.id === id)

// While safe mode is on, ping the server so it knows we are still here.
let beat
export function syncSafeTimer() {
  if (app.safe.active && !beat) {
    beat = setInterval(async () => {
      try {
        setSafe(await api('POST', '/api/safe/heartbeat'))
        if (!app.safe.active) syncSafeTimer()
      } catch {}
    }, 4000)
  } else if (!app.safe.active && beat) {
    clearInterval(beat)
    beat = null
  }
}

// Ask the server about updates. Without `refresh` it answers from its cache.
export async function loadUpdate(refresh = false) {
  try {
    app.update = await api('GET', '/api/update' + (refresh ? '?refresh=1' : ''))
  } catch {}
  return app.update
}
