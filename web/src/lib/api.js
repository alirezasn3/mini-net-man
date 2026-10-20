export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

let onUnauthorized = () => {}
export const setUnauthorizedHandler = (fn) => (onUnauthorized = fn)

// All calls are JSON. Non-GET requests always carry a JSON content type,
// which the server requires as a CSRF guard.
export async function api(method, path, body) {
  const init = { method, credentials: 'same-origin', headers: {} }
  if (method !== 'GET') {
    init.headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(body ?? {})
  }
  let res
  try {
    res = await fetch(path, init)
  } catch {
    throw new ApiError('Cannot reach the server', 0)
  }
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    if (res.status === 401 && path !== '/api/login') onUnauthorized()
    throw new ApiError(data.error || `${res.status} ${res.statusText}`, res.status)
  }
  return data
}
