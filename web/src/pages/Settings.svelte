<script>
  import { api } from '../lib/api.js'
  import { app, act } from '../lib/state.svelte.js'

  let web = $state({ listen: '', port: 8080, allowed_ips: '', users: [], tls: false })
  let pw = $state({ old: '', new: '', again: '' })

  async function load() {
    const w = await api('GET', '/api/settings/web')
    web = { ...w, allowed_ips: (w.allowed_ips ?? []).join('\n') }
  }
  $effect(() => {
    load()
  })

  async function saveWeb(e) {
    e.preventDefault()
    const ips = web.allowed_ips.split(/[\s,]+/).filter(Boolean)
    await act(() => api('PUT', '/api/settings/web', { listen: web.listen, port: Number(web.port), allowed_ips: ips }), 'Saved. Address and port apply after a restart; allowed IPs apply now.')
    load()
  }
  async function changePw(e) {
    e.preventDefault()
    if (pw.new !== pw.again) return act(() => Promise.reject(new Error('Passwords do not match')))
    if (await act(() => api('POST', '/api/password', { old: pw.old, new: pw.new }), 'Password changed. Please log in again.')) location.reload()
  }
  async function logout() {
    await api('POST', '/api/logout').catch(() => {})
    location.reload()
  }
</script>

<div class="grid max-w-4xl gap-5 lg:grid-cols-2">
  <form class="card space-y-4 p-4" onsubmit={saveWeb}>
    <h2 class="text-sm font-semibold">Web panel</h2>
    <div class="grid grid-cols-3 gap-3">
      <div class="col-span-2"><label class="label" for="listen">Listen address</label><input id="listen" class="input mono" bind:value={web.listen} /></div>
      <div><label class="label" for="port">Port</label><input id="port" type="number" class="input" bind:value={web.port} /></div>
    </div>
    <div>
      <label class="label" for="ips">Allowed client IPs (one per line, IPs or CIDRs)</label>
      <textarea id="ips" rows="4" class="input mono" bind:value={web.allowed_ips} placeholder="203.0.113.7&#10;198.51.100.0/24"></textarea>
      <p class="mt-1 text-xs text-slate-500">IPv4 or IPv6. Other addresses get no answer at all. An empty list allows only localhost. To serve IPv6, set the listen address to <span class="mono">::</span> (dual-stack).</p>
    </div>
    <p class="text-xs text-slate-500">{web.tls ? 'TLS is on (set in the config file).' : 'Served over plain HTTP. Set tls_cert and tls_key in the config file, or put it behind something that terminates TLS.'}</p>
    <button class="btn btn-primary">Save</button>
  </form>

  <form class="card space-y-4 p-4" onsubmit={changePw}>
    <h2 class="text-sm font-semibold">Password for {app.user}</h2>
    <div><label class="label" for="old">Current password</label><input id="old" type="password" autocomplete="current-password" class="input" bind:value={pw.old} /></div>
    <div><label class="label" for="new">New password</label><input id="new" type="password" autocomplete="new-password" class="input" bind:value={pw.new} /></div>
    <div><label class="label" for="again">Repeat new password</label><input id="again" type="password" autocomplete="new-password" class="input" bind:value={pw.again} /></div>
    <div class="flex gap-2">
      <button class="btn btn-primary">Change password</button>
      <button type="button" class="btn" onclick={logout}>Log out</button>
    </div>
  </form>
</div>
