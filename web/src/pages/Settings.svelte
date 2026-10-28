<script>
  import { api } from '../lib/api.js'
  import { app, act, loadUpdate, toast } from '../lib/state.svelte.js'

  let web = $state({ listen: '', port: 8080, allowed_ips: '', users: [], tls: false })
  let pw = $state({ old: '', new: '', again: '' })
  let un = $state({ password: '', name: '' })
  let tokens = $state([])
  let tk = $state({ name: '', read_only: false, password: '' })
  let fresh = $state(null) // the token just made: its secret is shown once
  const origin = location.origin

  async function load() {
    const w = await api('GET', '/api/settings/web')
    web = { ...w, allowed_ips: (w.allowed_ips ?? []).join('\n') }
  }
  async function loadTokens() {
    tokens = await api('GET', '/api/tokens').catch(() => [])
  }
  $effect(() => {
    load()
    loadTokens()
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
  async function changeName(e) {
    e.preventDefault()
    const r = await act(() => api('POST', '/api/username', { password: un.password, new: un.name }), 'Username changed')
    if (r) {
      app.user = r.user
      un = { password: '', name: '' }
      load()
    }
  }
  async function makeToken(e) {
    e.preventDefault()
    const r = await act(() => api('POST', '/api/tokens', { name: tk.name, read_only: tk.read_only, password: tk.password }), 'Token created')
    if (r) {
      fresh = r
      tk = { name: '', read_only: false, password: '' }
      loadTokens()
    }
  }
  async function deleteToken(t) {
    if (!confirm(`Delete the token "${t.name}"? Anything using it stops working at once.`)) return
    if (await act(() => api('DELETE', `/api/tokens/${t.id}`), 'Token deleted')) {
      if (fresh?.id === t.id) fresh = null
      loadTokens()
    }
  }
  async function copyToken() {
    try {
      await navigator.clipboard.writeText(fresh.token)
      toast('Copied')
    } catch {
      toast('Select the token and copy it by hand', 'error')
    }
  }
  const day = (s) => (s ? new Date(s).toLocaleDateString() : '')

  let checking = $state(false)
  let installing = $state(false)
  const up = $derived(app.update)
  $effect(() => {
    loadUpdate()
  })

  async function checkNow() {
    checking = true
    await loadUpdate(true)
    checking = false
    if (app.update?.error) toast(app.update.error, 'error')
    else if (!app.update?.available) toast('You are on the latest version')
  }
  async function installUpdate() {
    if (!confirm(`Update to ${up.latest}? mini-net-man restarts; your routes, rules and firewall stay in place while it does, and you will need to log in again.`)) return
    installing = true
    const res = await act(() => api('POST', '/api/update/install'))
    if (!res) {
      installing = false
      return
    }
    if (res.restarting) {
      toast(`Updated to ${res.version}. Restarting…`)
      setTimeout(() => location.reload(), 3500)
    } else {
      installing = false
      toast(`Installed ${res.version}. Restart mini-net-man to use it.`)
      loadUpdate(true)
    }
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
    <p class="hint -mt-2">0.0.0.0 listens on every IPv4 address, :: on IPv4 and IPv6, 127.0.0.1 only on this machine. Address and port change after a restart.</p>
    <div>
      <label class="label" for="ips">Allowed client IPs (one per line, IPs or CIDRs)</label>
      <textarea id="ips" rows="4" class="input mono" bind:value={web.allowed_ips} placeholder="203.0.113.7&#10;198.51.100.0/24"></textarea>
      <p class="hint">IPv4 or IPv6. Other addresses get no answer at all. An empty list allows only localhost. To serve IPv6, set the listen address to <span class="mono">::</span> (dual-stack).</p>
    </div>
    <p class="text-xs text-slate-500">{web.tls ? 'TLS is on (set in the config file).' : 'Served over plain HTTP. Set tls_cert and tls_key in the config file, or put it behind something that terminates TLS.'}</p>
    <button class="btn btn-primary">Save</button>
  </form>

  <form class="card space-y-4 p-4" onsubmit={changeName}>
    <h2 class="text-sm font-semibold">Username</h2>
    <p class="text-sm text-slate-500">You are signed in as <span class="mono">{app.user}</span>. You stay signed in after changing it.</p>
    <div><label class="label" for="newname">New username</label><input id="newname" class="input" autocomplete="off" spellcheck="false" bind:value={un.name} /><p class="hint">1 to 32 characters, no spaces.</p></div>
    <div><label class="label" for="unpw">Your password</label><input id="unpw" type="password" autocomplete="current-password" class="input" bind:value={un.password} /></div>
    <button class="btn btn-primary">Change username</button>
  </form>

  <form class="card space-y-4 p-4" onsubmit={changePw}>
    <h2 class="text-sm font-semibold">Password for {app.user}</h2>
    <div><label class="label" for="old">Current password</label><input id="old" type="password" autocomplete="current-password" class="input" bind:value={pw.old} /></div>
    <div><label class="label" for="new">New password</label><input id="new" type="password" autocomplete="new-password" class="input" bind:value={pw.new} /><p class="hint">At least 8 characters. You will be logged out everywhere afterwards.</p></div>
    <div><label class="label" for="again">Repeat new password</label><input id="again" type="password" autocomplete="new-password" class="input" bind:value={pw.again} /></div>
    <div class="flex gap-2">
      <button class="btn btn-primary">Change password</button>
      <button type="button" class="btn" onclick={logout}>Log out</button>
    </div>
  </form>

  <section class="card space-y-4 p-4 lg:col-span-2">
    <h2 class="text-sm font-semibold">API tokens</h2>
    <p class="text-sm text-slate-500">
      Everything this panel does is also an HTTP API, so other programs can use it. Give each program its own token and send it as
      <span class="mono">Authorization: Bearer &lt;token&gt;</span>. A <b>read-only</b> token can only look. No token can change logins, tokens or the allowed IPs, or update the program. The caller's address must also be in <b>Allowed client IPs</b>.
    </p>
    {#if fresh}
      <div class="space-y-2 rounded-md border border-accent-600/40 bg-accent-600/10 p-3">
        <p class="text-sm">Token <b>{fresh.name}</b> is ready. Copy it now: it is not stored and can't be shown again.</p>
        <div class="flex flex-wrap items-center gap-2">
          <input class="input mono min-w-0 flex-1" readonly value={fresh.token} aria-label="New token" onfocus={(e) => e.currentTarget.select()} />
          <button type="button" class="btn btn-sm" onclick={copyToken}>Copy</button>
          <button type="button" class="btn btn-ghost btn-sm" onclick={() => (fresh = null)}>Done</button>
        </div>
        <pre class="mono overflow-auto rounded-md bg-slate-950 p-3 text-xs whitespace-pre-wrap">curl -H "Authorization: Bearer {fresh.token}" {origin}/api/routes</pre>
      </div>
    {/if}
    {#if tokens.length}
      <ul class="divide-y divide-slate-200 text-sm dark:divide-slate-800">
        {#each tokens as t (t.id)}
          <li class="flex flex-wrap items-center justify-between gap-2 py-2">
            <span class="min-w-0">
              <b>{t.name}</b>
              <span class="mono ml-2 text-slate-500">{t.prefix}…</span>
              {#if t.read_only}<span class="badge ml-2 bg-slate-800 text-slate-400">read-only</span>{/if}
              <span class="ml-2 text-xs text-slate-500">created {day(t.created)}</span>
            </span>
            <button class="btn btn-ghost btn-sm text-red-600 dark:text-red-400" onclick={() => deleteToken(t)}>Delete</button>
          </li>
        {/each}
      </ul>
    {:else}
      <p class="text-sm text-slate-500">No tokens yet.</p>
    {/if}
    <form class="grid items-end gap-3 sm:grid-cols-[1fr_1fr_auto]" onsubmit={makeToken}>
      <div><label class="label" for="tkname">Name</label><input id="tkname" class="input" autocomplete="off" placeholder="grafana, backup script" bind:value={tk.name} /></div>
      <div><label class="label" for="tkpw">Your password</label><input id="tkpw" type="password" autocomplete="current-password" class="input" bind:value={tk.password} /></div>
      <button class="btn btn-primary">Create token</button>
      <label class="flex items-center gap-2 text-sm sm:col-span-3"><input type="checkbox" class="size-4 accent-accent-600" bind:checked={tk.read_only} /> Read-only (can look, can't change anything)</label>
    </form>
  </section>

  <section class="card space-y-3 p-4 lg:col-span-2">
    <div class="flex flex-wrap items-center justify-between gap-2">
      <h2 class="text-sm font-semibold">Updates</h2>
      <button class="btn btn-sm" onclick={checkNow} disabled={checking || installing}>{checking ? 'Checking…' : 'Check now'}</button>
    </div>
    {#if up}
      <dl class="grid max-w-md grid-cols-[8rem_1fr] gap-y-1 text-sm">
        <dt class="text-slate-500">Installed</dt>
        <dd class="mono">{up.current}</dd>
        <dt class="text-slate-500">Latest release</dt>
        <dd class="mono">
          {#if up.latest}
            {#if up.url}<a class="underline decoration-slate-400 underline-offset-2 hover:text-accent-300" href={up.url} target="_blank" rel="noreferrer noopener">{up.latest}</a>{:else}{up.latest}{/if}
            {#if up.available}<span class="badge ml-2 bg-accent-600/20 text-accent-300">newer</span>{:else if up.can_install}<span class="badge ml-2 bg-slate-800 text-slate-400">up to date</span>{/if}
          {:else}
            <span class="text-slate-400">not checked</span>
          {/if}
        </dd>
      </dl>
      {#if up.error}<p class="text-sm text-red-600 dark:text-red-400">{up.error}</p>{/if}
      {#if up.pending}
        <p class="text-sm">Version <span class="mono">{up.pending}</span> is installed. Restart mini-net-man to run it: <span class="mono">sudo systemctl restart mini-net-man</span>.</p>
      {:else if up.available && up.can_install}
        <button class="btn btn-primary" onclick={installUpdate} disabled={installing}>{installing ? 'Installing…' : `Update to ${up.latest}`}</button>
      {:else if up.available}
        <p class="text-sm text-slate-500">A newer version exists, but it can't be installed from here: {up.reason}.</p>
      {:else if !up.can_install && up.reason}
        <p class="text-xs text-slate-500">Installing from the panel is unavailable: {up.reason}.</p>
      {/if}
      {#if up.available && !up.pending && up.notes}
        <details class="text-sm">
          <summary class="cursor-pointer text-slate-500">Release notes</summary>
          <pre class="mono mt-2 max-h-64 overflow-auto whitespace-pre-wrap rounded-md bg-slate-100 p-3 dark:bg-slate-950">{up.notes}</pre>
        </details>
      {/if}
      <p class="text-xs text-slate-500">
        Updates come from GitHub Releases. The binary is checked against the release's checksums and test-run before it replaces the old one, which is kept for <span class="mono">mini-net-man update -rollback</span>.
        {up.auto_check ? 'The latest version is looked up when you log in.' : 'Automatic lookup is off (update.no_auto_check in the config).'}
      </p>
    {/if}
  </section>
</div>
