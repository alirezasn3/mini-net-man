<script>
  import { api, setUnauthorizedHandler } from './lib/api.js'
  import { app, act, refreshOverview, syncSafeTimer, setSafe, loadUpdate } from './lib/state.svelte.js'
  import Overview from './pages/Overview.svelte'
  import Interfaces from './pages/Interfaces.svelte'
  import Routes from './pages/Routes.svelte'
  import Rules from './pages/Rules.svelte'
  import Firewall from './pages/Firewall.svelte'
  import ClientRouting from './pages/ClientRouting.svelte'
  import Import from './pages/Import.svelte'
  import Settings from './pages/Settings.svelte'

  const pages = [
    { path: 'overview', label: 'Overview', comp: Overview },
    { path: 'interfaces', label: 'Interfaces', comp: Interfaces },
    { path: 'routes', label: 'Routes', comp: Routes },
    { path: 'rules', label: 'Policy rules', comp: Rules },
    { path: 'firewall', label: 'Firewall', comp: Firewall },
    { path: 'client-routing', label: 'Client routing', comp: ClientRouting },
    { path: 'import', label: 'Import', comp: Import },
    { path: 'settings', label: 'Settings', comp: Settings },
  ]

  let route = $state(location.hash.replace(/^#\/?/, '') || 'overview')
  const page = $derived(pages.find((p) => p.path === route) ?? pages[0])
  window.addEventListener('hashchange', () => (route = location.hash.replace(/^#\/?/, '') || 'overview'))

  let login = $state({ username: 'admin', password: '', error: '', busy: false })

  setUnauthorizedHandler(() => (app.user = null))

  async function boot() {
    try {
      app.user = (await api('GET', '/api/me')).user
      await refreshOverview()
      syncSafeTimer()
      loadUpdate()
    } catch {
      app.user = null
    }
    app.checked = true
  }
  boot()

  // Keep the overview (and safe-mode countdown) fresh while logged in.
  $effect(() => {
    if (!app.user) return
    const t = setInterval(async () => {
      await refreshOverview()
      syncSafeTimer()
    }, 5000)
    return () => clearInterval(t)
  })

  async function doLogin(e) {
    e.preventDefault()
    login.busy = true
    login.error = ''
    try {
      app.user = (await api('POST', '/api/login', { username: login.username, password: login.password })).user
      login.password = ''
      await refreshOverview()
      loadUpdate()
    } catch (err) {
      login.error = err.message
    }
    login.busy = false
  }

  async function safe(action, body) {
    const r = await act(() => api('POST', `/api/safe/${action}`, body))
    if (r) {
      setSafe(r)
      syncSafeTimer()
      refreshOverview()
    }
  }
</script>

{#if !app.checked}
  <div class="grid min-h-screen place-items-center text-sm text-slate-500">Loading…</div>
{:else if !app.user}
  <main class="grid min-h-screen place-items-center px-4">
    <form onsubmit={doLogin} class="card w-full max-w-sm space-y-4 p-6">
      <div>
        <h1 class="text-lg font-semibold">mini-net-man</h1>
        <p class="text-sm text-slate-500">Sign in to manage this machine's network.</p>
      </div>
      <div><label class="label" for="u">Username</label><input id="u" class="input" autocomplete="username" bind:value={login.username} /></div>
      <div><label class="label" for="p">Password</label><input id="p" type="password" class="input" autocomplete="current-password" bind:value={login.password} /></div>
      {#if login.error}<p class="text-sm text-red-600 dark:text-red-400" role="alert">{login.error}</p>{/if}
      <button class="btn btn-primary w-full" disabled={login.busy}>{login.busy ? 'Signing in…' : 'Sign in'}</button>
    </form>
  </main>
{:else}
  <div class="min-h-screen lg:grid lg:grid-cols-[14rem_1fr]">
    <aside class="border-b border-slate-800 bg-slate-950 lg:sticky lg:top-0 lg:h-screen lg:border-r lg:border-b-0">
      <div class="flex items-center gap-2 px-4 py-4">
        <span class="grid size-7 place-items-center rounded-md bg-accent-600 text-white">
          <svg viewBox="0 0 32 32" class="size-5" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 21l6-9 5 7 4-5 7 7" /></svg>
        </span>
        <div class="leading-tight">
          <div class="text-sm font-semibold">mini-net-man</div>
          <div class="text-xs text-slate-500">{app.overview?.hostname ?? ''}{app.overview?.mock ? ' · mock' : ''}</div>
          {#if app.overview?.version}<div class="mono text-xs text-slate-400">{app.overview.version}</div>{/if}
        </div>
      </div>
      <nav class="flex gap-1 overflow-x-auto px-2 pb-2 lg:flex-col lg:overflow-visible" aria-label="Main">
        {#each pages as p}
          <a href="#/{p.path}" aria-current={page.path === p.path ? 'page' : undefined}
            class="shrink-0 rounded-md px-3 py-1.5 text-sm whitespace-nowrap text-slate-400 hover:bg-slate-900 hover:text-slate-200 aria-[current=page]:bg-accent-600/15 aria-[current=page]:text-accent-300">
            {p.label}
          </a>
        {/each}
      </nav>
    </aside>

    <div class="min-w-0">
      <header class="sticky top-0 z-10 flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 bg-slate-950/90 px-5 py-3 backdrop-blur">
        <div class="flex items-center gap-3">
          <h1 class="text-base font-semibold">{page.label}</h1>
          {#if app.update?.available}
            <a href="#/settings" class="badge bg-accent-600/20 text-accent-300 hover:bg-accent-600/30">Update {app.update.latest} available</a>
          {/if}
        </div>
        {#if app.safe.active}
          <div class="flex flex-wrap items-center gap-2 rounded-lg border border-amber-400 bg-amber-50 px-3 py-1.5 text-sm dark:border-amber-700 dark:bg-amber-950/60" role="status">
            <span class="font-medium text-amber-900 dark:text-amber-200">Safe mode: changes revert in {app.safe.remaining_secs}s unless you stay connected and confirm</span>
            <button class="btn btn-primary btn-sm" onclick={() => safe('confirm')}>Keep changes</button>
            <button class="btn btn-danger btn-sm" onclick={() => safe('cancel')}>Revert</button>
          </div>
        {:else}
          <button class="btn btn-sm" onclick={() => safe('start', { timeout_secs: 30 })} title="Changes are rolled back automatically if you lose the connection or don't confirm">Enter safe mode</button>
        {/if}
      </header>

      <main class="p-5">
        {#key app.epoch}<page.comp />{/key}
      </main>
    </div>
  </div>
{/if}

<datalist id="ifaces">
  {#each app.links as l}<option value={l.name}></option>{/each}
</datalist>

<div class="pointer-events-none fixed right-4 bottom-4 z-50 flex flex-col gap-2" aria-live="polite">
  {#each app.toasts as t (t.id)}
    <div class="pointer-events-auto max-w-sm rounded-md px-3 py-2 text-sm shadow-lg {t.kind === 'error' ? 'bg-red-900 text-red-50' : 'border border-slate-700 bg-slate-800 text-slate-100'}">{t.message}</div>
  {/each}
</div>
