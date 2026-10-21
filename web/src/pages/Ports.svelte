<script>
  import { api } from '../lib/api.js'
  import LiveTable from '../lib/LiveTable.svelte'

  let socks = $state([])
  let loaded = $state(false)
  let error = $state('')
  let query = $state('')
  let proto = $state('all') // all | tcp | udp
  let hideLocal = $state(false)
  let live = $state(true)

  async function load() {
    try {
      socks = await api('GET', '/api/sockets')
      error = ''
    } catch (e) {
      error = e.message
    }
    loaded = true
  }
  $effect(() => {
    load()
  })
  // Refresh while the page is open, unless switched off.
  $effect(() => {
    if (!live) return
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  })

  const shown = $derived(
    socks.filter((s) => {
      if (proto !== 'all' && !s.proto.startsWith(proto)) return false
      if (hideLocal && s.scope === 'local') return false
      const q = query.trim().toLowerCase()
      if (!q) return true
      const hay = [s.port, s.proto, s.addr, s.user, s.kernel ? 'kernel' : '', ...(s.procs ?? []).flatMap((p) => [p.name, p.pid])].join(' ').toLowerCase()
      return hay.includes(q)
    }),
  )
  const open = $derived(socks.filter((s) => s.scope === 'all').length)

  const reach = (s) => ({ all: 'all interfaces', local: 'this machine only', address: 'this address only' })[s.scope]
  const reachClass = (s) =>
    s.scope === 'all' ? 'bg-amber-500/15 text-amber-300' : 'bg-slate-800 text-slate-400'
  const process = (s) => {
    if (s.kernel) return 'kernel'
    const p = s.procs ?? []
    if (!p.length) return '—'
    return `${p[0].name} (${p[0].pid})` + (p.length > 1 ? ` +${p.length - 1}` : '')
  }
</script>

<div class="space-y-5">
  <p class="text-sm text-slate-500">
    Programs waiting for connections on this machine, like <span class="mono">ss -tulnp</span>. <b class="font-medium text-slate-300">all interfaces</b> means the port answers on every network the machine is attached to, subject to the firewall; <b class="font-medium text-slate-300">this machine only</b> means only programs on this server can reach it.
  </p>

  <section class="card">
    <header class="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-slate-800 px-4 py-3">
      <h2 class="mr-auto text-sm font-semibold">
        Listening <span class="ml-1 font-normal text-slate-500">{shown.length}{shown.length !== socks.length ? ` of ${socks.length}` : ''}</span>
        {#if open}<span class="ml-2 font-normal text-slate-500">· {open} on all interfaces</span>{/if}
      </h2>
      <label class="flex items-center gap-1.5 text-xs text-slate-400"><input type="checkbox" class="size-3.5 accent-accent-600" bind:checked={live} /> Live</label>
      <button class="btn btn-sm" onclick={load}>Refresh</button>
    </header>

    <div class="flex flex-wrap items-center gap-3 border-b border-slate-800 px-4 py-3">
      <input class="input max-w-56 py-1 text-xs" type="search" placeholder="Search port, program, address…" aria-label="Search" bind:value={query} />
      <div class="flex gap-1" role="group" aria-label="Protocol">
        {#each ['all', 'tcp', 'udp'] as p}
          <button class="btn btn-sm {proto === p ? 'btn-primary' : 'btn-ghost'}" aria-pressed={proto === p} onclick={() => (proto = p)}>{p === 'all' ? 'All' : p.toUpperCase()}</button>
        {/each}
      </div>
      <label class="flex items-center gap-1.5 text-xs text-slate-400"><input type="checkbox" class="size-3.5 accent-accent-600" bind:checked={hideLocal} /> Hide this-machine-only</label>
    </div>

    {#if error}
      <p class="px-4 py-3 text-sm text-red-400">{error}</p>
    {:else if loaded}
      <LiveTable
        rows={shown}
        empty="No listening sockets match."
        columns={[
          { label: 'Port', key: 'port', mono: true },
          { label: 'Proto', key: 'proto', mono: true },
          { label: 'Address', key: 'addr', mono: true },
          { label: 'Reachable from', render: reach, badge: reachClass },
          { label: 'Program', render: process, mono: true },
          { label: 'User', key: 'user' },
        ]}
      />
    {/if}
  </section>
</div>
