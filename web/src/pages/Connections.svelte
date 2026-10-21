<script>
  import { api } from '../lib/api.js'
  import { act } from '../lib/state.svelte.js'
  import LiveTable from '../lib/LiveTable.svelte'

  let data = $state(null)
  let error = $state('')
  let kind = $state('') // '' | forwarded | incoming | outgoing
  let proto = $state('')
  let stateF = $state('')
  let client = $state('')
  let sort = $state('client')
  let q = $state('')
  let qNow = $state('') // q after a short pause, so typing doesn't fire a request per key
  let live = $state(true)

  $effect(() => {
    const v = q
    const t = setTimeout(() => (qNow = v), 300)
    return () => clearTimeout(t)
  })

  const query = $derived(
    new URLSearchParams(Object.entries({ kind, proto, state: stateF, client, sort, q: qNow }).filter(([, v]) => v)).toString(),
  )

  async function load() {
    try {
      data = await api('GET', '/api/connections' + (query ? '?' + query : ''))
      error = ''
    } catch (e) {
      error = e.message
    }
  }
  $effect(() => {
    query
    load()
  })
  $effect(() => {
    if (!live) return
    const t = setInterval(() => !document.hidden && load(), 5000)
    return () => clearInterval(t)
  })

  const info = $derived(data?.info)
  const sum = $derived(data?.summary)
  const acct = $derived(info?.acct)
  const pct = $derived(info?.max ? Math.min(100, Math.round((info.count / info.max) * 100)) : 0)
  const states = $derived(Object.entries(sum?.by_state ?? {}).sort((a, b) => b[1] - a[1]))
  const picked = $derived((sum?.clients ?? []).find((c) => c.key === client))

  const n = (x) => x.toLocaleString()
  const bytes = (b) => {
    if (!b) return '0 B'
    const u = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.min(u.length - 1, Math.floor(Math.log10(b) / 3))
    return (b / 1000 ** i).toFixed(i ? 1 : 0) + ' ' + u[i]
  }
  const ago = (s) => (s < 90 ? `${s}s` : s < 5400 ? `${Math.round(s / 60)}m` : s < 172800 ? `${Math.round(s / 3600)}h` : `${Math.round(s / 86400)}d`)
  const hp = (ip, port) => (!port ? ip : ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`)

  async function countBytes() {
    if (await act(() => api('PUT', '/api/sysctl', { conntrack_acct: true }), 'Counting bytes')) load()
  }

  const kinds = [
    ['', 'All'],
    ['forwarded', 'Forwarded'],
    ['incoming', 'To this machine'],
    ['outgoing', 'From this machine'],
  ]
  const columns = $derived([
    { label: 'Client', render: (c) => c.client || hp(c.src, c.src_port), sub: (c) => (c.client ? hp(c.src, c.src_port) : '') },
    { label: 'Destination', mono: true, render: (c) => hp(c.dst, c.dst_port) },
    { label: 'Proto', mono: true, render: (c) => [c.proto, c.state || (c.unreplied ? 'unreplied' : '')].filter(Boolean).join(' ') },
    // A plain masquerade is just the interface that owns the new address; anything else spells the NAT out.
    { label: 'Exit / NAT', mono: true, render: (c) => (c.via && c.nat?.startsWith('SNAT') && !c.nat.includes(';') ? c.via : [c.via, c.nat].filter(Boolean).join(' · ')) },
    ...(acct ? [{ label: 'Data', mono: true, render: (c) => `↑ ${bytes(c.bytes_out)}`, sub: (c) => `↓ ${bytes(c.bytes_in)}` }] : []),
    { label: 'Expires', render: (c) => ago(c.timeout) },
  ])
</script>

<div class="space-y-5">
  <p class="text-sm text-slate-500">
    Every connection the kernel is tracking, from its connection-tracking table (<span class="mono">conntrack -L</span>). This includes your VPN clients' traffic passing through this machine, which <span class="mono">ss</span> can't show. <b class="font-medium text-slate-300">Exit / NAT</b> shows how the source address was rewritten and which interface owns the new address.
  </p>

  {#if error}
    <p class="text-sm text-red-400">{error}</p>
  {:else if info && !info.available}
    <section class="card p-4 text-sm">
      <h2 class="mb-1 font-semibold">Connection tracking is off</h2>
      <p class="text-slate-400">{info.reason}</p>
    </section>
  {:else if info}
    <section class="card p-4">
      <div class="flex flex-wrap items-center justify-between gap-2 text-sm">
        <span><b class="font-semibold text-slate-200">{n(info.count)}</b> <span class="text-slate-500">of {n(info.max)} connections tracked</span></span>
        {#if !acct}
          <span class="flex items-center gap-2 text-xs text-slate-500">Byte counts are off <button class="btn btn-sm" onclick={countBytes}>Count bytes</button></span>
        {/if}
      </div>
      <div class="mt-2 h-1 overflow-hidden rounded bg-slate-800" role="img" aria-label="{pct}% of the tracking table is used">
        <div class="h-full {pct > 95 ? 'bg-red-500' : pct > 80 ? 'bg-amber-500' : 'bg-accent-600'}" style="width: {pct}%"></div>
      </div>
      {#if pct > 80}<p class="mt-2 text-xs text-amber-300">The table is nearly full. New connections are dropped when it is; raise <span class="mono">net.netfilter.nf_conntrack_max</span> if this is normal load.</p>{/if}
      {#if states.length}
        <div class="mt-3 flex flex-wrap gap-1.5" role="group" aria-label="Filter by state">
          {#each states as [name, count]}
            <button class="badge cursor-pointer {stateF === name ? 'bg-accent-600 text-white' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'}" aria-pressed={stateF === name} onclick={() => (stateF = stateF === name ? '' : name)}>{name} <span class="ml-1 opacity-70">{n(count)}</span></button>
          {/each}
        </div>
      {/if}
    </section>

    <section class="card">
      <header class="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-slate-800 px-4 py-3">
        <div class="flex flex-wrap gap-1" role="group" aria-label="Which connections">
          {#each kinds as [value, label]}
            <button class="btn btn-sm {kind === value ? 'btn-primary' : 'btn-ghost'}" aria-pressed={kind === value} onclick={() => (kind = value)}>{label}</button>
          {/each}
        </div>
        <div class="ml-auto flex items-center gap-3">
          <label class="flex items-center gap-1.5 text-xs text-slate-400"><input type="checkbox" class="size-3.5 accent-accent-600" bind:checked={live} /> Live</label>
          <button class="btn btn-sm" onclick={load}>Refresh</button>
        </div>
      </header>

      <div class="flex flex-wrap items-center gap-3 border-b border-slate-800 px-4 py-3">
        <input class="input max-w-56 py-1 text-xs" type="search" placeholder="Search address, port, client…" aria-label="Search" bind:value={q} />
        <select class="input w-auto py-1 text-xs" aria-label="Protocol" bind:value={proto}>
          <option value="">all protocols</option>
          <option value="tcp">tcp</option><option value="udp">udp</option><option value="icmp">icmp</option>
        </select>
        <select class="input w-auto py-1 text-xs" aria-label="Sort" bind:value={sort}>
          <option value="client">sort: client</option>
          {#if acct}<option value="data">sort: most data</option>{/if}
          <option value="expiry">sort: expiring soon</option>
          <option value="dest">sort: destination</option>
        </select>
      </div>

      {#if sum?.clients?.length}
        <div class="flex flex-wrap items-center gap-1.5 border-b border-slate-800 px-4 py-3" role="group" aria-label="Filter by client">
          <span class="mr-1 text-xs text-slate-500">Sources</span>
          {#each sum.clients as c}
            <button class="badge cursor-pointer {client === c.key ? 'bg-accent-600 text-white' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'}" aria-pressed={client === c.key} onclick={() => (client = client === c.key ? '' : c.key)} title={c.key}>
              {c.name || c.key} <span class="ml-1 opacity-70">{n(c.count)}</span>
            </button>
          {/each}
          {#if client && !picked}<button class="badge cursor-pointer bg-accent-600 text-white" onclick={() => (client = '')}>{client} ✕</button>{/if}
        </div>
      {/if}

      <div class="flex flex-wrap items-center justify-between gap-2 px-4 py-2 text-xs text-slate-500">
        <span>
          {n(sum.matching)} connection{sum.matching === 1 ? '' : 's'}
          {#if sum.shown < sum.matching}· showing the first {n(sum.shown)}; narrow the search to see the rest{/if}
        </span>
        {#if acct}<span class="mono">↑ {bytes(sum.bytes_out)} · ↓ {bytes(sum.bytes_in)}</span>{/if}
      </div>

      <LiveTable
        rows={data.conns}
        {columns}
        empty={sum.total === 0 ? 'Nothing is being tracked yet. Only traffic that a NAT or connection-state firewall rule applies to is tracked.' : 'No connections match.'}
      />
    </section>
  {/if}
</div>
