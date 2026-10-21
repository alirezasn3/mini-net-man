<script>
  import { api } from '../lib/api.js'
  import Resource from '../lib/Resource.svelte'
  import LiveTable from '../lib/LiveTable.svelte'
  import { refreshOverview } from '../lib/state.svelte.js'

  let live = $state([])
  let generated = $state([])
  let tableFilter = $state('all')
  let showLive = $state(false)

  async function reload() {
    const [l, g] = await Promise.all([api('GET', '/api/live/routes'), api('GET', '/api/generated')])
    live = l
    generated = g.routes
    refreshOverview()
  }
  $effect(() => {
    reload()
  })

  const tables = $derived([...new Set(live.map((r) => r.table))])
  const shown = $derived(live.filter((r) => tableFilter === 'all' || r.table === tableFilter))
</script>

<div class="space-y-5">
  <p class="text-sm text-slate-500">Like <span class="mono">ip route add … table N</span>, for IPv4 and IPv6. Use <span class="mono">default</span> for the IPv4 default route and <span class="mono">::/0</span> for IPv6. Routes created here carry an owner tag, so mini-net-man only ever removes its own.</p>
  <Resource
    title="Routes"
    endpoint="/api/routes"
    addLabel="Add route"
    onchange={reload}
    {generated}
    columns={[
      { key: 'dst', label: 'Destination', mono: true },
      { key: 'gateway', label: 'Gateway', mono: true },
      { key: 'dev', label: 'Interface', mono: true },
      { key: 'table', label: 'Table', render: (r) => r.table || 'main' },
      { key: 'metric', label: 'Metric', render: (r) => r.metric || '' },
      { key: 'type', label: 'Type', render: (r) => (r.type && r.type !== 'unicast' ? r.type : '') },
      { key: 'comment', label: 'Comment' },
    ]}
    fields={[
      { key: 'dst', label: 'Destination', type: 'text', mono: true, placeholder: 'default, ::/0, 10.0.0.0/16, fd00::/64', help: 'The network this route covers, like 10.0.0.0/16. Use default for all IPv4 traffic and ::/0 for all IPv6.' },
      { key: 'table', label: 'Table', type: 'text', placeholder: 'main, or a number like 200', help: 'Which routing table it goes in. Empty means the normal (main) table; use a number such as 200 for a policy-routing table.' },
      { key: 'dev', label: 'Interface', type: 'iface', mono: true, placeholder: 'wgBridge0', help: 'Where matching traffic leaves, for example an exit tunnel. Optional if you give a gateway.' },
      { key: 'gateway', label: 'Gateway', type: 'text', mono: true, placeholder: 'optional next hop (v4 or v6)', help: 'The router that should receive the traffic. Leave empty for tunnels and directly attached networks.' },
      { key: 'metric', label: 'Metric', type: 'number', help: 'When two routes cover the same destination the lower number wins. 0 uses the kernel default.' },
      { key: 'type', label: 'Type', type: 'select', options: ['unicast', 'blackhole', 'unreachable', 'prohibit'], help: (d) => ({ unicast: 'Forward normally.', blackhole: 'Silently drop. The sender just waits.', unreachable: 'Drop and tell the sender the host is unreachable.', prohibit: 'Drop and tell the sender it is prohibited.' })[d.type] },
      { key: 'comment', label: 'Comment', type: 'text', wide: true, help: 'Optional note for yourself.' },
    ]}
    blank={() => ({ dst: 'default', gateway: '', dev: '', table: '', metric: 0, type: 'unicast', comment: '', disabled: false })}
  />

  <section class="card">
    <header class="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
      <h2 class="text-sm font-semibold">Live kernel routes <span class="ml-1 font-normal text-slate-400">{live.length}</span></h2>
      <div class="flex items-center gap-2">
        {#if showLive}
          <select class="input w-auto py-1 text-xs" bind:value={tableFilter} aria-label="Filter by table">
            <option value="all">all tables</option>
            {#each tables as t}<option value={t}>table {t}</option>{/each}
          </select>
        {/if}
        <button class="btn btn-sm" onclick={() => { showLive = !showLive; reload() }}>{showLive ? 'Hide' : 'Show'}</button>
      </div>
    </header>
    {#if showLive}
      <LiveTable
        rows={shown}
        columns={[
          { label: 'Destination', mono: true, render: (r) => r.dst + (r.type && r.type !== 'unicast' ? ` (${r.type})` : '') },
          { label: 'Gateway', key: 'gateway', mono: true },
          { label: 'Interface', key: 'dev', mono: true },
          { label: 'Table', key: 'table' },
          { label: 'Metric', render: (r) => r.metric || '' },
          { label: 'Origin', origin: true, render: (r) => (r.owned ? 'mini-net-man' : r.proto) },
        ]}
      />
    {/if}
  </section>
</div>
