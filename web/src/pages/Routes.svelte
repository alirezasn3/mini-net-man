<script>
  import { api } from '../lib/api.js'
  import Resource from '../lib/Resource.svelte'
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
  <p class="text-sm text-slate-500">Like <span class="mono">ip route add … table N</span>. Routes created here carry an owner tag, so mini-net-man only ever removes its own.</p>
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
      { key: 'dst', label: 'Destination', type: 'text', mono: true, placeholder: 'default or 10.0.0.0/16' },
      { key: 'table', label: 'Table', type: 'text', placeholder: 'main, or a number like 200', help: 'Empty means main.' },
      { key: 'dev', label: 'Interface', type: 'iface', mono: true, placeholder: 'wgBridge0' },
      { key: 'gateway', label: 'Gateway', type: 'text', mono: true, placeholder: 'optional next hop' },
      { key: 'metric', label: 'Metric', type: 'number', help: '0 uses the kernel default.' },
      { key: 'type', label: 'Type', type: 'select', options: ['unicast', 'blackhole', 'unreachable', 'prohibit'] },
      { key: 'comment', label: 'Comment', type: 'text', wide: true },
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
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead class="border-b border-slate-200 dark:border-slate-800"><tr>
            {#each ['Destination', 'Gateway', 'Interface', 'Table', 'Metric', 'Origin'] as h}<th class="th">{h}</th>{/each}
          </tr></thead>
          <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
            {#each shown as r}
              <tr>
                <td class="td mono">{r.dst}{r.type && r.type !== 'unicast' ? ` (${r.type})` : ''}</td>
                <td class="td mono">{r.gateway}</td>
                <td class="td mono">{r.dev}</td>
                <td class="td">{r.table}</td>
                <td class="td">{r.metric || ''}</td>
                <td class="td"><span class="badge {r.owned ? 'bg-accent-100 text-accent-800 dark:bg-accent-800/40 dark:text-accent-100' : 'bg-slate-200 text-slate-600 dark:bg-slate-800 dark:text-slate-400'}">{r.owned ? 'mini-net-man' : r.proto}</span></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
</div>
