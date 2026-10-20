<script>
  import { api } from '../lib/api.js'
  import Resource from '../lib/Resource.svelte'
  import { refreshOverview } from '../lib/state.svelte.js'

  let live = $state([])
  let generated = $state([])
  let showLive = $state(false)

  async function reload() {
    const [l, g] = await Promise.all([api('GET', '/api/live/rules'), api('GET', '/api/generated')])
    live = l
    generated = g.rules
    refreshOverview()
  }
  $effect(() => {
    reload()
  })

  const match = (r) =>
    [r.family === 'ipv6' && !r.src && !r.dst && 'ipv6', r.src && `from ${r.src}`, r.dst && `to ${r.dst}`, r.iif && `iif ${r.iif}`, r.oif && `oif ${r.oif}`, r.fwmark && `fwmark 0x${r.fwmark.toString(16)}`]
      .filter(Boolean)
      .join(' ') || 'all'
  const action = (r) => (!r.action || r.action === 'lookup' ? `lookup ${r.table}` : r.action)
</script>

<div class="space-y-5">
  <p class="text-sm text-slate-500">Like <span class="mono">ip rule add … priority N</span>. IPv4 and IPv6 have separate rule lists; the family comes from the addresses you give, or from the Family field. The lowest priority number is checked first; the first rule whose table has a matching route wins.</p>
  <Resource
    title="Policy rules"
    endpoint="/api/rules"
    addLabel="Add rule"
    onchange={reload}
    {generated}
    sort={(a, b) => a.priority - b.priority}
    columns={[
      { key: 'priority', label: 'Priority', mono: true },
      { key: 'match', label: 'Match', mono: true, render: match },
      { key: 'action', label: 'Action', mono: true, render: action },
      { key: 'comment', label: 'Comment' },
    ]}
    fields={[
      { key: 'priority', label: 'Priority', type: 'number', help: '0 – 32765' },
      { key: 'action', label: 'Action', type: 'select', options: ['lookup', 'blackhole', 'unreachable', 'prohibit'] },
      { key: 'family', label: 'Family', type: 'select', options: [{ value: '', label: 'from addresses (IPv4 if none)' }, { value: 'ipv4', label: 'IPv4' }, { value: 'ipv6', label: 'IPv6' }] },
      { key: 'table', label: 'Table', type: 'text', placeholder: '200, main, local', show: (d) => !d.action || d.action === 'lookup' },
      { key: 'src', label: 'From (source)', type: 'text', mono: true, placeholder: '10.0.0.0/16 or fd00::/64' },
      { key: 'dst', label: 'To (destination)', type: 'text', mono: true, placeholder: '192.168.71.0/24' },
      { key: 'iif', label: 'Incoming interface', type: 'iface', mono: true },
      { key: 'oif', label: 'Outgoing interface', type: 'iface', mono: true },
      { key: 'fwmark', label: 'Firewall mark', type: 'number', help: '0 = any' },
      { key: 'comment', label: 'Comment', type: 'text', wide: true },
    ]}
    blank={() => ({ priority: 200, action: 'lookup', family: '', table: '', src: '', dst: '', iif: '', oif: '', fwmark: 0, comment: '', disabled: false })}
  />

  <section class="card">
    <header class="flex items-center justify-between border-b border-slate-200 px-4 py-3 dark:border-slate-800">
      <h2 class="text-sm font-semibold">Live kernel rules <span class="ml-1 font-normal text-slate-400">{live.length}</span></h2>
      <button class="btn btn-sm" onclick={() => { showLive = !showLive; reload() }}>{showLive ? 'Hide' : 'Show'}</button>
    </header>
    {#if showLive}
      <table class="w-full text-sm">
        <thead class="border-b border-slate-200 dark:border-slate-800"><tr>
          {#each ['Priority', 'Match', 'Action', 'Origin'] as h}<th class="th">{h}</th>{/each}
        </tr></thead>
        <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
          {#each live as r}
            <tr>
              <td class="td mono">{r.priority}</td>
              <td class="td mono">{match(r)}</td>
              <td class="td mono">{action(r)}</td>
              <td class="td"><span class="badge {r.owned ? 'bg-accent-100 text-accent-800 dark:bg-accent-800/40 dark:text-accent-100' : 'bg-slate-200 text-slate-600 dark:bg-slate-800 dark:text-slate-400'}">{r.owned ? 'mini-net-man' : 'system / manual'}</span></td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>
</div>
