<script>
  import { api } from '../lib/api.js'
  import Resource from '../lib/Resource.svelte'
  import LiveTable from '../lib/LiveTable.svelte'
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
      { key: 'priority', label: 'Priority', type: 'number', help: 'Rules are checked from the lowest number up. 0 to 32765; the system uses 0 and 32766, so pick something in between.' },
      { key: 'action', label: 'Action', type: 'select', options: ['lookup', 'blackhole', 'unreachable', 'prohibit'], help: (d) => ({ lookup: 'Send matching packets through a routing table.', blackhole: 'Silently drop matching packets.', unreachable: 'Drop and tell the sender the host is unreachable.', prohibit: 'Drop and tell the sender it is prohibited.' })[d.action || 'lookup'] },
      { key: 'family', label: 'Family', type: 'select', options: [{ value: '', label: 'from addresses (IPv4 if none)' }, { value: 'ipv4', label: 'IPv4' }, { value: 'ipv6', label: 'IPv6' }], help: 'IPv4 and IPv6 have separate rule lists. Only matters when the rule has no From or To address.' },
      { key: 'table', label: 'Table', type: 'text', placeholder: '200, main, local', help: 'The routing table to look in: a number like 200, or main / local. If it has no matching route the search continues with the next rule.', show: (d) => !d.action || d.action === 'lookup' },
      { key: 'src', label: 'From (source)', type: 'text', mono: true, placeholder: '10.0.0.0/16 or fd00::/64', help: 'Match packets sent from this address or network. Empty matches anyone.' },
      { key: 'dst', label: 'To (destination)', type: 'text', mono: true, placeholder: '192.168.71.0/24', help: 'Match packets going to this address or network. Empty matches anywhere.' },
      { key: 'iif', label: 'Incoming interface', type: 'iface', mono: true, help: 'Match packets that arrived on this interface.' },
      { key: 'oif', label: 'Outgoing interface', type: 'iface', mono: true, help: 'Match packets created on this machine that leave through this interface.' },
      { key: 'fwmark', label: 'Firewall mark', type: 'number', help: 'Match packets carrying this firewall mark. 0 ignores it.' },
      { key: 'comment', label: 'Comment', type: 'text', wide: true, help: 'Optional note for yourself.' },
    ]}
    blank={() => ({ priority: 200, action: 'lookup', family: '', table: '', src: '', dst: '', iif: '', oif: '', fwmark: 0, comment: '', disabled: false })}
  />

  <section class="card">
    <header class="flex items-center justify-between border-b border-slate-200 px-4 py-3 dark:border-slate-800">
      <h2 class="text-sm font-semibold">Live kernel rules <span class="ml-1 font-normal text-slate-400">{live.length}</span></h2>
      <button class="btn btn-sm" onclick={() => { showLive = !showLive; reload() }}>{showLive ? 'Hide' : 'Show'}</button>
    </header>
    {#if showLive}
      <LiveTable
        rows={live}
        columns={[
          { label: 'Priority', key: 'priority', mono: true },
          { label: 'Match', mono: true, render: match },
          { label: 'Action', mono: true, render: action },
          { label: 'Origin', origin: true, render: (r) => (r.owned ? 'mini-net-man' : 'system / manual') },
        ]}
      />
    {/if}
  </section>
</div>
