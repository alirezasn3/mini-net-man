<script>
  import { api } from '../lib/api.js'
  import Resource from '../lib/Resource.svelte'
  import LiveTable from '../lib/LiveTable.svelte'
  import { refreshOverview } from '../lib/state.svelte.js'

  let live = $state([])
  let generated = $state([])
  let showLive = $state(false)
  let checks = $state([])
  let status = $state({}) // check id -> { state, rtt_ms, error, since }

  async function loadChecks() {
    ;[checks, status] = await Promise.all([api('GET', '/api/checks'), api('GET', '/api/checks/status')])
    reload()
  }
  // Keep the up/down state fresh while the page is open.
  $effect(() => {
    loadChecks()
    const t = setInterval(() => api('GET', '/api/checks/status').then((s) => (status = s)).catch(() => {}), 3000)
    return () => clearInterval(t)
  })

  const checkName = (id) => checks.find((c) => c.id === id)?.name ?? 'a deleted check'
  const ruleBadge = (r) =>
    r.check && status[r.check]?.state === 'down'
      ? { text: 'off: check failing', cls: 'bg-red-500/15 text-red-300', title: `${checkName(r.check)} is down: ${status[r.check].error || 'no reply'}. The rule is out of the kernel until it recovers.` }
      : null
  const condition = (r) => (r.check ? `only while ${checkName(r.check)} is up` : '')

  const stateText = (c) => {
    const s = status[c.id]
    if (!s) return 'starting…'
    if (s.state === 'up') return `up · ${s.rtt_ms < 10 ? s.rtt_ms.toFixed(1) : Math.round(s.rtt_ms)} ms`
    if (s.state === 'down') return `down · ${s.error || 'no reply'}`
    return 'checking…'
  }
  const stateClass = (c) => ({ up: 'bg-accent-600/20 text-accent-300', down: 'bg-red-500/15 text-red-300' })[status[c.id]?.state] ?? 'bg-slate-800 text-slate-400'

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
    rowBadge={ruleBadge}
    sort={(a, b) => a.priority - b.priority}
    columns={[
      { key: 'priority', label: 'Priority', mono: true },
      { key: 'match', label: 'Match', mono: true, render: match },
      { key: 'action', label: 'Action', mono: true, render: action },
      { key: 'check', label: 'Condition', render: condition },
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
      {
        key: 'check',
        label: 'Condition',
        type: 'select',
        options: [{ value: '', label: 'always on' }, ...checks.map((c) => ({ value: c.id, label: `only while "${c.name}" is up` }))],
        wide: true,
        help: checks.length
          ? 'Tie the rule to a health check below. While its pings fail the rule is taken out of the kernel (traffic falls through to the next rule), and it is put back once they succeed again.'
          : 'Add a health check below first, and you can make this rule depend on it.',
      },
      { key: 'comment', label: 'Comment', type: 'text', wide: true, help: 'Optional note for yourself.' },
    ]}
    blank={() => ({ priority: 200, action: 'lookup', family: '', table: '', src: '', dst: '', iif: '', oif: '', fwmark: 0, check: '', comment: '', disabled: false })}
  />

  <p class="text-sm text-slate-500">
    A <b class="font-medium text-slate-300">health check</b> pings an address out of one interface. Rules that depend on it are switched off while the pings go unanswered, for example to stop sending clients through an exit tunnel that has silently died, and switched back on when it recovers. A brief blip doesn't flap it: it takes several misses in a row to go down and several replies to come back.
  </p>
  <Resource
    title="Health checks"
    endpoint="/api/checks"
    addLabel="Add check"
    onchange={loadChecks}
    columns={[
      { key: 'name', label: 'Name' },
      { label: 'Ping', mono: true, render: (c) => `${c.target} via ${c.interface}${c.table ? ` · table ${c.table}` : ''}` },
      { label: 'State', render: stateText, badge: stateClass },
      { label: 'Every', render: (c) => `${c.interval_secs || 5}s` },
    ]}
    fields={[
      { key: 'name', label: 'Name', type: 'text', placeholder: 'germany exit', wide: true, help: 'A label you will recognise when picking it for a rule.' },
      { key: 'target', label: 'Ping this address', type: 'text', mono: true, placeholder: '1.1.1.1 or 2606:4700:4700::1111', help: 'An IPv4 or IPv6 address that should always answer, ideally something beyond the exit (a public DNS server) so it proves the whole path works. Replies have to pass Linux\u2019s reverse-path filter, so the target needs a route on this machine (a default route is enough).' },
      { key: 'interface', label: 'Out of interface', type: 'iface', mono: true, placeholder: 'wgBridge0', help: 'The ping is sent out of this interface, so it tests that interface\u2019s own path, not whatever the main routing table would pick.' },
      { key: 'table', label: 'Routing table (optional)', type: 'text', placeholder: '200', help: 'Leave empty for a tunnel such as WireGuard; the ping goes straight into it. Only if the exit is reached through a gateway in a custom table, name that table so the ping uses its route.' },
      { key: 'interval_secs', label: 'Every (seconds)', type: 'number', help: 'How often to ping. 0 means the default, 5.' },
      { key: 'timeout_ms', label: 'Wait for a reply (ms)', type: 'number', help: 'How long to wait for the answer before counting it as missed. 0 means 1000.' },
      { key: 'fail_after', label: 'Down after (misses in a row)', type: 'number', help: 'How many unanswered pings in a row mark the check down. 0 means 3.' },
      { key: 'recover_after', label: 'Up again after (replies in a row)', type: 'number', help: 'How many answered pings in a row bring it back. 0 means 2.' },
    ]}
    blank={() => ({ name: '', target: '', interface: '', table: '', interval_secs: 5, timeout_ms: 1000, fail_after: 3, recover_after: 2 })}
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
