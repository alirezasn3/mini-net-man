<script>
  import { api } from '../lib/api.js'
  import Resource from '../lib/Resource.svelte'
  import Nft from '../lib/Nft.svelte'
  import { act, refreshOverview } from '../lib/state.svelte.js'

  let policy = $state({ input: 'accept', forward: 'accept', output: 'accept' })
  let generated = $state([])
  let ruleset = $state({ desired: '', live: '' })
  let showRuleset = $state(false)

  async function reload() {
    const [fw, g, rs] = await Promise.all([api('GET', '/api/firewall'), api('GET', '/api/generated'), api('GET', '/api/firewall/ruleset')])
    policy = { input: 'accept', forward: 'accept', output: 'accept', ...fw.policy }
    generated = g.firewall
    ruleset = rs
    refreshOverview()
  }
  $effect(() => {
    reload()
  })

  // One row per filter chain, shown at the end of the rule list.
  const defaults = $derived(['input', 'forward', 'output'].map((chain) => ({ id: 'default-' + chain, chain, action: policy[chain], default: true, comment: 'default action' })))
  const defaultMessage = {
    input: 'This changes what happens to everything not explicitly allowed above, including this panel. Make sure a rule above allows its port first.',
  }

  async function setDefault(item, value) {
    const risky = value !== 'accept' && item.chain === 'input'
    if (risky && !confirm(defaultMessage.input + ' Continue?')) {
      await reload()
      return
    }
    await act(() => api('PUT', '/api/firewall/policy', { ...policy, [item.chain]: value }), `Default for ${item.chain}: ${value}`)
    await reload()
  }

  const chains = ['input', 'forward', 'output', 'mangle', 'mangle-in', 'mangle-out', 'dstnat', 'srcnat']
  const actions = ['accept', 'drop', 'reject', 'return', 'masquerade', 'dnat', 'snat', 'clamp-mss', 'mark-connection', 'restore-mark']
  const match = (r) =>
    r.default ? 'everything not matched above' : [
      r.family && r.family.replace('ipv', 'IPv'),
      r.in_iface && `in ${r.in_iface}`,
      r.out_iface && `out ${r.out_iface}`,
      r.proto,
      r.src && `from ${r.src}`,
      r.src_port && `sport ${r.src_port}`,
      r.dst && `to ${r.dst}`,
      r.dst_port && `dport ${r.dst_port}`,
      r.conn_state && `state ${r.conn_state}`,
    ]
      .filter(Boolean)
      .join(' ') || 'any'
  const target = (r) => (r.action === 'clamp-mss' ? (r.mss ? `clamp-mss ${r.mss}` : 'clamp-mss to route MTU') : r.action === 'mark-connection' ? `mark-connection ${r.mark}` : r.to_addr ? `${r.action} → ${r.to_addr}${r.to_port ? ':' + r.to_port : ''}` : r.action)
</script>

<div class="space-y-5">
  <p class="text-sm text-slate-500">
    Rules live in their own nftables table, <span class="mono">inet mini-net-man</span> (IPv4 and IPv6), replaced atomically on every change. A rule with no address and no Family applies to both families. Rules in a chain run top to bottom; <b>dstnat</b> and <b>srcnat</b> are the NAT chains (like MikroTik's dst-nat / src-nat); <b>mangle</b> holds MSS clamping, and <b>mangle-in</b> / <b>mangle-out</b> hold connection marking. The three <b>default</b> rows at the end say what happens to anything no rule decided: <b>accept</b> lets it through, <b>drop</b> discards it silently, <b>reject</b> discards it and tells the sender, so it fails at once instead of timing out.
  </p>

  <Resource
    title="Firewall rules"
    endpoint="/api/firewall/rules"
    addLabel="Add rule"
    orderable
    groupBy={(r) => r.chain}
    groupOrder={chains}
    onchange={reload}
    {generated}
    {defaults}
    defaultOptions={['accept', 'drop', 'reject']}
    ondefault={setDefault}
    columns={[
      { key: 'chain', label: 'Chain', mono: true },
      { key: 'action', label: 'Action', mono: true, render: target },
      { key: 'match', label: 'Match', mono: true, render: match },
      { key: 'comment', label: 'Comment' },
    ]}
    fields={[
      { key: 'chain', label: 'Chain', type: 'select', options: chains, help: (d) => ({ input: 'Traffic addressed to this machine.', forward: 'Traffic passing through this machine to somewhere else.', output: 'Traffic this machine creates itself.', mangle: 'Traffic passing through, after routing. Used for MSS clamping.', 'mangle-in': 'Everything arriving, before the routing decision. Used to mark connections.', 'mangle-out': 'Traffic this machine sends, re-routed if its mark changes. Used to send replies back the way the request came.', dstnat: 'Rewrites the destination before routing: port forwarding.', srcnat: 'Rewrites the source on the way out: masquerade.' })[d.chain] },
      { key: 'action', label: 'Action', type: 'select', options: actions, help: (d) => ({ accept: 'Let the packet through.', drop: 'Discard it silently.', reject: 'Discard it and tell the sender, so it fails fast.', return: 'Stop checking this chain.', masquerade: 'Use the outgoing interface\u2019s address as the source. srcnat chain only.', dnat: 'Send it to another address or port. dstnat chain only.', snat: 'Use a fixed address as the source. srcnat chain only.', 'clamp-mss': 'Lower the TCP segment size announced when a connection starts, so packets fit a smaller link and are not silently dropped. mangle chain only.', 'mark-connection': 'Stamp a number on the packet and its whole connection. A policy rule with the same fwmark can then route it. mangle-in or mangle-out chain.', 'restore-mark': 'Give the packet the mark its connection already has. Use it in mangle-out so replies are routed by the mark of the request.' })[d.action] },
      { key: 'in_iface', label: 'In interface', type: 'iface', mono: true, help: 'Only traffic that arrived on this interface. Empty matches any. A trailing * is a wildcard: wg* matches wg0, wgBridge1.', show: (d) => d.chain !== 'output' && d.chain !== 'srcnat' && d.chain !== 'mangle-out' },
      { key: 'out_iface', label: 'Out interface', type: 'iface', mono: true, help: 'Only traffic leaving through this interface. Empty matches any. A trailing * is a wildcard: wg* matches wg0, wgBridge1.', show: (d) => d.chain !== 'input' && d.chain !== 'dstnat' && d.chain !== 'mangle-in' },
      { key: 'src', label: 'Source', type: 'text', mono: true, placeholder: '10.0.0.0/16 or fd00::/64', help: 'Only traffic from this address or network.' },
      { key: 'dst', label: 'Destination', type: 'text', mono: true, help: 'Only traffic to this address or network.' },
      { key: 'family', label: 'Family', type: 'select', options: [{ value: '', label: 'both (or from addresses)' }, { value: 'ipv4', label: 'IPv4 only' }, { value: 'ipv6', label: 'IPv6 only' }], help: 'Leave on both unless the rule should only apply to one. Addresses above decide it automatically.' },
      { key: 'proto', label: 'Protocol', type: 'select', options: [{ value: '', label: 'any' }, 'tcp', 'udp', 'icmp', 'icmpv6'], help: 'Choose tcp or udp to match ports.' },
      { key: 'conn_state', label: 'Connection state', type: 'text', placeholder: 'established,related', help: 'Comma list of new, established, related, invalid. established,related lets replies to your own traffic through.' },
      { key: 'src_port', label: 'Source port', type: 'text', placeholder: '1024-65535', help: 'One port, a range like 1000-2000, or a list like 80,443.', show: (d) => d.proto === 'tcp' || d.proto === 'udp' },
      { key: 'dst_port', label: 'Destination port', type: 'text', placeholder: '22 or 80,443', help: 'The port being connected to: one port, a range, or a list.', show: (d) => d.proto === 'tcp' || d.proto === 'udp' },
      { key: 'to_addr', label: 'To address', type: 'text', mono: true, help: 'The address to send matching traffic to.', show: (d) => d.action === 'dnat' || d.action === 'snat' },
      { key: 'to_port', label: 'To port', type: 'number', help: 'Optional. 0 keeps the original port.', show: (d) => d.action === 'dnat' || d.action === 'snat' },
      { key: 'mss', label: 'MSS', type: 'number', help: '0 fits the outgoing route\u2019s MTU (recommended, and what pppoe/tunnel clamping usually wants). Or give a fixed size such as 1300. An MSS already lower is never raised.', show: (d) => d.action === 'clamp-mss' },
      { key: 'mark', label: 'Mark', type: 'number', help: 'A number above 0, for example 1 for traffic from one link and 2 for the other. Create a policy rule with the same fwmark to route on it.', show: (d) => d.action === 'mark-connection' },
      { key: 'comment', label: 'Comment', type: 'text', wide: true, help: 'Optional note for yourself. It also shows in nft list.' },
    ]}
    blank={() => ({ chain: 'forward', action: 'accept', family: '', in_iface: '', out_iface: '', src: '', dst: '', proto: '', src_port: '', dst_port: '', conn_state: '', to_addr: '', to_port: 0, mss: 0, mark: 0, comment: '', disabled: false })}
  />

  <section class="card">
    <header class="flex items-center justify-between border-b border-slate-200 px-4 py-3 dark:border-slate-800">
      <h2 class="text-sm font-semibold">nftables ruleset</h2>
      <button class="btn btn-sm" onclick={() => { showRuleset = !showRuleset; reload() }}>{showRuleset ? 'Hide' : 'Show'}</button>
    </header>
    {#if showRuleset}
      <div class="grid grid-cols-1 gap-4 p-4 lg:grid-cols-2">
        <div class="min-w-0">
          <h3 class="label">What will be applied</h3>
          <Nft text={ruleset.desired} />
        </div>
        <div class="min-w-0">
          <h3 class="label">What the kernel has (nft list)</h3>
          <Nft text={ruleset.live || '(table not present, or nft is not installed)'} />
        </div>
      </div>
    {/if}
  </section>
</div>
