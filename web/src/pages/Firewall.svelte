<script>
  import { api } from '../lib/api.js'
  import Resource from '../lib/Resource.svelte'
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

  async function setPolicy(chain, value) {
    if (value === 'drop' && chain === 'input' && !confirm('Default-drop on input blocks everything not explicitly allowed, including this panel. Make sure a rule allows its port first. Continue?')) {
      await reload()
      return
    }
    await act(() => api('PUT', '/api/firewall/policy', { ...policy, [chain]: value }), 'Policy updated')
    await reload()
  }

  const chains = ['input', 'forward', 'output', 'dstnat', 'srcnat']
  const actions = ['accept', 'drop', 'reject', 'return', 'masquerade', 'dnat', 'snat']
  const match = (r) =>
    [
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
  const target = (r) => (r.to_addr ? `${r.action} → ${r.to_addr}${r.to_port ? ':' + r.to_port : ''}` : r.action)
</script>

<div class="space-y-5">
  <p class="text-sm text-slate-500">
    Rules live in their own nftables table, <span class="mono">inet mini-net-man</span> (IPv4 and IPv6), replaced atomically on every change. A rule with no address and no Family applies to both families. Rules in a chain run top to bottom; <b>dstnat</b> and <b>srcnat</b> are the NAT chains (like MikroTik's dst-nat / src-nat).
  </p>

  <section class="card p-4">
    <h2 class="mb-3 text-sm font-semibold">Default policy</h2>
    <div class="flex flex-wrap gap-4">
      {#each ['input', 'forward', 'output'] as c}
        <div>
          <label class="label" for="pol-{c}">{c}</label>
          <select id="pol-{c}" class="input w-32" value={policy[c]} onchange={(e) => setPolicy(c, e.currentTarget.value)}>
            <option>accept</option><option>drop</option>
          </select>
        </div>
      {/each}
    </div>
  </section>

  <Resource
    title="Firewall rules"
    endpoint="/api/firewall/rules"
    addLabel="Add rule"
    orderable
    onchange={reload}
    {generated}
    columns={[
      { key: 'chain', label: 'Chain', mono: true },
      { key: 'action', label: 'Action', mono: true, render: target },
      { key: 'match', label: 'Match', mono: true, render: match },
      { key: 'comment', label: 'Comment' },
    ]}
    fields={[
      { key: 'chain', label: 'Chain', type: 'select', options: chains },
      { key: 'action', label: 'Action', type: 'select', options: actions },
      { key: 'in_iface', label: 'In interface', type: 'iface', mono: true, show: (d) => d.chain !== 'output' && d.chain !== 'srcnat' },
      { key: 'out_iface', label: 'Out interface', type: 'iface', mono: true, show: (d) => d.chain !== 'input' && d.chain !== 'dstnat' },
      { key: 'src', label: 'Source', type: 'text', mono: true, placeholder: '10.0.0.0/16 or fd00::/64' },
      { key: 'dst', label: 'Destination', type: 'text', mono: true },
      { key: 'family', label: 'Family', type: 'select', options: [{ value: '', label: 'both (or from addresses)' }, { value: 'ipv4', label: 'IPv4 only' }, { value: 'ipv6', label: 'IPv6 only' }] },
      { key: 'proto', label: 'Protocol', type: 'select', options: [{ value: '', label: 'any' }, 'tcp', 'udp', 'icmp', 'icmpv6'] },
      { key: 'conn_state', label: 'Connection state', type: 'text', placeholder: 'established,related' },
      { key: 'src_port', label: 'Source port', type: 'text', placeholder: '1024-65535', show: (d) => d.proto === 'tcp' || d.proto === 'udp' },
      { key: 'dst_port', label: 'Destination port', type: 'text', placeholder: '22 or 80,443', show: (d) => d.proto === 'tcp' || d.proto === 'udp' },
      { key: 'to_addr', label: 'To address', type: 'text', mono: true, show: (d) => d.action === 'dnat' || d.action === 'snat' },
      { key: 'to_port', label: 'To port', type: 'number', show: (d) => d.action === 'dnat' || d.action === 'snat' },
      { key: 'comment', label: 'Comment', type: 'text', wide: true },
    ]}
    blank={() => ({ chain: 'forward', action: 'accept', family: '', in_iface: '', out_iface: '', src: '', dst: '', proto: '', src_port: '', dst_port: '', conn_state: '', to_addr: '', to_port: 0, comment: '', disabled: false })}
  />

  <section class="card">
    <header class="flex items-center justify-between border-b border-slate-200 px-4 py-3 dark:border-slate-800">
      <h2 class="text-sm font-semibold">nftables ruleset</h2>
      <button class="btn btn-sm" onclick={() => { showRuleset = !showRuleset; reload() }}>{showRuleset ? 'Hide' : 'Show'}</button>
    </header>
    {#if showRuleset}
      <div class="grid gap-4 p-4 lg:grid-cols-2">
        <div>
          <h3 class="label">What will be applied</h3>
          <pre class="mono max-h-96 overflow-auto rounded-md bg-slate-100 p-3 dark:bg-slate-950">{ruleset.desired}</pre>
        </div>
        <div>
          <h3 class="label">What the kernel has (nft list)</h3>
          <pre class="mono max-h-96 overflow-auto rounded-md bg-slate-100 p-3 dark:bg-slate-950">{ruleset.live || '(table not present, or nft is not installed)'}</pre>
        </div>
      </div>
    {/if}
  </section>
</div>
