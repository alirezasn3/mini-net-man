<script>
  import Resource from '../lib/Resource.svelte'
  import { api } from '../lib/api.js'
  import { act, refreshOverview } from '../lib/state.svelte.js'

  let links = $state([])
  let managers = $state([])
  let settings = $state([])
  let busy = $state(null)

  async function load() {
    links = await api('GET', '/api/links').catch(() => [])
    managers = (await api('GET', '/api/network/managers').catch(() => ({ managers: [] }))).managers
    settings = await api('GET', '/api/interfaces').catch(() => [])
  }
  $effect(() => {
    load()
  })
  function changed() {
    load()
    refreshOverview()
  }

  // The state buttons keep an interface up or down by adding (or editing) its entry under Interface settings.
  async function setState(l, state) {
    if (state === 'down' && !confirm(`Take ${l.name} down? Anything that reaches this machine through it, possibly this panel, stops working. Use Safe mode first if you are not sure.`)) return
    busy = l.name
    const have = settings.find((s) => s.name === l.name)
    const call = have
      ? () => api('PUT', `/api/interfaces/${have.id}`, { ...have, state, disabled: false })
      : () => api('POST', '/api/interfaces', { name: l.name, state, mtu: 0, comment: '', disabled: false })
    await act(call, state === 'up' ? `${l.name} is kept up` : `${l.name} is kept down`)
    busy = null
    changed()
  }

  const others = (l) => (l.managed_by ?? []).filter((m) => m !== 'mini-net-man')
  const clash = (l) => (l.managed_by ?? []).includes('mini-net-man') && others(l).length > 0
  const sorted = $derived([...links].sort((a, b) => a.index - b.index))
</script>

<div class="space-y-5">
  <section class="card">
    <header class="border-b border-slate-200 px-4 py-3 dark:border-slate-800">
      <h2 class="text-sm font-semibold">What manages the network</h2>
    </header>
    <div class="space-y-3 p-4 text-sm">
      {#each managers as m (m.id)}
        <div>
          <div class="flex flex-wrap items-center gap-2">
            <b>{m.name}</b>
            {#if m.running}<span class="badge bg-accent-600/20 text-accent-300">running</span>{:else}<span class="badge bg-slate-800 text-slate-400">not running</span>{/if}
            {#if m.config}<span class="badge bg-slate-800 text-slate-400">has configuration</span>{/if}
            <span class="text-slate-500">{m.detail}</span>
          </div>
          {#if m.note}<p class="hint mt-1">{m.note}</p>{/if}
        </div>
      {:else}
        <p class="text-slate-500">Nothing else is configuring the network that the panel recognises (NetworkManager, systemd-networkd, netplan, ifupdown, ConnMan, dhcpcd, netctl). Interfaces are set up by hand or by a script, so mini-net-man is the only thing keeping them the way you set them.</p>
      {/each}
    </div>
  </section>

  <section class="card">
    <header class="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
      <h2 class="text-sm font-semibold">Interfaces <span class="ml-1 font-normal text-slate-400">{links.length}</span></h2>
      <span class="text-xs text-slate-500">live from the kernel</span>
    </header>
    <div class="overflow-x-auto max-sm:overflow-visible">
      <table class="w-full text-sm max-sm:block">
        <thead class="border-b border-slate-200 max-sm:hidden dark:border-slate-800">
          <tr><th class="th">Name</th><th class="th">Type</th><th class="th">State</th><th class="th">MTU</th><th class="th">Bridge</th><th class="th">Addresses</th><th class="th">Managed by</th><th class="th"></th></tr>
        </thead>
        <tbody class="divide-y divide-slate-100 max-sm:block dark:divide-slate-800">
          {#each sorted as l (l.name)}
            <tr class="hover:bg-slate-50 max-sm:block max-sm:px-4 max-sm:py-3 dark:hover:bg-slate-800/40">
              <td class="td mono max-sm:block max-sm:px-0 max-sm:py-0.5"><b>{l.name}</b></td>
              <td class="td max-sm:flex max-sm:justify-between max-sm:px-0 max-sm:py-0.5"><span class="label mb-0 uppercase tracking-wide sm:hidden">Type</span>{l.type}</td>
              <td class="td max-sm:flex max-sm:justify-between max-sm:px-0 max-sm:py-0.5">
                <span class="label mb-0 uppercase tracking-wide sm:hidden">State</span>
                <span class="badge {l.up ? 'bg-accent-600/20 text-accent-300' : 'bg-slate-800 text-slate-400'}">{l.up ? (l.running ? 'up' : 'up, no carrier') : 'down'}</span>
              </td>
              <td class="td max-sm:flex max-sm:justify-between max-sm:px-0 max-sm:py-0.5"><span class="label mb-0 uppercase tracking-wide sm:hidden">MTU</span>{l.mtu}</td>
              <td class="td mono max-sm:flex max-sm:justify-between max-sm:px-0 max-sm:py-0.5 {l.master ? '' : 'max-sm:hidden'}"><span class="label mb-0 uppercase tracking-wide sm:hidden">Bridge</span>{l.master ?? ''}</td>
              <td class="td mono max-sm:flex max-sm:justify-between max-sm:gap-4 max-sm:px-0 max-sm:py-0.5 {l.addrs?.length ? '' : 'max-sm:hidden'}"><span class="label mb-0 shrink-0 uppercase tracking-wide sm:hidden">Addresses</span><span class="break-words max-sm:text-right">{(l.addrs ?? []).join(', ')}</span></td>
              <td class="td max-sm:flex max-sm:justify-between max-sm:px-0 max-sm:py-0.5 {l.managed_by?.length ? '' : 'max-sm:hidden'}">
                <span class="label mb-0 uppercase tracking-wide sm:hidden">Managed by</span>
                <span>
                  {#each l.managed_by ?? [] as m}<span class="badge mr-1 {m === 'mini-net-man' ? 'bg-accent-600/20 text-accent-300' : 'bg-slate-800 text-slate-300'}">{m}</span>{/each}
                  {#if clash(l)}<span class="badge bg-amber-500/20 text-amber-300" title="{others(l).join(' and ')} also manages this interface and may undo what mini-net-man sets on it.">both</span>{/if}
                </span>
              </td>
              <td class="td text-right whitespace-nowrap max-sm:flex max-sm:justify-end max-sm:px-0 max-sm:pt-2">
                {#if l.type !== 'loopback'}
                  {#if l.up}
                    <button class="btn btn-ghost btn-sm" disabled={busy === l.name} onclick={() => setState(l, 'down')}>Take down</button>
                  {:else}
                    <button class="btn btn-ghost btn-sm" disabled={busy === l.name} onclick={() => setState(l, 'up')}>Bring up</button>
                  {/if}
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>

  <p class="text-sm text-slate-500">
    A <b>bridge</b> joins interfaces into one network, like a switch. Put the IP address on the bridge, not on its ports: a port that keeps its own address stops answering on it. An interface can be in one bridge.
    Bridges mini-net-man creates are removed again when you delete the entry; ones that already existed are only joined to or released from.
  </p>
  <Resource
    title="Bridges"
    endpoint="/api/bridges"
    addLabel="Add bridge"
    onchange={changed}
    columns={[
      { key: 'name', label: 'Bridge', mono: true },
      { key: 'ports', label: 'Ports', mono: true, render: (b) => (b.ports ?? []).join(', ') },
      { key: 'stp', label: 'STP', render: (b) => (b.stp ? 'on' : '') },
      { key: 'mtu', label: 'MTU', render: (b) => b.mtu || '' },
      { key: 'comment', label: 'Comment' },
    ]}
    fields={[
      { key: 'name', label: 'Name', type: 'text', mono: true, placeholder: 'br0', help: 'Up to 15 characters. It is created if it does not exist, and brought up.' },
      { key: 'ports', label: 'Ports', type: 'list', mono: true, wide: true, placeholder: 'eth1, eth2', help: 'The interfaces to join, separated by commas. They must exist, and are brought up unless an Interface setting keeps them down. Ports you take out of this list are released.' },
      { key: 'stp', label: 'Spanning tree (STP)', type: 'checkbox', help: 'Turn on only if the bridge could end up connected to the same network twice, which would loop.' },
      { key: 'mtu', label: 'MTU', type: 'number', help: '0 leaves it as it is.' },
      { key: 'comment', label: 'Comment', type: 'text', wide: true, help: 'Optional note for yourself.' },
    ]}
    blank={() => ({ name: '', ports: [], stp: false, mtu: 0, comment: '', disabled: false })}
  />

  <Resource
    title="Interface settings"
    endpoint="/api/interfaces"
    addLabel="Add setting"
    onchange={changed}
    columns={[
      { key: 'name', label: 'Interface', mono: true },
      { key: 'state', label: 'Keep', render: (i) => (i.state ? `${i.state}` : '') },
      { key: 'mtu', label: 'MTU', render: (i) => i.mtu || '' },
      { key: 'comment', label: 'Comment' },
    ]}
    fields={[
      { key: 'name', label: 'Interface', type: 'iface', mono: true, placeholder: 'eth1', help: 'An interface that exists. The settings below are put back if something changes them.' },
      { key: 'state', label: 'Keep it', type: 'select', options: [{ value: '', label: 'as it is' }, { value: 'up', label: 'up' }, { value: 'down', label: 'down' }], help: 'Up or down. Taking down the interface this panel is reached through cuts you off: use Safe mode.' },
      { key: 'mtu', label: 'MTU', type: 'number', help: 'The largest packet it sends. 0 leaves it as it is. Removing the entry stops managing it but does not undo the change.' },
      { key: 'comment', label: 'Comment', type: 'text', wide: true, help: 'Optional note for yourself.' },
    ]}
    blank={() => ({ name: '', state: '', mtu: 0, comment: '', disabled: false })}
  />

  <p class="text-sm text-slate-500">Addresses you add here are kept on the interface by mini-net-man. Addresses configured by the OS (netplan, NetworkManager, wg-quick) are shown above and left alone.</p>
  <Resource
    title="Addresses"
    endpoint="/api/addresses"
    addLabel="Add address"
    onchange={changed}
    columns={[
      { key: 'address', label: 'Address', mono: true },
      { key: 'interface', label: 'Interface', mono: true },
      { key: 'comment', label: 'Comment' },
    ]}
    fields={[
      { key: 'address', label: 'Address', type: 'text', mono: true, placeholder: '10.0.0.1/16 or fd00::1/64', help: 'The address to give the interface, with its prefix length: 10.0.0.1/16 (IPv4) or fd00::1/64 (IPv6).' },
      { key: 'interface', label: 'Interface', type: 'iface', mono: true, placeholder: 'wgServer', help: 'Which interface gets it. Pick one from the list or type a name; it must already exist (a bridge you add above exists once it is applied).' },
      { key: 'comment', label: 'Comment', type: 'text', wide: true, help: 'Optional note for yourself.' },
    ]}
    blank={() => ({ address: '', interface: '', comment: '', disabled: false })}
  />
</div>
