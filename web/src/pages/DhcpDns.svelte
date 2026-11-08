<script>
  import Resource from '../lib/Resource.svelte'
  import { api } from '../lib/api.js'
  import { act, refreshOverview } from '../lib/state.svelte.js'

  let settings = $state({ enabled: false, dns: true, interfaces: '', upstreams: '', domain: '', cache_size: 0 })
  let status = $state(null)
  let leases = $state([])
  let configs = $state({ dnsmasq: '' })
  let showLog = $state(false)
  let showConfig = $state(false)
  let rev = $state(0)

  async function loadSettings() {
    const d = await api('GET', '/api/dnsmasq')
    settings = { ...d, interfaces: (d.interfaces ?? []).join(', '), upstreams: (d.upstreams ?? []).join(', ') }
  }
  async function loadLive() {
    status = await api('GET', '/api/dnsmasq/status').catch(() => null)
    leases = await api('GET', '/api/dhcp/leases').catch(() => [])
    configs = await api('GET', '/api/services/config').catch(() => ({ dnsmasq: '' }))
  }
  $effect(() => {
    loadSettings()
    loadLive()
    const t = setInterval(loadLive, 5000)
    return () => clearInterval(t)
  })
  function changed() {
    loadLive()
    refreshOverview()
  }

  const list = (s) => s.split(/[\s,]+/).filter(Boolean)
  async function save(e) {
    e.preventDefault()
    const body = { enabled: settings.enabled, dns: settings.dns, interfaces: list(settings.interfaces), upstreams: list(settings.upstreams), domain: settings.domain.trim(), cache_size: Number(settings.cache_size) || 0 }
    if (await act(() => api('PUT', '/api/dnsmasq', body), 'Saved')) {
      await loadSettings()
      changed()
    }
  }

  async function makeFixed(l) {
    if (await act(() => api('POST', '/api/dhcp/hosts', { mac: l.mac, ip: l.ip, hostname: l.hostname ?? '', comment: '', disabled: false }), `${l.ip} is now fixed for ${l.mac}`)) {
      rev++
      changed()
    }
  }

  const left = (n) => (n <= 0 ? 'never' : n >= 86400 ? `${Math.floor(n / 86400)}d ${Math.floor((n % 86400) / 3600)}h` : n >= 3600 ? `${Math.floor(n / 3600)}h ${Math.floor((n % 3600) / 60)}m` : n >= 60 ? `${Math.floor(n / 60)}m` : `${n}s`)
  const since = (t) => (t ? new Date(t).toLocaleTimeString() : '')
</script>

<div class="space-y-5">
  <p class="text-sm text-slate-500">
    Gives out IP addresses (DHCP) and answers DNS questions for the devices on your interfaces, using <span class="mono">dnsmasq</span>. mini-net-man runs its own copy with a config it writes itself, so it never touches the system's dnsmasq files. The firewall rules that let clients reach it (DHCP, DNS) are added for you and show up as <i>generated</i> on the Firewall page.
  </p>

  <section class="card space-y-3 p-4">
    <div class="flex flex-wrap items-center justify-between gap-2">
      <h2 class="text-sm font-semibold">Status</h2>
      <div class="flex gap-2">
        <button class="btn btn-sm" onclick={() => (showLog = !showLog)}>{showLog ? 'Hide log' : 'Log'}</button>
        <button class="btn btn-sm" onclick={() => (showConfig = !showConfig)}>{showConfig ? 'Hide config' : 'Generated config'}</button>
      </div>
    </div>
    {#if status}
      <div class="flex flex-wrap items-center gap-2 text-sm">
        {#if !status.installed}
          <span class="badge bg-red-500/20 text-red-300">not installed</span>
        {:else if status.running}
          <span class="badge bg-accent-600/20 text-accent-300">running</span>
          <span class="text-slate-500">since {since(status.since)}{status.restarts ? `, restarted ${status.restarts}×` : ''}</span>
        {:else if status.wanted}
          <span class="badge bg-amber-500/20 text-amber-300">not running</span>
        {:else}
          <span class="badge bg-slate-800 text-slate-400">off</span>
          <span class="text-slate-500">Switch it on below and add a DHCP scope, or turn on DNS.</span>
        {/if}
        {#if status.version}<span class="mono text-slate-500">dnsmasq {status.version}</span>{/if}
      </div>
      {#if status.problem}<p class="text-sm text-red-600 dark:text-red-400">{status.problem}. Install it with your package manager: the program is all that is needed, not its system service.</p>{/if}
      {#if status.last_error && !status.running}<p class="text-sm text-red-600 dark:text-red-400">Stopped: {status.last_error}</p>{/if}
      {#each status.conflicts as c}<p class="text-sm text-amber-600 dark:text-amber-400">⚠ {c}. Two programs can't both answer on a port: stop the other one, or dnsmasq won't start.</p>{/each}
      {#if showLog}<pre class="mono max-h-64 overflow-auto rounded-md bg-slate-950 p-3 text-xs whitespace-pre-wrap">{status.log.join('\n') || 'No output yet.'}</pre>{/if}
      {#if showConfig}<pre class="mono max-h-96 overflow-auto rounded-md bg-slate-950 p-3 text-xs whitespace-pre-wrap">{configs.dnsmasq || 'Nothing to run: nothing is switched on or there is no scope.'}</pre>{/if}
    {/if}
  </section>

  <form class="card space-y-4 p-4" onsubmit={save}>
    <h2 class="text-sm font-semibold">Settings</h2>
    <div class="flex flex-wrap gap-x-6 gap-y-2">
      <label class="flex items-center gap-2 text-sm"><input type="checkbox" class="size-4 accent-accent-600" bind:checked={settings.enabled} /> Run the DHCP and DNS server</label>
      <label class="flex items-center gap-2 text-sm"><input type="checkbox" class="size-4 accent-accent-600" bind:checked={settings.dns} /> Answer DNS questions too</label>
    </div>
    <div class="grid gap-3 sm:grid-cols-2">
      <div>
        <label class="label" for="up">Upstream DNS servers</label>
        <input id="up" class="input mono" bind:value={settings.upstreams} placeholder="1.1.1.1, 9.9.9.9" autocomplete="off" spellcheck="false" />
        <p class="hint">Where questions it can't answer go. Empty uses this machine's own (<span class="mono">/etc/resolv.conf</span>). <span class="mono">1.1.1.1#5353</span> picks a port.</p>
      </div>
      <div>
        <label class="label" for="dom">Local domain</label>
        <input id="dom" class="input mono" bind:value={settings.domain} placeholder="lan" autocomplete="off" spellcheck="false" />
        <p class="hint">Names without a dot (<span class="mono">nas</span>) are answered from here, and clients get it as their search domain.</p>
      </div>
      <div>
        <label class="label" for="ifs">Also answer DNS on these interfaces</label>
        <input id="ifs" class="input mono" bind:value={settings.interfaces} placeholder="wgServer" autocomplete="off" spellcheck="false" />
        <p class="hint">DNS is served on the interfaces of your DHCP scopes. Add others here, even with no DHCP, to be the DNS server for them.</p>
      </div>
      <div>
        <label class="label" for="cache">Cache size</label>
        <input id="cache" type="number" class="input" bind:value={settings.cache_size} />
        <p class="hint">Answers kept in memory. 0 means 1000; up to 10000.</p>
      </div>
    </div>
    <button class="btn btn-primary">Save</button>
  </form>

  <Resource
    title="DHCP scopes"
    endpoint="/api/dhcp/scopes"
    addLabel="Add scope"
    onchange={changed}
    columns={[
      { key: 'interface', label: 'Interface', mono: true },
      { key: 'start', label: 'Range', mono: true, render: (s) => `${s.start} – ${s.end}` },
      { key: 'lease_time', label: 'Lease', render: (s) => s.lease_time || '12h' },
      { key: 'router', label: 'Gateway', mono: true, render: (s) => s.router || 'this machine' },
      { key: 'dns', label: 'DNS', mono: true, render: (s) => (s.dns?.length ? s.dns.join(', ') : 'this machine') },
      { key: 'comment', label: 'Comment' },
    ]}
    fields={[
      { key: 'interface', label: 'Interface', type: 'iface', mono: true, placeholder: 'br0', help: 'Where addresses are handed out. It needs an address of its own in the same network as the range (add one on the Interfaces page).' },
      { key: 'start', label: 'First address', type: 'text', mono: true, placeholder: '192.168.50.100', help: 'The first address given to a device.' },
      { key: 'end', label: 'Last address', type: 'text', mono: true, placeholder: '192.168.50.200', help: 'The last one. Keep fixed addresses outside this range or inside it, either works.' },
      { key: 'lease_time', label: 'Lease time', type: 'text', placeholder: '12h', help: 'How long a device keeps an address before asking again: 30m, 12h, 2d, seconds, or infinite. Empty means 12h; at least 2 minutes.' },
      { key: 'router', label: 'Gateway sent to devices', type: 'text', mono: true, placeholder: 'empty = this machine', help: 'The default gateway devices should use. Empty is this machine’s address on the interface; none sends no gateway (a network with no internet).' },
      { key: 'dns', label: 'DNS servers sent to devices', type: 'list', mono: true, placeholder: 'empty = this machine', help: 'Separated by commas. Empty is this machine when it answers DNS, otherwise none.' },
      { key: 'domain', label: 'Search domain', type: 'text', mono: true, placeholder: 'optional', help: 'Overrides the local domain for this scope.' },
      { key: 'name', label: 'Name', type: 'text', help: 'Optional label.' },
      { key: 'comment', label: 'Comment', type: 'text', wide: true, help: 'Optional note for yourself.' },
    ]}
    blank={() => ({ name: '', interface: '', start: '', end: '', lease_time: '', router: '', dns: [], domain: '', comment: '', disabled: false })}
  />

  <section class="card">
    <header class="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
      <h2 class="text-sm font-semibold">Leases <span class="ml-1 font-normal text-slate-400">{leases.length}</span></h2>
      <button class="btn btn-sm" onclick={loadLive}>Refresh</button>
    </header>
    <div class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead class="border-b border-slate-200 dark:border-slate-800"><tr><th class="th">Address</th><th class="th">MAC</th><th class="th">Name</th><th class="th">Expires in</th><th class="th"></th></tr></thead>
        <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
          {#each leases as l (l.mac + l.ip)}
            <tr>
              <td class="td mono">{l.ip}</td>
              <td class="td mono">{l.mac}</td>
              <td class="td">{l.hostname ?? ''}{#if l.static}<span class="badge ml-2 bg-slate-800 text-slate-400">fixed</span>{/if}</td>
              <td class="td">{left(l.remaining)}</td>
              <td class="td text-right">{#if !l.static}<button class="btn btn-ghost btn-sm" title="Always give this device this address" onclick={() => makeFixed(l)}>Make fixed</button>{/if}</td>
            </tr>
          {:else}
            <tr><td class="td py-6 text-center text-slate-400" colspan="5">No devices have an address from here yet.</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>

  {#key rev}
    <Resource
      title="Fixed addresses"
      endpoint="/api/dhcp/hosts"
      addLabel="Add fixed address"
      searchable
      selectable
      onchange={changed}
      columns={[
        { key: 'mac', label: 'MAC address', mono: true },
        { key: 'ip', label: 'Address', mono: true },
        { key: 'hostname', label: 'Name' },
        { key: 'comment', label: 'Comment' },
      ]}
      fields={[
        { key: 'mac', label: 'MAC address', type: 'text', mono: true, placeholder: 'aa:bb:cc:dd:ee:ff', help: 'The device’s hardware address. Phones often use a different one per Wi-Fi network (a “private address”); use the one shown in the leases list.' },
        { key: 'ip', label: 'Address', type: 'text', mono: true, placeholder: '192.168.50.10', help: 'The address this device always gets. It must be in the scope’s network.' },
        { key: 'hostname', label: 'Name', type: 'text', mono: true, placeholder: 'nas', help: 'Optional. Also becomes a DNS name for the address.' },
        { key: 'comment', label: 'Comment', type: 'text', wide: true, help: 'Optional note for yourself.' },
      ]}
      blank={() => ({ mac: '', ip: '', hostname: '', comment: '', disabled: false })}
    />
  {/key}

  <Resource
    title="DNS records"
    endpoint="/api/dns/records"
    addLabel="Add record"
    searchable
    selectable
    onchange={changed}
    columns={[
      { key: 'name', label: 'Name', mono: true },
      { key: 'address', label: 'Points to', mono: true },
      { key: 'comment', label: 'Comment' },
    ]}
    fields={[
      { key: 'name', label: 'Name', type: 'text', mono: true, placeholder: 'router.lan', help: 'The name to answer for. Exactly this name, not its subdomains.' },
      { key: 'address', label: 'Points to', type: 'text', mono: true, placeholder: '192.168.50.1 or other.lan', help: 'An IP address (IPv4 or IPv6), or another name to make this an alias for it.' },
      { key: 'comment', label: 'Comment', type: 'text', wide: true, help: 'Optional note for yourself.' },
    ]}
    blank={() => ({ name: '', address: '', comment: '', disabled: false })}
  />
</div>
