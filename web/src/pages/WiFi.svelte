<script>
  import Resource from '../lib/Resource.svelte'
  import { api } from '../lib/api.js'
  import { act, refreshOverview } from '../lib/state.svelte.js'

  let links = $state([])
  let states = $state([])
  let configs = $state({ hostapd: {} })
  let open = $state({}) // which access points have their log or config showing

  async function loadLive() {
    states = await api('GET', '/api/access-points/status').catch(() => [])
    configs = await api('GET', '/api/services/config').catch(() => ({ hostapd: {} }))
  }
  $effect(() => {
    api('GET', '/api/links').then((l) => (links = l)).catch(() => {})
    loadLive()
    const t = setInterval(loadLive, 5000)
    return () => clearInterval(t)
  })
  function changed() {
    loadLive()
    refreshOverview()
  }

  const wireless = $derived(links.filter((l) => l.wireless).map((l) => l.name))
  const bridges = $derived(links.filter((l) => l.type === 'bridge').map((l) => l.name))
  const stateOf = (id) => states.find((s) => s.id === id)

  async function kick(ap, mac) {
    if (!confirm(`Disconnect ${mac}? It may reconnect straight away; this is not a ban.`)) return
    if (await act(() => api('POST', `/api/access-points/${ap.id}/kick`, { mac }), 'Disconnected')) loadLive()
  }

  const dur = (n) => (n >= 3600 ? `${Math.floor(n / 3600)}h ${Math.floor((n % 3600) / 60)}m` : n >= 60 ? `${Math.floor(n / 60)}m` : `${n}s`)
  const bytes = (n) => (n >= 1e9 ? (n / 1e9).toFixed(1) + ' GB' : n >= 1e6 ? (n / 1e6).toFixed(1) + ' MB' : n >= 1e3 ? Math.round(n / 1e3) + ' kB' : n + ' B')
  const bars = (dbm) => (!dbm ? '' : dbm >= -55 ? 'excellent' : dbm >= -67 ? 'good' : dbm >= -75 ? 'fair' : 'weak')

  const secLabel = { open: 'open', wpa2: 'WPA2', wpa3: 'WPA3', 'wpa2+wpa3': 'WPA2/WPA3' }
  const chip = (ap) => {
    const s = stateOf(ap.id)
    if (ap.disabled || !s) return null
    if (!s.process.installed) return { text: 'hostapd missing', cls: 'bg-red-500/20 text-red-300', title: s.process.problem }
    if (!s.exists) return { text: 'no such interface', cls: 'bg-red-500/20 text-red-300', title: `${ap.interface} does not exist` }
    if (!s.process.running) return { text: 'not running', cls: 'bg-amber-500/20 text-amber-300', title: s.process.last_error || '' }
    const n = s.radio?.clients ?? s.stations.length
    return { text: `${n} client${n === 1 ? '' : 's'}`, cls: 'bg-accent-600/20 text-accent-300', title: s.radio ? `${s.radio.state}, channel ${s.radio.channel}` : '' }
  }
</script>

<div class="space-y-5">
  <p class="text-sm text-slate-500">
    Turns a Wi-Fi card into an access point with <span class="mono">hostapd</span>. mini-net-man runs one hostapd per access point with a config it writes itself. Put the Wi-Fi in a <b>bridge</b> (so its devices share a network with the bridge's other ports and get addresses from its DHCP scope) or give the interface its own address and DHCP scope on the <a class="underline" href="#/dhcp-dns">DHCP &amp; DNS</a> page.
    The Wi-Fi card has to support access point mode, and nothing else may be controlling it: NetworkManager or <span class="mono">wpa_supplicant</span> on the same interface will fight hostapd.
  </p>

  {#if !wireless.length && links.length}
    <p class="rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-700 dark:text-amber-300">No Wi-Fi interface found on this machine. The access point can still be set up here for an interface that appears later (a USB adapter).</p>
  {/if}

  <Resource
    title="Access points"
    endpoint="/api/access-points"
    addLabel="Add access point"
    onchange={changed}
    rowBadge={chip}
    columns={[
      { key: 'ssid', label: 'Network name' },
      { key: 'interface', label: 'Interface', mono: true },
      { key: 'band', label: 'Band', render: (a) => `${a.band} GHz, ${a.channel ? 'channel ' + a.channel : 'automatic'}` },
      { key: 'security', label: 'Security', render: (a) => secLabel[a.security] ?? a.security },
      { key: 'bridge', label: 'Bridge', mono: true },
    ]}
    fields={[
      { key: 'interface', label: 'Wi-Fi interface', type: 'select', mono: true, options: [...new Set(['', ...wireless])].map((n) => ({ value: n, label: n || 'choose…' })), help: 'The Wi-Fi card to use. Only wireless interfaces are listed.' },
      { key: 'ssid', label: 'Network name (SSID)', type: 'text', placeholder: 'Home', help: 'What devices see when they look for Wi-Fi. Up to 32 bytes.' },
      { key: 'security', label: 'Security', type: 'select', options: [{ value: 'wpa2+wpa3', label: 'WPA2 + WPA3 (recommended)' }, { value: 'wpa2', label: 'WPA2 only (oldest devices)' }, { value: 'wpa3', label: 'WPA3 only' }, { value: 'open', label: 'Open, no password' }], help: 'WPA2 + WPA3 lets newer devices use WPA3 and older ones WPA2. An open network lets anyone join and read their own traffic.' },
      { key: 'passphrase', label: 'Password', type: 'password', placeholder: 'leave empty to keep the current one', help: '8 to 63 characters (WPA2 also takes a 64-digit key). It is stored in the config and never shown again, so leave this empty when editing to keep it.', show: (d) => d.security !== 'open' },
      { key: 'band', label: 'Band', type: 'select', options: [{ value: '2.4', label: '2.4 GHz (longer range)' }, { value: '5', label: '5 GHz (faster)' }], help: 'The card has to support the band.' },
      { key: 'channel', label: 'Channel', type: 'number', help: '0 lets the driver choose (not every driver can). 2.4 GHz: 1, 6 or 11 overlap least. 5 GHz: 36 to 165; the ones from 52 to 144 can be paused by radar detection.' },
      { key: 'country', label: 'Country code', type: 'text', mono: true, placeholder: 'DE', help: 'Two capital letters. The allowed channels and transmit power depend on it, and it is required for 5 GHz. Use the country the access point is in.' },
      { key: 'bridge', label: 'Bridge', type: 'text', mono: true, datalist: 'bridges', placeholder: 'br0', help: 'Join the Wi-Fi to this bridge. Don’t also list this interface as a port on the Interfaces page: hostapd does the joining.' },
      { key: 'max_clients', label: 'Most devices', type: 'number', help: '0 leaves it to the card.' },
      { key: 'n', label: '802.11n (Wi-Fi 4)', type: 'checkbox', help: 'Faster speeds than the oldest standard. Almost every device supports it.' },
      { key: 'ac', label: '802.11ac (Wi-Fi 5), 5 GHz only', type: 'checkbox' },
      { key: 'ax', label: '802.11ax (Wi-Fi 6)', type: 'checkbox', help: 'Only if the card and driver support it; otherwise hostapd won’t start.' },
      { key: 'hidden', label: 'Hidden network', type: 'checkbox', help: 'Don’t announce the name. This hides it from lists but is not a security measure.' },
      { key: 'isolate', label: 'Isolate devices from each other', type: 'checkbox', help: 'For a guest network: devices can reach the internet but not each other.' },
      { key: 'comment', label: 'Comment', type: 'text', wide: true, help: 'Optional note for yourself.' },
    ]}
    blank={() => ({ interface: wireless[0] ?? '', ssid: '', hidden: false, band: '2.4', channel: 0, country: '', security: 'wpa2+wpa3', passphrase: '', bridge: '', isolate: false, max_clients: 0, n: true, ac: false, ax: false, comment: '', disabled: false })}
  />
  <datalist id="bridges">
    {#each bridges as b}<option value={b}></option>{/each}
  </datalist>

  {#each states as s (s.id)}
    {@const ap = { id: s.id, interface: s.interface }}
    <section class="card">
      <header class="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
        <h2 class="text-sm font-semibold">
          <span class="mono">{s.interface}</span>
          {#if s.process.running}<span class="badge ml-2 bg-accent-600/20 text-accent-300">{s.radio?.state ?? 'running'}</span>{:else if s.process.wanted}<span class="badge ml-2 bg-amber-500/20 text-amber-300">not running</span>{:else}<span class="badge ml-2 bg-slate-800 text-slate-400">off</span>{/if}
          {#if s.radio}<span class="ml-2 font-normal text-slate-400">channel {s.radio.channel}, {s.radio.freq} MHz</span>{/if}
        </h2>
        <div class="flex gap-2">
          <button class="btn btn-sm" onclick={() => (open[s.id] = open[s.id] === 'log' ? '' : 'log')}>{open[s.id] === 'log' ? 'Hide log' : 'Log'}</button>
          <button class="btn btn-sm" onclick={() => (open[s.id] = open[s.id] === 'conf' ? '' : 'conf')}>{open[s.id] === 'conf' ? 'Hide config' : 'Generated config'}</button>
        </div>
      </header>
      <div class="space-y-3 p-4 text-sm">
        {#if !s.process.installed && s.process.wanted}<p class="text-red-600 dark:text-red-400">{s.process.problem}</p>{/if}
        {#if !s.exists}<p class="text-red-600 dark:text-red-400">There is no interface called {s.interface} on this machine.</p>
        {:else if !s.wireless}<p class="text-amber-600 dark:text-amber-400">{s.interface} is not a Wi-Fi interface.</p>{/if}
        {#if s.managed_by?.length}<p class="text-amber-600 dark:text-amber-400">⚠ {s.managed_by.join(' and ')} also manages {s.interface} and will fight hostapd for it. For NetworkManager: <span class="mono">nmcli device set {s.interface} managed no</span>.</p>{/if}
        {#if s.process.last_error && !s.process.running}<p class="text-red-600 dark:text-red-400">Stopped: {s.process.last_error}. The log below usually says why (a card without access point mode, a channel the country doesn't allow, rfkill).</p>{/if}
        {#if s.error}<p class="text-amber-600 dark:text-amber-400">{s.error}</p>{/if}
        {#if open[s.id] === 'log'}<pre class="mono max-h-64 overflow-auto rounded-md bg-slate-950 p-3 text-xs whitespace-pre-wrap">{s.process.log.join('\n') || 'No output yet.'}</pre>{/if}
        {#if open[s.id] === 'conf'}<pre class="mono max-h-96 overflow-auto rounded-md bg-slate-950 p-3 text-xs whitespace-pre-wrap">{configs.hostapd[s.interface] ?? ''}</pre>{/if}
        {#if s.process.running}
          <div class="overflow-x-auto">
            <table class="w-full">
              <thead class="border-b border-slate-200 dark:border-slate-800"><tr><th class="th">Device</th><th class="th">Signal</th><th class="th">Connected</th><th class="th">Down / up</th><th class="th"></th></tr></thead>
              <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
                {#each s.stations as st (st.mac)}
                  <tr>
                    <td class="td mono">{st.mac}</td>
                    <td class="td">{st.signal ? `${st.signal} dBm` : ''} <span class="text-slate-500">{bars(st.signal)}</span></td>
                    <td class="td">{dur(st.connected_secs)}</td>
                    <td class="td">{bytes(st.tx_bytes)} / {bytes(st.rx_bytes)}</td>
                    <td class="td text-right"><button class="btn btn-ghost btn-sm" onclick={() => kick(ap, st.mac)}>Disconnect</button></td>
                  </tr>
                {:else}
                  <tr><td class="td py-5 text-center text-slate-400" colspan="5">No devices connected.</td></tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      </div>
    </section>
  {/each}
</div>
