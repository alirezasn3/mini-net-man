<script>
  import { api } from '../lib/api.js'
  import Resource from '../lib/Resource.svelte'
  import { act, refreshOverview } from '../lib/state.svelte.js'

  let cfg = $state({ enabled: false, table_base: 200, priority_base: 10000, exits: [] })
  let generated = $state({ routes: [], rules: [], firewall: [] })

  async function reload() {
    const [c, g] = await Promise.all([api('GET', '/api/client-routing'), api('GET', '/api/generated')])
    cfg = { table_base: 200, priority_base: 10000, exits: [], ...c }
    generated = g
    refreshOverview()
  }
  $effect(() => {
    reload()
  })

  async function saveSettings() {
    await act(() => api('PUT', '/api/client-routing', { enabled: cfg.enabled, table_base: Number(cfg.table_base), priority_base: Number(cfg.priority_base) }), 'Saved')
    await reload()
  }
  const total = $derived(generated.routes.length + generated.rules.length + generated.firewall.length)
</script>

<div class="space-y-5">
  <section class="card p-4">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div class="max-w-2xl">
        <h2 class="text-sm font-semibold">Client routing</h2>
        <p class="mt-1 text-sm text-slate-500">
          An optional shortcut: send traffic from chosen clients out through a chosen interface (for example, VPN clients on <span class="mono">wgServer</span> exiting through <span class="mono">wgBridge1</span>).
          It only creates ordinary routes, policy rules and firewall entries, shown as <span class="badge bg-accent-100 text-accent-800 dark:bg-accent-800/40 dark:text-accent-100">generated</span> on their own pages. Turn it off and they disappear. Nothing else depends on it.
        </p>
      </div>
      <label class="flex items-center gap-2 text-sm font-medium">
        <input type="checkbox" class="size-4 accent-accent-600" bind:checked={cfg.enabled} onchange={saveSettings} />
        Enabled
      </label>
    </div>
    <div class="mt-4 flex flex-wrap items-end gap-4">
      <div><label class="label" for="tb">First routing table</label><input id="tb" type="number" class="input w-32" bind:value={cfg.table_base} /></div>
      <div><label class="label" for="pb">First rule priority</label><input id="pb" type="number" class="input w-32" bind:value={cfg.priority_base} /></div>
      <button class="btn btn-sm" onclick={saveSettings}>Save</button>
    </div>
    {#if cfg.exits.length}
      <p class="mt-3 text-xs text-slate-500">Tables in use: {cfg.exits.map((e) => `${e.interface} → ${e.table}`).join(', ')}</p>
    {/if}
  </section>

  <Resource
    title="Clients"
    endpoint="/api/client-routing/clients"
    addLabel="Add client"
    onchange={reload}
    columns={[
      { key: 'name', label: 'Name' },
      { key: 'src', label: 'Client IP / network', mono: true },
      { key: 'in', label: 'Arrives on', mono: true },
      { key: 'out', label: 'Exits via', mono: true },
      { key: 'kill_switch', label: 'Kill switch', render: (c) => (c.kill_switch ? 'on' : 'off') },
    ]}
    fields={[
      { key: 'name', label: 'Name', type: 'text', placeholder: 'alice-laptop', wide: true },
      { key: 'src', label: 'Client IP or network', type: 'text', mono: true, placeholder: '10.0.0.5' },
      { key: 'in', label: 'Client-facing interface', type: 'iface', mono: true, placeholder: 'wgServer' },
      { key: 'out', label: 'Exit interface', type: 'iface', mono: true, placeholder: 'wgBridge1' },
      { key: 'kill_switch', label: 'Kill switch: drop traffic if the exit is down', type: 'checkbox', wide: true },
    ]}
    blank={() => ({ name: '', src: '', in: '', out: '', kill_switch: true, disabled: false })}
  />

  {#if cfg.enabled && total}
    <section class="card p-4">
      <h2 class="mb-2 text-sm font-semibold">What this creates ({total} items)</h2>
      <ul class="mono space-y-0.5 text-slate-600 dark:text-slate-400">
        {#each generated.routes as r}<li>route {r.dst} {r.dev ? 'dev ' + r.dev : ''} table {r.table}</li>{/each}
        {#each generated.rules as r}<li>rule {r.priority}: {r.src ? 'from ' + r.src : ''} {r.action === 'lookup' || !r.action ? 'lookup ' + r.table : r.action}</li>{/each}
        {#each generated.firewall as r}<li>firewall {r.chain}: {r.action} {r.in_iface ? 'in ' + r.in_iface : ''} {r.out_iface ? 'out ' + r.out_iface : ''} {r.conn_state ? 'state ' + r.conn_state : ''}</li>{/each}
      </ul>
      <p class="mt-3 text-xs text-slate-500">IP forwarding must also be on (Overview).</p>
    </section>
  {/if}
</div>
