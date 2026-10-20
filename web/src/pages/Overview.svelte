<script>
  import { api } from '../lib/api.js'
  import { app, act, refreshOverview } from '../lib/state.svelte.js'

  const o = $derived(app.overview)
  const fmt = (n) => {
    if (!n) return '0 B'
    const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
    const i = Math.min(u.length - 1, Math.floor(Math.log2(n) / 10))
    return (n / 1024 ** i).toFixed(i ? 1 : 0) + ' ' + u[i]
  }

  async function setForward(on) {
    if (await act(() => api('PUT', '/api/sysctl', { ip_forward: on }), on ? 'IP forwarding enabled' : 'IP forwarding disabled')) refreshOverview()
  }
  async function reapply() {
    if (await act(() => api('POST', '/api/reapply'), 'Reapplied')) refreshOverview()
  }
</script>

{#if o}
  <div class="space-y-5">
    <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {#each [['Addresses', o.counts.addresses, '#/interfaces'], ['Routes', o.counts.routes, '#/routes'], ['Policy rules', o.counts.rules, '#/rules'], ['Firewall rules', o.counts.firewall, '#/firewall']] as [label, n, href]}
        <a {href} class="card block p-4 transition-colors hover:border-accent-600">
          <div class="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
          <div class="mt-1 text-2xl font-semibold tabular-nums">{n}</div>
        </a>
      {/each}
    </div>

    {#if o.issues.length}
      <div class="card border-red-300 p-4 dark:border-red-900">
        <h2 class="mb-2 text-sm font-semibold text-red-700 dark:text-red-400">Some items could not be applied</h2>
        <ul class="space-y-1 text-sm">
          {#each o.issues as i}<li><span class="badge bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300">{i.kind}</span> {i.message}</li>{/each}
        </ul>
        <button class="btn btn-sm mt-3" onclick={reapply}>Try again</button>
      </div>
    {/if}

    {#if o.detect.warnings.length}
      <div class="card border-amber-300 p-4 dark:border-amber-800">
        <h2 class="mb-2 text-sm font-semibold text-amber-700 dark:text-amber-400">Heads up</h2>
        <ul class="list-disc space-y-1 pl-5 text-sm">
          {#each o.detect.warnings as w}<li>{w}</li>{/each}
        </ul>
        {#if o.detect.ufw_active || o.detect.iptables_persistent_files.length}
          <a href="#/import" class="btn btn-sm mt-3">Review & import existing rules</a>
        {/if}
      </div>
    {/if}

    <section class="card">
      <header class="border-b border-slate-200 px-4 py-3 dark:border-slate-800"><h2 class="text-sm font-semibold">Interfaces</h2></header>
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead class="border-b border-slate-200 dark:border-slate-800"><tr>
            {#each ['Name', 'Type', 'State', 'Addresses', 'MTU', 'Rx', 'Tx'] as h}<th class="th">{h}</th>{/each}
          </tr></thead>
          <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
            {#each o.links as l (l.name)}
              <tr>
                <td class="td mono font-medium">{l.name}</td>
                <td class="td text-slate-500">{l.type}</td>
                <td class="td">
                  <span class="badge {l.up ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300' : 'bg-slate-200 text-slate-600 dark:bg-slate-800 dark:text-slate-400'}">{l.up ? 'up' : 'down'}</span>
                </td>
                <td class="td mono">{(l.addrs ?? []).join(', ')}</td>
                <td class="td tabular-nums text-slate-500">{l.mtu}</td>
                <td class="td tabular-nums text-slate-500">{fmt(l.rx_bytes)}</td>
                <td class="td tabular-nums text-slate-500">{fmt(l.tx_bytes)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>

    <div class="grid gap-4 lg:grid-cols-2">
      <section class="card p-4">
        <h2 class="mb-3 text-sm font-semibold">IP forwarding</h2>
        <p class="mb-3 text-sm text-slate-500">Needed for any traffic that passes through this machine (routing between interfaces).</p>
        <div class="flex items-center gap-3">
          <span class="badge {o.ip_forward ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300' : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'}">{o.ip_forward ? 'enabled' : 'disabled'}</span>
          <button class="btn btn-sm" onclick={() => setForward(!o.ip_forward)}>{o.ip_forward ? 'Disable' : 'Enable'} and keep it that way</button>
        </div>
        <p class="mt-2 text-xs text-slate-500">{o.ip_forward_managed ? 'mini-net-man sets this at startup.' : 'Not managed: left as the system has it.'}</p>
      </section>

      <section class="card p-4">
        <h2 class="mb-3 text-sm font-semibold">Detected tools</h2>
        <ul class="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
          {#each o.detect.tools as t}
            <li class="flex items-center gap-2">
              <span class="size-2 rounded-full {t.installed ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-slate-700'}"></span>
              <span class="mono">{t.name}</span>
            </li>
          {/each}
        </ul>
        <p class="mt-3 text-xs text-slate-500">
          ufw: {o.detect.ufw_active ? 'active' : 'inactive'}
          {#if o.detect.iptables_backend} · iptables backend: {o.detect.iptables_backend}{/if}
        </p>
      </section>
    </div>
  </div>
{/if}
