<script>
  import { api } from '../lib/api.js'
  import { act, refreshOverview } from '../lib/state.svelte.js'

  let scan = $state(null)
  let sel = $state({ routes: {}, rules: {}, firewall: {}, policy: true })
  let scanning = $state(false)

  async function run() {
    scanning = true
    const res = await act(() => api('POST', '/api/import/scan'))
    scanning = false
    if (!res) return
    scan = res
    sel = { routes: {}, rules: {}, firewall: {}, policy: true }
    for (const k of ['routes', 'rules', 'firewall']) for (const x of res[k] ?? []) sel[k][x.id] = true
  }

  const ids = (m) => Object.keys(m).filter((k) => m[k])
  const count = $derived(scan ? ids(sel.routes).length + ids(sel.rules).length + ids(sel.firewall).length : 0)

  async function apply() {
    const ok = await act(
      () => api('POST', '/api/import/apply', { routes: ids(sel.routes), rules: ids(sel.rules), firewall: ids(sel.firewall), policy: sel.policy && !!scan.policy }),
      'Imported',
    )
    if (ok) {
      scan = null
      refreshOverview()
    }
  }
  async function disableUfw() {
    if (!confirm('Run `ufw disable`? ufw stops filtering immediately. Import its rules first if you want to keep them.')) return
    const r = await act(() => api('POST', '/api/import/disable-ufw'), 'ufw disabled')
    if (r) refreshOverview()
  }

  // IPv4 / IPv6 label for any proposed item.
  const fam = (x) =>
    x.family === 'ipv6' || [x.dst, x.src, x.gateway, x.to_addr].some((a) => (a ?? '').includes(':')) ? 'IPv6' : x.family === 'ipv4' ? 'IPv4' : ''
  const ruleText = (r) => `${r.priority}: ${[r.src && 'from ' + r.src, r.dst && 'to ' + r.dst, r.iif && 'iif ' + r.iif].filter(Boolean).join(' ') || 'all'} ${r.action === 'lookup' || !r.action ? 'lookup ' + r.table : r.action}`
  const routeText = (r) => `${r.dst}${r.gateway ? ' via ' + r.gateway : ''}${r.dev ? ' dev ' + r.dev : ''} table ${r.table}`
  const fwText = (r) =>
    `${r.chain}: ${r.action}${r.to_addr ? ' → ' + r.to_addr + (r.to_port ? ':' + r.to_port : '') : ''} ${[r.in_iface && 'in ' + r.in_iface, r.out_iface && 'out ' + r.out_iface, r.proto, r.src && 'from ' + r.src, r.dst && 'to ' + r.dst, r.dst_port && 'dport ' + r.dst_port, r.conn_state && 'state ' + r.conn_state].filter(Boolean).join(' ')}`
</script>

{#snippet group(title, key, list, text)}
  {#if list?.length}
    <section class="card">
      <header class="flex items-center justify-between border-b border-slate-200 px-4 py-3 dark:border-slate-800">
        <h3 class="text-sm font-semibold">{title} <span class="font-normal text-slate-400">{list.length}</span></h3>
        <div class="flex gap-1">
          <button class="btn btn-ghost btn-sm" onclick={() => list.forEach((x) => (sel[key][x.id] = true))}>All</button>
          <button class="btn btn-ghost btn-sm" onclick={() => list.forEach((x) => (sel[key][x.id] = false))}>None</button>
          {#if list.some((x) => fam(x) === 'IPv6')}
            <button class="btn btn-ghost btn-sm" onclick={() => list.forEach((x) => fam(x) === 'IPv6' && (sel[key][x.id] = false))}>Skip IPv6</button>
          {/if}
        </div>
      </header>
      <ul class="divide-y divide-slate-100 dark:divide-slate-800">
        {#each list as x (x.id)}
          <li>
            <label class="flex cursor-pointer items-center gap-3 px-4 py-2 hover:bg-slate-50 dark:hover:bg-slate-800/40">
              <input type="checkbox" class="size-4 accent-accent-600" bind:checked={sel[key][x.id]} />
              <span class="mono flex-1">{text(x)}</span>
              {#if fam(x)}<span class="badge {fam(x) === 'IPv6' ? 'bg-accent-600/20 text-accent-300' : 'bg-slate-800 text-slate-400'}">{fam(x)}</span>{/if}
              <span class="badge bg-slate-800 text-slate-400">{x.source}</span>
            </label>
          </li>
        {/each}
      </ul>
    </section>
  {/if}
{/snippet}

<div class="space-y-5">
  <section class="card p-4">
    <h2 class="text-sm font-semibold">Import existing configuration</h2>
    <p class="mt-1 max-w-2xl text-sm text-slate-500">
      Scans live <span class="mono">ip rule</span> / <span class="mono">ip route</span>, <span class="mono">iptables-save</span>, ufw (<span class="mono">/etc/ufw/user.rules</span>) and iptables-persistent (<span class="mono">/etc/iptables/rules.v4</span>), and proposes matching entries. Nothing changes until you apply. Importing copies rules into mini-net-man; it does not remove the originals.
    </p>
    <div class="mt-3 flex gap-2">
      <button class="btn btn-primary" onclick={run} disabled={scanning}>{scanning ? 'Scanning…' : scan ? 'Scan again' : 'Scan this machine'}</button>
      <button class="btn btn-danger" onclick={disableUfw}>Disable ufw…</button>
    </div>
  </section>

  {#if scan}
    {#if scan.notes?.length}
      <div class="card border-amber-300 p-4 text-sm dark:border-amber-800">
        <ul class="list-disc space-y-1 pl-5">{#each scan.notes as n}<li>{n}</li>{/each}</ul>
      </div>
    {/if}

    {#if !(scan.routes?.length || scan.rules?.length || scan.firewall?.length)}
      <p class="text-sm text-slate-500">Nothing new to import.</p>
    {/if}

    {@render group('Routes', 'routes', scan.routes, routeText)}
    {@render group('Policy rules', 'rules', scan.rules, ruleText)}
    {@render group('Firewall rules', 'firewall', scan.firewall, fwText)}

    {#if scan.policy}
      <label class="card flex items-center gap-3 p-4 text-sm">
        <input type="checkbox" class="size-4 accent-accent-600" bind:checked={sel.policy} />
        <span>Also set default policies to <span class="mono">input {scan.policy.input} · forward {scan.policy.forward} · output {scan.policy.output}</span> (what ufw uses)</span>
      </label>
    {/if}

    {#if count || (scan.policy && sel.policy)}
      <div class="sticky bottom-4 flex justify-end">
        <button class="btn btn-primary shadow-lg" onclick={apply}>Import {count} item{count === 1 ? '' : 's'}</button>
      </div>
    {/if}
  {/if}
</div>
