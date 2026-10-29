<script>
  import Resource from '../lib/Resource.svelte'
  import { api } from '../lib/api.js'
  import { act, refreshOverview, toast } from '../lib/state.svelte.js'

  let names = $state([])
  let dynamic = $state([])
  let domains = $state([])
  let bulk = $state({ list: '', text: '', comment: '', replace: false })
  let busy = $state(false)
  let rev = $state(0) // bumped to make the entries table fetch again

  async function loadNames() {
    names = [...new Set((await api('GET', '/api/address-lists').catch(() => [])).map((e) => e.list))].sort()
  }
  async function loadDynamic() {
    dynamic = await api('GET', '/api/address-lists/dynamic').catch(() => [])
    domains = await api('GET', '/api/address-lists/domains').catch(() => [])
  }
  $effect(() => {
    loadNames()
    loadDynamic()
    // What rules add comes and goes by itself.
    const t = setInterval(loadDynamic, 5000)
    return () => clearInterval(t)
  })
  function changed() {
    loadNames()
    refreshOverview()
  }

  async function addMany(e) {
    e.preventDefault()
    if (bulk.replace && !confirm(`Replace everything in the list "${bulk.list}" with these addresses?`)) return
    busy = true
    const r = await act(() => api('POST', '/api/address-lists/bulk', { list: bulk.list, addresses: bulk.text, comment: bulk.comment, replace: bulk.replace }))
    busy = false
    if (r) {
      toast(`${r.added} added${r.skipped ? `, ${r.skipped} already there` : ''}`)
      bulk = { ...bulk, text: '', replace: false }
      rev++
      changed()
    }
  }

  async function removeDyn(d) {
    if (await act(() => api('DELETE', `/api/address-lists/dynamic?list=${encodeURIComponent(d.list)}&address=${encodeURIComponent(d.address)}`), 'Removed')) loadDynamic()
  }
  async function flush(list) {
    if (!confirm(list ? `Remove every address rules added to "${list}"?` : 'Remove every address rules added to any list?')) return
    if (await act(() => api('DELETE', '/api/address-lists/dynamic' + (list ? `?list=${encodeURIComponent(list)}` : '')), 'Removed')) loadDynamic()
  }

  // The chip next to a domain entry: what it resolved to, or why it didn't.
  const domainChip = (e) => {
    const name = e.address.toLowerCase().replace(/\.$/, '')
    if (e.disabled || !/[a-z]/.test(name.split('.').pop() ?? '') || !/^[a-z0-9_.-]+$/.test(name)) return null
    const st = domains.find((d) => d.list === e.list && d.domain === name)
    if (!st) return { text: 'looking up…', cls: 'bg-slate-800 text-slate-400', title: 'Not looked up yet' }
    if (st.error && !st.addresses.length) return { text: 'lookup failed', cls: 'bg-red-500/20 text-red-300', title: `${st.error}. Trying again at ${new Date(st.next_at).toLocaleTimeString()}.` }
    const n = st.addresses.length
    return {
      text: `${n} address${n === 1 ? '' : 'es'}`,
      cls: st.error ? 'bg-amber-500/20 text-amber-300' : 'bg-accent-600/20 text-accent-300',
      title: `${st.addresses.join(', ')}${st.error ? `\nLast lookup failed: ${st.error}` : ''}\nNext lookup ${new Date(st.next_at).toLocaleTimeString()}`,
    }
  }

  const left = (n) => (n <= 0 ? 'never' : n >= 86400 ? `${Math.floor(n / 86400)}d ${Math.floor((n % 86400) / 3600)}h` : n >= 3600 ? `${Math.floor(n / 3600)}h ${Math.floor((n % 3600) / 60)}m` : n >= 60 ? `${Math.floor(n / 60)}m ${n % 60}s` : `${n}s`)
  const dynGroups = $derived(
    Object.entries(Object.groupBy(dynamic, (d) => d.list))
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([list, items]) => ({ list, items: items.sort((a, b) => a.address.localeCompare(b.address, undefined, { numeric: true })) })),
  )
</script>

<datalist id="lists">
  {#each names as n}<option value={n}></option>{/each}
</datalist>

<div class="space-y-5">
  <p class="text-sm text-slate-500">
    An address list is a named set of addresses, like MikroTik's <span class="mono">/ip firewall address-list</span>. Each row puts one IP, network (<span class="mono">10.0.0.0/8</span>), range (<span class="mono">10.0.0.5-10.0.0.20</span>) or <b>domain name</b> (<span class="mono">example.com</span>) in a list, IPv4 or IPv6; a list can hold both. A name is looked up by this machine and its addresses stay in the list as long as DNS says they are valid, so they follow the name when it changes. On the <a class="underline" href="#/firewall">Firewall</a> page a rule can match a list (<b>Source in address list</b>, <b>Destination in address list</b>, with <span class="mono">!</span> for "not in") and can <b>add</b> the source or destination of matching packets to a list for a while, which is how you build things like a blocklist, a whitelist, or "block anyone who tries SSH five times".
  </p>

  {#key rev}
  <Resource
    title="Address list entries"
    endpoint="/api/address-lists"
    addLabel="Add address"
    groupBy={(e) => e.list}
    pageSize={200}
    searchable
    selectable
    rowBadge={domainChip}
    onchange={changed}
    columns={[
      { key: 'list', label: 'List', mono: true },
      { key: 'address', label: 'Address', mono: true },
      { key: 'comment', label: 'Comment' },
    ]}
    fields={[
      { key: 'list', label: 'List', type: 'text', mono: true, datalist: 'lists', placeholder: 'blocklist', help: 'The name of the list. A new name makes a new list. Start with a letter; letters, digits, _ - and . after that; at most 24 characters.' },
      { key: 'address', label: 'Address', type: 'text', mono: true, placeholder: '203.0.113.0/24, 198.51.100.5-198.51.100.9, example.com', help: 'One IP, a network, a range from-to, or a domain name. A name covers exactly that name, not its subdomains, and only the addresses this machine\u2019s DNS returns for it. Overlapping entries are merged for you.' },
      { key: 'comment', label: 'Comment', type: 'text', wide: true, help: 'Optional note for yourself.' },
    ]}
    blank={() => ({ list: names[0] ?? '', address: '', comment: '', disabled: false })}
  />
  {/key}

  <form class="card space-y-3 p-4" onsubmit={addMany}>
    <h2 class="text-sm font-semibold">Add many at once</h2>
    <p class="text-sm text-slate-500">Paste a blocklist: one address, network, range or domain name per line, or separated by spaces or commas. Everything after <span class="mono">#</span> or <span class="mono">;</span> on a line is ignored. If any entry is invalid nothing is added.</p>
    <div class="grid gap-3 sm:grid-cols-2">
      <div><label class="label" for="bl-list">List</label><input id="bl-list" class="input mono" list="lists" autocomplete="off" placeholder="blocklist" bind:value={bulk.list} /></div>
      <div><label class="label" for="bl-comment">Comment on each (optional)</label><input id="bl-comment" class="input" autocomplete="off" bind:value={bulk.comment} /></div>
    </div>
    <textarea class="input mono" rows="6" aria-label="Addresses" placeholder="203.0.113.0/24&#10;198.51.100.5-198.51.100.9&#10;2001:db8::/32" bind:value={bulk.text}></textarea>
    <div class="flex flex-wrap items-center justify-between gap-3">
      <label class="flex items-center gap-2 text-sm"><input type="checkbox" class="size-4 accent-accent-600" bind:checked={bulk.replace} /> Replace everything already in this list</label>
      <button class="btn btn-primary" disabled={busy || !bulk.list || !bulk.text.trim()}>{busy ? 'Adding…' : 'Add addresses'}</button>
    </div>
  </form>

  <section class="card">
    <header class="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
      <h2 class="text-sm font-semibold">Added by rules and domain names <span class="ml-1 font-normal text-slate-400">{dynamic.length}</span></h2>
      <div class="flex gap-2">
        <button class="btn btn-sm" onclick={loadDynamic}>Refresh</button>
        {#if dynamic.length}<button class="btn btn-sm" onclick={() => flush('')}>Remove all</button>{/if}
      </div>
    </header>
    <div class="space-y-4 p-4 text-sm">
      <p class="text-slate-500">Addresses that <b>add-src-to-list</b> and <b>add-dst-to-list</b> rules put in a list, and the addresses of the domain names above. They live in the kernel, expire by themselves, and stay while you change the firewall. They are not in your config, so after a reboot rules start again from nothing and names are looked up afresh. A rule that matches a list matches these as well as the rows above.</p>
      {#each dynGroups as g (g.list)}
        <div>
          <div class="mb-1 flex items-center justify-between">
            <span class="mono font-semibold">{g.list} <span class="font-normal text-slate-400">{g.items.length}</span></span>
            <button class="btn btn-ghost btn-sm" onclick={() => flush(g.list)}>Remove all from this list</button>
          </div>
          <ul class="divide-y divide-slate-200 rounded-md border border-slate-200 dark:divide-slate-800 dark:border-slate-800">
            {#each g.items.slice(0, 100) as d (d.address)}
              <li class="flex items-center justify-between gap-3 px-3 py-1.5">
                <span class="mono">{d.address}{#if d.domain}<span class="ml-2 text-slate-500">{d.domain}</span>{/if}</span>
                <span class="flex items-center gap-3 text-slate-500">
                  <span>{d.remaining > 0 ? 'expires in ' + left(d.remaining) : 'does not expire'}</span>
                  <button class="btn btn-ghost btn-sm text-red-600 dark:text-red-400" onclick={() => removeDyn(d)}>Remove</button>
                </span>
              </li>
            {/each}
          </ul>
          {#if g.items.length > 100}<p class="hint mt-1">Showing the first 100 of {g.items.length}.</p>{/if}
        </div>
      {:else}
        <p class="text-slate-500">Nothing yet.</p>
      {/each}
    </div>
  </section>
</div>
