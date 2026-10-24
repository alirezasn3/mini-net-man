<script>
  import { api } from '../lib/api.js'
  import { act, toast } from '../lib/state.svelte.js'

  let items = $state([])
  let loaded = $state(false)
  let draft = $state({}) // text of the number boxes, by setting id

  async function load() {
    items = await api('GET', '/api/tuning')
    for (const it of items) if (it.kind === 'int') draft[it.id] = it.managed || it.current || ''
    loaded = true
  }
  $effect(() => {
    load()
  })

  const groups = $derived([...new Set(items.map((i) => i.group))].map((name) => ({ name, items: items.filter((i) => i.group === name) })))

  async function save(it, value) {
    const res = await act(() => api('PUT', `/api/tuning/${it.id}`, { value: String(value) }))
    await load()
    if (!res) return
    const bad = (res.issues ?? []).find((i) => i.kind === 'sysctl' && i.id === it.id)
    if (bad) toast(bad.message, 'error')
    else toast(value === '' ? `${it.label}: no longer managed` : `${it.label}: ${value}`)
  }

  const label = (it, v) => it.choices?.find((c) => c.value === v)?.label ?? v
  const recommended = (it) => (it.kind === 'int' ? `${Number(it.recommended).toLocaleString()} ${it.unit}` : label(it, it.recommended))
  // A choice the kernel only offers once its module is loaded.
  const notLoaded = (it, c) => it.available?.length && !it.available.includes(c.value)
</script>

<div class="space-y-5">
  <p class="text-sm text-slate-500">
    Kernel settings that matter for a VPN or router gateway. A setting you <b class="font-medium text-slate-300">manage</b> here is applied at boot and put back if something changes it; one you don't manage is left exactly as the system has it. <b class="font-medium text-slate-300">Stop managing</b> doesn't undo the change: the value stays until the next reboot, when the system default returns.
  </p>

  {#if !loaded}
    <p class="text-sm text-slate-500">Loading…</p>
  {/if}

  {#each groups as g (g.name)}
    <section class="card">
      <header class="border-b border-slate-800 px-4 py-3"><h2 class="text-sm font-semibold">{g.name}</h2></header>
      <div class="divide-y divide-slate-800">
        {#each g.items as it (it.id)}
          <div class="space-y-2 px-4 py-4">
            <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
              <h3 class="text-sm font-medium text-slate-200">{it.label}</h3>
              {#if it.supported}
                <span class="badge bg-slate-800 text-slate-400">now: <span class="mono ml-1">{it.kind === 'int' ? Number(it.current).toLocaleString() : label(it, it.current)}</span></span>
              {/if}
              {#if it.error}
                <span class="badge bg-red-500/15 text-red-300">not applied</span>
              {:else if it.managed}
                <span class="badge bg-accent-600/20 text-accent-300">managed</span>
              {/if}
            </div>
            <p class="max-w-3xl text-sm leading-relaxed text-slate-500">{it.desc}</p>

            {#if !it.supported}
              <p class="text-xs text-amber-300">Not available here: {it.why}</p>
            {:else}
              <div class="flex flex-wrap items-center gap-2">
                {#if it.kind === 'choice'}
                  <select class="input w-auto py-1 text-xs" aria-label={it.label} value={it.managed} onchange={(e) => save(it, e.currentTarget.value)}>
                    <option value="">don't manage</option>
                    {#each it.choices as c}
                      <option value={c.value}>{c.label}{notLoaded(it, c) ? ' (will be loaded)' : ''}</option>
                    {/each}
                  </select>
                {:else}
                  <input type="number" class="input w-40 py-1 text-xs" aria-label={it.label} min={it.min} max={it.max} bind:value={draft[it.id]} />
                  <span class="text-xs text-slate-500">{it.unit}</span>
                  <button class="btn btn-sm" onclick={() => save(it, draft[it.id])}>Apply</button>
                {/if}
                {#if it.recommended && it.managed !== it.recommended}
                  <button class="btn btn-sm btn-ghost" onclick={() => save(it, it.recommended)}>Use recommended: {recommended(it)}</button>
                {/if}
                {#if it.managed}
                  <button class="btn btn-sm btn-ghost" onclick={() => save(it, '')}>Stop managing</button>
                {/if}
              </div>
              {#if it.kind === 'int'}
                <p class="hint">Between {it.min.toLocaleString()} and {it.max.toLocaleString()} {it.unit}.</p>
              {/if}
            {/if}
            {#if it.error}<p class="text-xs text-red-300">{it.error}</p>{/if}
          </div>
        {/each}
      </div>
    </section>
  {/each}
</div>
