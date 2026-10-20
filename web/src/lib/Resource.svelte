<script>
  import { api } from './api.js'
  import { app, act, issuesFor } from './state.svelte.js'

  // A schema-driven table + edit dialog used by every list in the panel.
  let {
    title = '',
    endpoint,
    columns,
    fields,
    blank,
    orderable = false,
    sort = null,
    generated = [],
    addLabel = 'Add',
    onchange = () => {},
  } = $props()

  let items = $state([])
  const shown = $derived(sort ? [...items].sort(sort) : items)
  let draft = $state(null)
  let isNew = $state(false)
  let dialog = $state()

  async function load() {
    items = await api('GET', endpoint).catch(() => [])
  }
  $effect(() => {
    load()
  })

  async function changed() {
    await load()
    onchange()
  }

  function openNew() {
    draft = structuredClone(blank())
    isNew = true
    dialog?.showModal()
  }
  function openEdit(item) {
    draft = structuredClone($state.snapshot(item))
    isNew = false
    dialog?.showModal()
  }

  async function save(e) {
    e.preventDefault()
    const body = $state.snapshot(draft)
    for (const f of fields) if (f.type === 'number') body[f.key] = Number(body[f.key]) || 0
    const res = await act(
      () => (isNew ? api('POST', endpoint, body) : api('PUT', `${endpoint}/${body.id}`, body)),
      isNew ? 'Added' : 'Saved',
    )
    if (res) {
      dialog.close()
      await changed()
    }
  }

  async function toggle(item) {
    if (await act(() => api('PUT', `${endpoint}/${item.id}`, { ...$state.snapshot(item), disabled: !item.disabled }))) await changed()
  }
  async function remove(item) {
    if (!confirm('Delete this entry?')) return
    if (await act(() => api('DELETE', `${endpoint}/${item.id}`), 'Deleted')) await changed()
  }
  async function move(item, to) {
    if (await act(() => api('POST', `${endpoint}/${item.id}/move`, { to }))) await changed()
  }

  const cell = (col, item) => (col.render ? col.render(item) : (item[col.key] ?? ''))
</script>

<section class="card">
  <header class="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
    <h2 class="text-sm font-semibold">{title} <span class="ml-1 font-normal text-slate-400">{items.length}</span></h2>
    <button class="btn btn-primary btn-sm" onclick={openNew}>+ {addLabel}</button>
  </header>

  <div class="overflow-x-auto">
    <table class="w-full text-sm">
      <thead class="border-b border-slate-200 dark:border-slate-800">
        <tr>
          {#each columns as col}<th class="th">{col.label}</th>{/each}
          <th class="th"></th>
        </tr>
      </thead>
      <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
        {#each shown as item, i (item.id)}
          {@const bad = issuesFor(item.id)}
          <tr class="hover:bg-slate-50 dark:hover:bg-slate-800/40 {item.disabled ? 'opacity-50' : ''}">
            {#each columns as col, ci}
              <td class="td {col.mono ? 'mono' : ''}">
                {cell(col, item)}
                {#if ci === 0}
                  {#if item.disabled}<span class="badge ml-2 bg-slate-200 text-slate-600 dark:bg-slate-800 dark:text-slate-400">disabled</span>{/if}
                {/if}
              </td>
            {/each}
            <td class="td whitespace-nowrap text-right">
              {#if orderable}
                <button class="btn btn-ghost btn-sm" disabled={i === 0} title="Move up" aria-label="Move up" onclick={() => move(item, i - 1)}>↑</button>
                <button class="btn btn-ghost btn-sm" disabled={i === shown.length - 1} title="Move down" aria-label="Move down" onclick={() => move(item, i + 1)}>↓</button>
              {/if}
              <button class="btn btn-ghost btn-sm" onclick={() => toggle(item)}>{item.disabled ? 'Enable' : 'Disable'}</button>
              <button class="btn btn-ghost btn-sm" onclick={() => openEdit(item)}>Edit</button>
              <button class="btn btn-ghost btn-sm text-red-600 dark:text-red-400" onclick={() => remove(item)}>Delete</button>
            </td>
          </tr>
          {#each bad as b}
            <tr class="bg-red-50 dark:bg-red-950/40"><td class="px-3 py-1.5 text-xs text-red-700 dark:text-red-300" colspan={columns.length + 1}>Not applied: {b.message}</td></tr>
          {/each}
        {:else}
          <tr><td class="td py-8 text-center text-slate-400" colspan={columns.length + 1}>Nothing here yet.</td></tr>
        {/each}
        {#each generated as item (item.id)}
          <tr class="bg-slate-50/70 text-slate-500 dark:bg-slate-900/60 dark:text-slate-400">
            {#each columns as col, ci}
              <td class="td {col.mono ? 'mono' : ''}">
                {cell(col, item)}
                {#if ci === 0}<span class="badge ml-2 bg-accent-100 text-accent-800 dark:bg-accent-800/40 dark:text-accent-100" title="Created by Client Routing">generated</span>{/if}
              </td>
            {/each}
            <td class="td"></td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>

<dialog bind:this={dialog} class="m-auto w-[min(34rem,calc(100vw-2rem))] rounded-xl border border-slate-200 bg-white p-0 text-slate-800 shadow-xl backdrop:bg-slate-950/50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200">
  {#if draft}
    <form onsubmit={save} class="p-5">
      <h3 class="mb-4 text-base font-semibold">{isNew ? addLabel : 'Edit ' + addLabel.replace(/^Add /, '')}</h3>
      <div class="grid grid-cols-2 gap-x-3 gap-y-3">
        {#each fields as f}
          {#if !f.show || f.show(draft)}
            <div class={f.wide ? 'col-span-2' : ''}>
              {#if f.type === 'checkbox'}
                <label class="flex items-center gap-2 pt-5 text-sm">
                  <input type="checkbox" bind:checked={draft[f.key]} class="size-4 accent-accent-600" />
                  {f.label}
                </label>
              {:else}
                <label class="label" for="f-{f.key}">{f.label}</label>
                {#if f.type === 'select'}
                  <select id="f-{f.key}" class="input" bind:value={draft[f.key]}>
                    {#each f.options as o}<option value={o.value ?? o}>{o.label ?? o}</option>{/each}
                  </select>
                {:else if f.type === 'number'}
                  <input id="f-{f.key}" type="number" class="input" bind:value={draft[f.key]} placeholder={f.placeholder ?? ''} />
                {:else}
                  <input id="f-{f.key}" type="text" class="input {f.mono ? 'mono' : ''}" bind:value={draft[f.key]} placeholder={f.placeholder ?? ''}
                    list={f.type === 'iface' ? 'ifaces' : undefined} autocomplete="off" spellcheck="false" />
                {/if}
                {#if f.help}<p class="mt-1 text-xs text-slate-500">{f.help}</p>{/if}
              {/if}
            </div>
          {/if}
        {/each}
      </div>
      <div class="mt-5 flex justify-end gap-2">
        <button type="button" class="btn" onclick={() => dialog.close()}>Cancel</button>
        <button type="submit" class="btn btn-primary">Save</button>
      </div>
    </form>
  {/if}
</dialog>
