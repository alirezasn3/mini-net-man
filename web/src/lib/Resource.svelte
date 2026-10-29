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
    groupBy = null, // (item) => string: keep rows of a group together, with a gap between groups
    groupOrder = [], // order of the groups; unlisted ones go last, by name
    pageSize = 0, // show this many rows, then a button for the rest; 0 shows all
    searchable = false, // a search box that narrows the rows
    selectable = false, // a checkbox on every row and a button to delete the ticked ones
    generated = [],
    rowBadge = null, // (item) => { text, cls, title } | null: a status chip beside the first column
    defaults = [], // rows for each chain's default action: editable, but not deletable or movable
    defaultOptions = [],
    ondefault = () => {},
    addLabel = 'Add',
    onchange = () => {},
  } = $props()

  let items = $state([])
  const rank = (it) => {
    const i = groupOrder.indexOf(groupBy(it))
    return i < 0 ? groupOrder.length : i
  }

  // A sort picked by the user (click a column heading) is only a way of looking at the list:
  // it is remembered in this browser, and never changes the order the rules are applied in.
  const sortStore = () => `mnm-sort:${endpoint}`
  const saved = (() => {
    try {
      const [key, dir] = (localStorage.getItem(sortStore()) ?? '').split(':')
      return columns.some((c) => c.key === key) ? { key, dir: dir === '-1' ? -1 : 1 } : null
    } catch {
      return null
    }
  })()
  let sortKey = $state(saved?.key ?? null)
  let sortDir = $state(saved?.dir ?? 1)
  function setSort(key, dir = 1) {
    sortKey = key
    sortDir = dir
    try {
      if (key) localStorage.setItem(sortStore(), `${key}:${dir}`)
      else localStorage.removeItem(sortStore())
    } catch {}
  }
  // Click: ascending, then descending, then back to the page's own order.
  const cycle = (key) => (sortKey !== key ? setSort(key, 1) : sortDir === 1 ? setSort(key, -1) : setSort(null))
  const sortCol = $derived(columns.find((c) => c.key === sortKey))
  const sortVal = (col, it) => (col.sortBy ? col.sortBy(it) : col.render ? col.render(it) : it[col.key])
  const blank_ = (v) => v === '' || v == null
  function byColumn(col, dir) {
    return (a, b) => {
      const x = sortVal(col, a)
      const y = sortVal(col, b)
      if (blank_(x) || blank_(y)) return blank_(x) - blank_(y) // empty cells go last, either way
      const c = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: 'base' })
      return c * dir
    }
  }
  // Search: every word has to appear somewhere in the row (shown text or any field).
  let q = $state('')
  const hay = (it) => (columns.map((c) => String(cell(c, it) ?? '')).join(' ') + ' ' + Object.values(it).filter((v) => typeof v === 'string' || typeof v === 'number').join(' ')).toLowerCase()
  const base = $derived.by(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return words.length ? items.filter((it) => { const h = hay(it); return words.every((w) => h.includes(w)) }) : items
  })
  // Array.sort is stable, so equal rows keep their list order.
  const shown = $derived(
    sortCol ? [...base].sort(byColumn(sortCol, sortDir)) : groupBy ? [...base].sort((a, b) => rank(a) - rank(b) || (rank(a) === groupOrder.length ? String(groupBy(a)).localeCompare(String(groupBy(b))) : 0)) : sort ? [...base].sort(sort) : base,
  )
  const span = $derived(columns.length + 1 + (selectable ? 1 : 0))

  // Ticked rows. Searching again clears them, so nothing hidden is ever deleted by accident.
  let selected = $state({})
  let lastTicked = -1
  const nsel = $derived(items.filter((it) => selected[it.id]).length)
  const allVisible = $derived(visible.length > 0 && visible.every((it) => selected[it.id]))
  const someVisible = $derived(visible.some((it) => selected[it.id]))
  $effect(() => {
    q
    selected = {}
  })
  function tick(i, e) {
    const on = e.currentTarget.checked
    if (e.shiftKey && lastTicked >= 0) {
      const [a, b] = [Math.min(lastTicked, i), Math.max(lastTicked, i)]
      for (let k = a; k <= b; k++) selected[visible[k].id] = on
    } else selected[visible[i].id] = on
    lastTicked = i
  }
  function tickAll(on) {
    for (const it of visible) selected[it.id] = on
  }
  async function deleteSelected() {
    const ids = items.filter((it) => selected[it.id]).map((it) => it.id)
    if (!ids.length || !confirm(`Delete ${ids.length} ${ids.length === 1 ? 'entry' : 'entries'}?`)) return
    if (await act(() => api('POST', `${endpoint}/delete`, { ids }), `Deleted ${ids.length}`)) {
      selected = {}
      await changed()
    }
  }
  let showAll = $state(false)
  const visible = $derived(pageSize && !showAll ? shown.slice(0, pageSize) : shown)
  const grouped = $derived(groupBy && !sortCol)
  const gap = (i) => grouped && i > 0 && groupBy(visible[i]) !== groupBy(visible[i - 1])
  // Rows only move within their group; the server wants the neighbour's place in the whole list.
  const canMove = (i, d) => !sortCol && visible[i + d] && (!groupBy || groupBy(visible[i + d]) === groupBy(visible[i]))
  const moveBy = (i, d) => move(visible[i], items.findIndex((x) => x.id === visible[i + d].id))
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
    for (const f of fields) if (f.type === 'list') draft[f.key] = (draft[f.key] ?? []).join(', ')
    isNew = true
    dialog?.showModal()
  }
  function openEdit(item) {
    draft = structuredClone($state.snapshot(item))
    for (const f of fields) if (f.type === 'list') draft[f.key] = (draft[f.key] ?? []).join(', ')
    isNew = false
    dialog?.showModal()
  }

  async function save(e) {
    e.preventDefault()
    const body = $state.snapshot(draft)
    for (const f of fields) if (f.type === 'number') body[f.key] = Number(body[f.key]) || 0
    for (const f of fields) if (f.type === 'list') body[f.key] = String(body[f.key] ?? '').split(/[\s,]+/).filter(Boolean)
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

{#snippet spacer()}
  <tr aria-hidden="true" class="max-sm:block"><td colspan={span} class="h-4 bg-slate-950/80 p-0 max-sm:block"></td></tr>
{/snippet}

<section class="card">
  <header class="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
    <h2 class="text-sm font-semibold">{title} <span class="ml-1 font-normal text-slate-400">{q.trim() ? `${shown.length} of ` : ''}{items.length}</span></h2>
    <div class="flex flex-wrap items-center gap-2">
      {#if searchable}
        <input type="search" class="input w-44 py-1 text-xs" placeholder="Search…" aria-label="Search {title}" autocomplete="off" spellcheck="false" bind:value={q} />
      {/if}
      <!-- Phones have no column headings to click. -->
      <select class="input w-auto py-1 text-xs sm:hidden" aria-label="Sort by" value={sortKey ? `${sortKey}:${sortDir}` : ''}
        onchange={(e) => { const [k, d] = e.currentTarget.value.split(':'); setSort(k || null, Number(d) || 1) }}>
        <option value="">default order</option>
        {#each columns as col}
          <option value="{col.key}:1">{col.label} ↑</option>
          <option value="{col.key}:-1">{col.label} ↓</option>
        {/each}
      </select>
      <button class="btn btn-primary btn-sm" onclick={openNew}>+ {addLabel}</button>
    </div>
  </header>
  {#if selectable && (nsel > 0 || visible.length > 0)}
    <div class="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-2 text-xs dark:border-slate-800 {nsel ? 'bg-accent-600/10' : 'sm:hidden'}">
      <label class="flex items-center gap-2 sm:hidden"><input type="checkbox" class="size-4 accent-accent-600" checked={allVisible} onchange={(e) => tickAll(e.currentTarget.checked)} /> Select all</label>
      {#if nsel}
        <span><b>{nsel}</b> selected</span>
        {#if nsel < shown.length && shown.length > visible.length}
          <button class="btn btn-ghost btn-sm" onclick={() => { for (const it of shown) selected[it.id] = true }}>Select all {shown.length}{q.trim() ? ' matching' : ''}</button>
        {/if}
        <button class="btn btn-ghost btn-sm" onclick={() => (selected = {})}>Clear</button>
        <button class="btn btn-sm border-red-500/40 text-red-400" onclick={deleteSelected}>Delete {nsel}</button>
      {/if}
    </div>
  {/if}
  {#if sortCol}
    <div class="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 bg-slate-50/60 px-4 py-2 text-xs text-slate-500 dark:border-slate-800 dark:bg-slate-900/40">
      <span>
        Sorted by <b>{sortCol.label}</b> {sortDir === 1 ? '↑' : '↓'}.
        {#if orderable}This only changes how the list looks: rules are still applied in their own order, and moving is off until you reset.{/if}
      </span>
      <button class="btn btn-ghost btn-sm" onclick={() => setSort(null)}>Reset</button>
    </div>
  {/if}

  <!-- Wide screens: a table. Phones: every row becomes a card (labels come from the column
       names), so the Edit / Delete buttons never end up off-screen. -->
  <div class="overflow-x-auto max-sm:overflow-visible">
    <table class="w-full text-sm max-sm:block">
      <thead class="border-b border-slate-200 max-sm:hidden dark:border-slate-800">
        <tr>
          {#if selectable}
            <th class="th w-8"><input type="checkbox" class="size-4 accent-accent-600" aria-label="Select all shown" checked={allVisible} indeterminate={someVisible && !allVisible} onchange={(e) => tickAll(e.currentTarget.checked)} /></th>
          {/if}
          {#each columns as col}
            <th class="th" aria-sort={sortKey === col.key ? (sortDir === 1 ? 'ascending' : 'descending') : 'none'}>
              <button class="inline-flex cursor-pointer items-center gap-1 hover:text-slate-300 {sortKey === col.key ? 'text-slate-200' : ''}" title="Sort by {col.label}" onclick={() => cycle(col.key)}>
                {col.label}<span class="w-3 text-accent-300">{sortKey === col.key ? (sortDir === 1 ? '↑' : '↓') : ''}</span>
              </button>
            </th>
          {/each}
          <th class="th"></th>
        </tr>
      </thead>
      <tbody class="divide-y divide-slate-100 max-sm:block dark:divide-slate-800">
        {#each visible as item, i (item.id)}
          {@const bad = issuesFor(item.id)}
          {#if gap(i)}{@render spacer()}{/if}
          <tr class="hover:bg-slate-50 max-sm:block max-sm:px-4 max-sm:py-3 dark:hover:bg-slate-800/40 {item.disabled ? 'opacity-50' : ''}">
            {#if selectable}
              <td class="td w-8 max-sm:flex max-sm:items-center max-sm:gap-2 max-sm:px-0 max-sm:py-0.5">
                <input type="checkbox" class="size-4 accent-accent-600" aria-label="Select this row" checked={!!selected[item.id]} onclick={(e) => tick(i, e)} />
                <span class="label mb-0 uppercase tracking-wide sm:hidden">Select</span>
              </td>
            {/if}
            {#each columns as col, ci}
              {@const v = cell(col, item)}
              {@const long = String(v).length > 26}
              <td class="td max-sm:flex max-sm:px-0 max-sm:py-0.5 {long ? 'max-sm:flex-col max-sm:gap-0.5' : 'max-sm:justify-between max-sm:gap-4'} {col.mono ? 'mono' : ''} {ci > 0 && (v === '' || v == null) ? 'max-sm:hidden' : ''}">
                <span class="label mb-0 shrink-0 uppercase tracking-wide sm:hidden">{col.label}</span>
                <span class="min-w-0 break-words {long ? 'max-sm:text-left' : 'max-sm:text-right'}">
                  {#if col.badge}<span class="badge {col.badge(item)}">{v}</span>{:else}{v}{/if}
                  {#if ci === 0 && item.disabled}<span class="badge ml-2 bg-slate-800 text-slate-400">disabled</span>{/if}
                  {#if ci === 0 && rowBadge}
                    {@const b = rowBadge(item)}
                    {#if b}<span class="badge ml-2 {b.cls}" title={b.title}>{b.text}</span>{/if}
                  {/if}
                </span>
              </td>
            {/each}
            <td class="td text-right whitespace-nowrap max-sm:flex max-sm:flex-wrap max-sm:justify-end max-sm:gap-1 max-sm:px-0 max-sm:pt-2 max-sm:whitespace-normal">
              {#if orderable}
                <button class="btn btn-ghost btn-sm" disabled={!canMove(i, -1)} title="Move up" aria-label="Move up" onclick={() => moveBy(i, -1)}>↑</button>
                <button class="btn btn-ghost btn-sm" disabled={!canMove(i, 1)} title="Move down" aria-label="Move down" onclick={() => moveBy(i, 1)}>↓</button>
              {/if}
              <button class="btn btn-ghost btn-sm" onclick={() => toggle(item)}>{item.disabled ? 'Enable' : 'Disable'}</button>
              <button class="btn btn-ghost btn-sm" onclick={() => openEdit(item)}>Edit</button>
              <button class="btn btn-ghost btn-sm text-red-600 dark:text-red-400" onclick={() => remove(item)}>Delete</button>
            </td>
          </tr>
          {#each bad as b}
            <tr class="bg-red-50 max-sm:block dark:bg-red-950/40"><td class="px-3 py-1.5 text-xs text-red-700 max-sm:block max-sm:px-4 dark:text-red-300" colspan={span}>Not applied: {b.message}</td></tr>
          {/each}
        {:else}
          <tr class="max-sm:block"><td class="td py-8 text-center text-slate-400 max-sm:block" colspan={span}>{items.length ? `Nothing matches “${q.trim()}”.` : 'Nothing here yet.'}</td></tr>
        {/each}
        {#if grouped && visible.length && generated.length}{@render spacer()}{/if}
        {#each generated as item (item.id)}
          <tr class="bg-slate-50/70 text-slate-500 max-sm:block max-sm:px-4 max-sm:py-3 dark:bg-slate-900/60 dark:text-slate-400">
            {#if selectable}<td class="td max-sm:hidden"></td>{/if}
            {#each columns as col, ci}
              {@const v = cell(col, item)}
              {@const long = String(v).length > 26}
              <td class="td max-sm:flex max-sm:px-0 max-sm:py-0.5 {long ? 'max-sm:flex-col max-sm:gap-0.5' : 'max-sm:justify-between max-sm:gap-4'} {col.mono ? 'mono' : ''} {ci > 0 && (v === '' || v == null) ? 'max-sm:hidden' : ''}">
                <span class="label mb-0 shrink-0 uppercase tracking-wide sm:hidden">{col.label}</span>
                <span class="min-w-0 break-words {long ? 'max-sm:text-left' : 'max-sm:text-right'}">
                  {v}
                  {#if ci === 0}<span class="badge ml-2 bg-accent-600/20 text-accent-300" title="Created by Client Routing">generated</span>{/if}
                </span>
              </td>
            {/each}
            <td class="td max-sm:hidden"></td>
          </tr>
        {/each}
        {#if grouped && (visible.length || generated.length) && defaults.length}{@render spacer()}{/if}
        {#each defaults as item (item.id)}
          <tr class="bg-slate-950/50 max-sm:block max-sm:px-4 max-sm:py-3">
            {#if selectable}<td class="td max-sm:hidden"></td>{/if}
            {#each columns as col, ci}
              {@const v = cell(col, item)}
              <td class="td max-sm:flex max-sm:items-center max-sm:justify-between max-sm:gap-4 max-sm:px-0 max-sm:py-0.5 {col.mono ? 'mono' : ''} {ci > 0 && col.key !== 'action' && (v === '' || v == null) ? 'max-sm:hidden' : ''}">
                <span class="label mb-0 shrink-0 uppercase tracking-wide sm:hidden">{col.label}</span>
                {#if col.key === 'action'}
                  <select class="input w-auto py-0.5 text-xs" aria-label="Default action of {item.chain}" value={item.action} onchange={(e) => ondefault(item, e.currentTarget.value)}>
                    {#each defaultOptions as o}<option value={o}>{o}</option>{/each}
                  </select>
                {:else}
                  <span class="min-w-0 break-words text-slate-400 italic max-sm:text-right">
                    {v}
                    {#if ci === 0}<span class="badge ml-2 bg-slate-800 text-slate-400 not-italic" title="What happens to anything no rule above decided">default</span>{/if}
                  </span>
                {/if}
              </td>
            {/each}
            <td class="td max-sm:hidden"></td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if pageSize && shown.length > pageSize}
    <div class="flex items-center justify-between gap-2 border-t border-slate-200 px-4 py-2 text-xs text-slate-500 dark:border-slate-800">
      <span>{showAll ? `All ${shown.length} shown` : `Showing ${pageSize} of ${shown.length}`}</span>
      <button class="btn btn-ghost btn-sm" onclick={() => (showAll = !showAll)}>{showAll ? 'Show fewer' : 'Show all'}</button>
    </div>
  {/if}
</section>

<dialog bind:this={dialog} class="m-auto max-h-[calc(100dvh-2rem)] w-[min(34rem,calc(100vw-2rem))] overflow-y-auto rounded-xl border border-slate-800 bg-slate-900 p-0 text-slate-300 shadow-2xl shadow-black/60 backdrop:bg-black/70">
  {#if draft}
    <form onsubmit={save} class="p-5">
      <h3 class="mb-4 text-base font-semibold">{isNew ? addLabel : 'Edit ' + addLabel.replace(/^Add /, '')}</h3>
      <div class="grid grid-cols-1 gap-x-3 gap-y-3 sm:grid-cols-2">
        {#each fields as f}
          {#if !f.show || f.show(draft)}
            {@const hint = typeof f.help === 'function' ? f.help(draft) : f.help}
            <div class={f.wide ? 'sm:col-span-2' : ''}>
              {#if f.type === 'checkbox'}
                <label class="flex items-center gap-2 pt-1 text-sm">
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
                    list={f.type === 'iface' ? 'ifaces' : f.datalist} autocomplete="off" spellcheck="false" />
                {/if}
              {/if}
              {#if hint}<p class="hint">{hint}</p>{/if}
            </div>
          {/if}
        {/each}
      </div>
      <div class="sticky -bottom-5 -mx-5 mt-5 -mb-5 flex justify-end gap-2 border-t border-slate-800 bg-slate-900 px-5 py-3">
        <button type="button" class="btn" onclick={() => dialog.close()}>Cancel</button>
        <button type="submit" class="btn btn-primary">Save</button>
      </div>
    </form>
  {/if}
</dialog>
