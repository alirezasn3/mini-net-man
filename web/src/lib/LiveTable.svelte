<script>
  // Read-only table: a normal table on wide screens, one labelled card per row on phones,
  // so nothing runs off the right edge.
  //   columns: [{ label, key?, render?(row), mono?, origin?, badge?(row), sub?(row) }]
  //   `sub` adds a smaller muted second line under the value.
  //   `origin` columns draw a badge: green when the row is owned by mini-net-man.
  //   `badge` columns draw a badge with the Tailwind classes badge(row) returns.
  let { columns, rows, empty = 'Nothing here.' } = $props()
  const value = (c, r) => (c.render ? c.render(r) : (r[c.key] ?? ''))
</script>

<div class="overflow-x-auto max-sm:overflow-visible">
  <table class="w-full text-sm max-sm:block">
    <thead class="border-b border-slate-800 max-sm:hidden">
      <tr>{#each columns as c}<th class="th">{c.label}</th>{/each}</tr>
    </thead>
    <tbody class="divide-y divide-slate-800/60 max-sm:block">
      {#each rows as r}
        <tr class="max-sm:block max-sm:px-4 max-sm:py-3">
          {#each columns as c, ci}
            {@const v = value(c, r)}
            {@const long = String(v).length > 26}
            <td class="td max-sm:flex max-sm:px-0 max-sm:py-0.5 {long ? 'max-sm:flex-col max-sm:gap-0.5' : 'max-sm:justify-between max-sm:gap-4'} {c.mono ? 'mono' : ''} {ci > 0 && (v === '' || v == null) ? 'max-sm:hidden' : ''}">
              <span class="label mb-0 shrink-0 uppercase tracking-wide sm:hidden">{c.label}</span>
              {#if c.badge}
                <span class="badge {c.badge(r)}">{v}</span>
              {:else if c.origin}
                <span class="badge {r.owned ? 'bg-accent-600/20 text-accent-300' : 'bg-slate-800 text-slate-400'}">{v}</span>
              {:else}
                <span class="min-w-0 break-words {long ? 'max-sm:text-left' : 'max-sm:text-right'}">
                  {v}
                  {#if c.sub && c.sub(r)}<span class="mono block text-xs text-slate-500">{c.sub(r)}</span>{/if}
                </span>
              {/if}
            </td>
          {/each}
        </tr>
      {:else}
        <tr class="max-sm:block"><td class="td py-6 text-center text-slate-500 max-sm:block" colspan={columns.length}>{empty}</td></tr>
      {/each}
    </tbody>
  </table>
</div>
