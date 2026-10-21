<script>
  // Shows an nft listing. Long lines wrap with a hanging indent, so a wrapped line
  // reads as the continuation of the one above instead of a new statement.
  let { text = '' } = $props()
  const STEP = 1.1 // rem per level of nesting
  const lines = $derived(
    text
      .replace(/\n$/, '')
      .split('\n')
      .map((l) => {
        const tabs = l.match(/^\t*/)[0].length
        return { tabs, body: l.slice(tabs) }
      }),
  )
</script>

<div class="ruleset">
  {#each lines as l}
    <div style="padding-left: {(l.tabs + 1) * STEP}rem; text-indent: -{STEP}rem">{l.body || ' '}</div>
  {/each}
</div>
