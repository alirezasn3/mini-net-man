<script>
  import Resource from '../lib/Resource.svelte'
  import { refreshOverview } from '../lib/state.svelte.js'
</script>

<div class="space-y-5">
  <p class="text-sm text-slate-500">Addresses you add here are kept on the interface by mini-net-man. Addresses configured by the OS (netplan, NetworkManager, wg-quick) are shown on the Overview and left alone.</p>
  <Resource
    title="Addresses"
    endpoint="/api/addresses"
    addLabel="Add address"
    onchange={refreshOverview}
    columns={[
      { key: 'address', label: 'Address', mono: true },
      { key: 'interface', label: 'Interface', mono: true },
      { key: 'comment', label: 'Comment' },
    ]}
    fields={[
      { key: 'address', label: 'Address', type: 'text', mono: true, placeholder: '10.0.0.1/16 or fd00::1/64', help: 'The address to give the interface, with its prefix length: 10.0.0.1/16 (IPv4) or fd00::1/64 (IPv6).' },
      { key: 'interface', label: 'Interface', type: 'iface', mono: true, placeholder: 'wgServer', help: 'Which interface gets it. Pick one from the list or type a name; it must already exist.' },
      { key: 'comment', label: 'Comment', type: 'text', wide: true, help: 'Optional note for yourself.' },
    ]}
    blank={() => ({ address: '', interface: '', comment: '', disabled: false })}
  />
</div>
