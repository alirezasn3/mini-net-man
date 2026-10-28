# HTTP API

Everything the web panel does goes through this JSON API, so any program can do the same. This page lists every call, the fields each item takes, and what comes back.

- [Quick start](#quick-start)
- [Authentication](#authentication)
- [Conventions](#conventions)
- [Safe mode from a script](#safe-mode-from-a-script)
- [Items you manage](#items-you-manage): addresses, routes, policy rules, firewall rules, bridges, interface settings, health checks, client routing
- [Other settings](#other-settings): firewall policy, client routing switch, kernel settings, reapply
- [Looking at the machine](#looking-at-the-machine)
- [Panel, accounts and updates](#panel-accounts-and-updates)
- [Examples](#examples)

## Quick start

Create a token in the panel under **Settings → API tokens**, then:

```sh
TOKEN=mnm_...                       # shown once when you create it
URL=http://panel.example:8080

curl -H "Authorization: Bearer $TOKEN" $URL/api/routes

curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"dst":"10.9.0.0/24","dev":"wg0"}' $URL/api/routes
# {"id":"13349acc","issues":[]}
```

## Authentication

Send `Authorization: Bearer <token>` on every request.

- A token is made in **Settings → API tokens** (name, your password, optionally *read-only*). The secret starts with `mnm_` and is shown **once**. Only a hash is stored, so a lost token can't be recovered: delete it and make another. Give each program its own token.
- A **read-only** token may use `GET` and nothing else (`403 {"error":"this token is read-only"}`).
- **No token** can do the account tasks: change the username or password, create, list or delete tokens, change the panel's listen address, port or allowed IPs (`PUT /api/settings/web`), or install updates. These return `403 {"error":"this needs a logged-in session, not an API token"}`. Use the panel for them.
- The caller's address must be in **Allowed client IPs** (Settings), otherwise the connection is dropped with no answer at all. With an empty list only localhost is allowed.
- A wrong or malformed token is `401 {"error":"invalid API token"}`. Five wrong tokens or passwords from one address within a minute lock that address out for a minute (`429`).
- Changes made with a token are written to the service log with the token's name, the method, the path and the caller's address.
- Browsers on other sites can't call the API (no CORS headers are sent). Call it from a server or a script.
- Serve the panel over TLS (`tls_cert` and `tls_key` in `config.yaml`) whenever a token crosses a network you don't control. Over plain HTTP the token is readable on the wire.

The panel itself uses a cookie session from `POST /api/login` (`{"username": "...", "password": "..."}`) and needs `Content-Type: application/json` on every non-`GET` call. Scripts should use a token instead; the cookie logins expire after 12 hours.

## Conventions

**Format.** Requests and responses are JSON. Send `Content-Type: application/json` on requests with a body. With a token the header isn't enforced, but the body must still be JSON. Unknown fields in a request are ignored. Bodies larger than 1 MiB are refused.

**Errors** are `{"error": "message in plain words"}` with a status code:

| Status | Meaning |
|---|---|
| `400` | The request was invalid. Nothing was changed. The message says what is wrong (`route nonsense: invalid IP address or network "nonsense/32"`). |
| `401` | No or wrong token. |
| `403` | The token is read-only, or the call needs a logged-in session. |
| `404` | No item with that id. |
| `409` | Not possible right now (safe mode already active, update already installed, ...). |
| `429` | Locked out after too many wrong tokens. |
| `5xx` | The kernel or something outside refused it. |

**Changes are validated first, then applied.** A change that fails validation is a `400` and nothing is saved. A change that is valid is **saved**, and then applied to the kernel. If the kernel can't apply some item (an interface doesn't exist yet, a port is missing), the call still succeeds and the answer lists it:

```json
{"issues": [{"kind": "route", "id": "13349acc", "message": "interface \"wg0\": Link not found"}]}
```

`kind` is one of `address`, `route`, `rule`, `firewall`, `sysctl`, `bridge`, `interface`. Items that couldn't be applied are retried automatically with a growing delay, and again whenever the kernel's interfaces, addresses or routes change. The current list is also in `GET /api/overview` under `issues`.

**Lists.** Items you manage all share the same five calls (`<list>` is `routes`, `rules`, `addresses`, `bridges`, `interfaces`, `checks`, `firewall/rules` or `client-routing/clients`):

| Call | What it does |
|---|---|
| `GET /api/<list>` | The items, in order, as an array (`[]` when empty). |
| `POST /api/<list>` | Adds one to the end. The `id` is chosen for you and returned: `{"id": "...", "issues": []}`. |
| `PUT /api/<list>/{id}` | **Replaces** the item. Send the complete item; a field you leave out goes back to its default. Returns `{"issues": []}`. |
| `DELETE /api/<list>/{id}` | Removes it. Returns `{"issues": []}`. |
| `POST /api/<list>/{id}/move` | Body `{"to": 0}`: moves it to that position (0 is first; a too-large number means last). Order matters for firewall rules (each chain runs top to bottom). |

To change one field, `GET` the item, change it and `PUT` it back. Setting `"disabled": true` keeps an item in the config but not in the kernel.

Every item has an `id` (8 hex characters) and many have `comment` and `disabled`. Items created by client routing appear in `GET /api/generated`, not in these lists, and can't be edited.

**Interface names** are up to 15 characters with no spaces or slashes. **Addresses** may be IPv4 or IPv6 and are written with a prefix length (`10.0.0.1/16`, `fd00::1/64`); IPv6 works everywhere IPv4 does.

## Safe mode from a script

Safe mode snapshots the configuration. Everything changed afterwards is rolled back unless you confirm, or if nobody keeps the session alive. Use it for changes that could cut off the machine.

| Call | Body | Does |
|---|---|---|
| `GET /api/safe` | | `{"active": false, "remaining_secs": 0, "timeout_secs": 0}` |
| `POST /api/safe/start` | `{"timeout_secs": 60}` | Starts it. A value under 5 means 30. `409` if already active. |
| `POST /api/safe/heartbeat` | | Restarts the countdown. Returns the status. |
| `POST /api/safe/confirm` | | Keeps the changes and ends safe mode. |
| `POST /api/safe/cancel` | | Rolls back now. |

The countdown is **not** paused while you work: send a heartbeat more often than `timeout_secs`, or after that long without one everything reverts. Typical use: `start`, make the changes, check that you can still reach the machine, then `confirm`. If the machine becomes unreachable, nothing sends a heartbeat and it reverts by itself. The panel's own settings (users, tokens, allowed IPs) are never rolled back. `POST /api/update/install` is refused while safe mode is active.

## Items you manage

Field types: strings unless noted. Empty strings mean "not set".

### Addresses: `/api/addresses`

Extra addresses mini-net-man keeps on an interface.

| Field | Meaning |
|---|---|
| `address` | `10.0.0.1/16` or `fd00::1/64`. Required. |
| `interface` | The interface that gets it. Required; it must exist when applied. |
| `comment`, `disabled` | |

Addresses configured by something else (netplan, NetworkManager, `wg-quick`) are left alone. Removing an entry removes the address mini-net-man added.

### Routes: `/api/routes`

Like `ip route`.

| Field | Meaning |
|---|---|
| `dst` | `10.0.0.0/16`, `fd00::/64`, or `default` (IPv4 default route; `::/0` for IPv6). Required. The family of the route comes from this. |
| `gateway` | Next hop, same family as `dst`. |
| `dev` | Output interface. |
| `table` | A number (`200`), `main`, `local` or `default`. Empty is `main`. |
| `metric` (number) | Lower wins. `0` is the kernel default. |
| `type` | `unicast` (default), `blackhole`, `unreachable` or `prohibit`. A unicast route needs `gateway` or `dev`. |
| `comment`, `disabled` | |

mini-net-man only ever deletes routes it created (they carry protocol number 201).

### Policy rules: `/api/rules`

Like `ip rule`. The kernel checks them by `priority`, whatever their order in the list.

| Field | Meaning |
|---|---|
| `priority` (number) | 0 to 32765. Lowest is checked first. |
| `src`, `dst` | Match packets from / to this address or network. |
| `iif`, `oif` | Match the incoming interface / the interface of locally created packets. |
| `fwmark` (number) | Match this firewall mark (set with a `mark-connection` firewall rule). `0` ignores it. |
| `family` | `ipv4` or `ipv6`; empty means from `src` and `dst`, else IPv4. |
| `action` | `lookup` (default), `blackhole`, `unreachable` or `prohibit`. |
| `table` | The table to look in; required for `lookup`. |
| `check` | A health check id. The rule is in the kernel only while that check is not failing. |
| `comment`, `disabled` | |

### Firewall rules: `/api/firewall/rules`

One nftables table, `inet mini-net-man`, replaced atomically on every change. A rule with no address and no `family` applies to both IPv4 and IPv6. Order matters: within a chain the rules run top to bottom.

| Field | Meaning |
|---|---|
| `chain` | `input`, `forward`, `output`; `dstnat` (before routing) and `srcnat` (after routing); `mangle` (forwarded traffic, for MSS clamping); `mangle-in` (everything arriving, before routing) and `mangle-out` (locally created traffic), both for connection marking. Required. |
| `action` | `accept`, `drop`, `reject`, `return`; `masquerade`, `snat`, `dnat`; `clamp-mss`; `mark-connection`, `restore-mark`. Required. |
| `in_iface`, `out_iface` | Interface name; a trailing `*` is a wildcard (`wg*`). Only use `in_iface` where packets arrive (not in `output`, `srcnat` or `mangle-out`) and `out_iface` where they leave (not in `input`, `dstnat` or `mangle-in`); the panel hides them elsewhere, and the API does not check. |
| `src`, `dst` | Address or network. |
| `family` | `ipv4` or `ipv6`; empty is both. |
| `proto` | `tcp`, `udp`, `icmp` or `icmpv6`. Ports need `tcp` or `udp`. |
| `src_port`, `dst_port` | `80`, `1000-2000` or `80,443`. |
| `conn_state` | Comma list of `new`, `established`, `related`, `invalid`. |
| `to_addr`, `to_port` (number) | The target of `dnat` and `snat`. `to_port` 0 keeps the port. |
| `mss` (number) | For `clamp-mss`: 536 to 9000, or `0` to fit the outgoing route's MTU. |
| `mark` (number) | For `mark-connection`: above 0. |
| `comment`, `disabled` | |

Which actions go in which chain: `masquerade` and `snat` in `srcnat`; `dnat` in `dstnat`; `clamp-mss` only in `mangle`; marking only in `mangle-in` and `mangle-out`. The server explains a mismatch in the `400`. `GET /api/firewall/ruleset` shows the generated nft text.

### Bridges: `/api/bridges`

| Field | Meaning |
|---|---|
| `name` | Up to 15 characters. Created if it doesn't exist, and brought up. Required. |
| `ports` (array of strings) | Interfaces to join. They must exist; they are brought up unless an interface setting keeps them down. Ports removed from the array are released. An interface can be in only one bridge. |
| `stp` (boolean) | Spanning tree. |
| `mtu` (number) | `0` leaves it as it is, otherwise 68 to 65535. |
| `comment`, `disabled` | |

A bridge mini-net-man created is deleted when you delete its entry. A bridge that already existed is only joined to and released from.

### Interface settings: `/api/interfaces`

Keep an existing interface up or down, and/or at an MTU.

| Field | Meaning |
|---|---|
| `name` | The interface. Required. |
| `state` | `up`, `down`, or empty to leave it. |
| `mtu` (number) | `0` leaves it, otherwise 68 to 65535. |
| `comment`, `disabled` | |

At least one of `state` and `mtu` must be set. `lo` can't be taken down. Deleting an entry stops managing the interface but doesn't undo the change.

### Health checks: `/api/checks`

A ping sent out of one interface. Policy rules whose `check` names it are switched off while it is failing.

| Field | Meaning |
|---|---|
| `name` | Required. |
| `target` | An IPv4 or IPv6 address to ping. Required. |
| `interface` | The ping leaves through this interface. Required. |
| `table` | Optional: look the route up in this table. Leave empty for tunnels like WireGuard. |
| `interval_secs` (number) | Between pings, 1 to 3600. `0` means 5. |
| `timeout_ms` (number) | Wait for a reply, 100 to 30000, and not longer than the interval. `0` means 1000. |
| `fail_after` (number) | Consecutive misses before it is down, 1 to 100. `0` means 3. |
| `recover_after` (number) | Consecutive replies before it is up again, 1 to 100. `0` means 2. |
| `comment` | |

`GET /api/checks/status` returns the latest result of each, keyed by check id:

```json
{"0f915142": {"state": "up", "since": "2026-10-28T15:01:15+03:30", "last_probe": "2026-10-28T15:01:15+03:30",
              "rtt_ms": 12, "fails": 0, "oks": 1}}
```

`state` is `up`, `down`, or `unknown` before the first probe; `error` says why the last try failed.

### Client routing clients: `/api/client-routing/clients`

Sends a client out through a chosen interface; it generates the routes, rules and firewall entries for you. It only takes effect while client routing is switched on (see below).

| Field | Meaning |
|---|---|
| `name` | A label. |
| `src` | The client's IP or network, for example `10.0.0.5` or `10.0.0.0/16`. Required. |
| `in` | The client-facing interface. Required. |
| `out` | The exit interface. Required. |
| `kill_switch` (boolean) | Drop the client's traffic if the exit has no route, instead of leaking out the normal way. |
| `disabled` | |

`GET /api/generated` returns what client routing produced, as `{"routes": [], "rules": [], "firewall": []}`; each item has a `source` field and can't be changed through the API.

## Other settings

| Call | Body | Does |
|---|---|---|
| `GET /api/firewall` | | `{"policy": {...}, "rules": [...]}` |
| `PUT /api/firewall/policy` | `{"input": "accept", "forward": "accept", "output": "accept"}` | What happens to packets no rule decided, per chain: `accept`, `drop` or `reject`. |
| `GET /api/client-routing` | | `{"enabled": false, "table_base": 200, "priority_base": 10000, "exits": [...], "clients": [...]}` |
| `PUT /api/client-routing` | `{"enabled": true, "table_base": 200, "priority_base": 10000}` | Switches the feature on or off; the two numbers (`0` for the defaults) are where table and rule numbering start. The clients are changed through their own list. |
| `PUT /api/sysctl` | `{"ip_forward": true, "ipv6_forward": null, "conntrack_acct": true}` | Keep IP forwarding or connection byte counting on or off. A field you leave out stays as it is; `null` stops managing it. There is no `GET`: read the values from `/api/overview`. |
| `GET /api/tuning` | | The catalogue of kernel settings (id, group, label, description, allowed values, a recommended value) with `current` (in the kernel now), `managed` (what mini-net-man keeps, empty if not managed), `supported`, and `error`. |
| `PUT /api/tuning/{id}` | `{"value": "bbr"}` | Manage this setting at that value. An empty `value` stops managing it without undoing the change. `404` for an unknown id. |
| `POST /api/reapply` | | Makes the kernel match the config again. Returns `{"issues": []}`. |

## Looking at the machine

All `GET`, all safe for a read-only token.

| Call | Returns |
|---|---|
| `GET /api/overview` | Hostname, version, links, forwarding state, detected tools and warnings, current `issues`, safe mode status, and item `counts`. |
| `GET /api/links` | Every interface: `name`, `index`, `type`, `up`, `running`, `mtu`, `mac`, `addrs`, `rx_bytes`, `tx_bytes`, and, when they apply, `master` (its bridge) and `managed_by` (an array of `NetworkManager`, `systemd-networkd`, `mini-net-man`). |
| `GET /api/network/managers` | What manages the network on this machine: `{"managers": [{"id", "name", "running", "config", "detail", "note"}]}` (NetworkManager, systemd-networkd, netplan, ifupdown, ConnMan, dhcpcd, netctl, wicd, DHCP clients, cloud-init). |
| `GET /api/live/routes` | All routes in the kernel (except the `local` table). Items have `owned` (made by mini-net-man) and `proto` (`kernel`, `static`, `dhcp`, `mini-net-man`, ...). |
| `GET /api/live/rules` | All policy rules in the kernel, with `owned`. |
| `GET /api/sockets` | Listening TCP and bound UDP sockets, like `ss -tulnp`: `proto`, `addr`, `port`, `scope` (`all`, `local`, `address`), `user`, and `procs` (`pid`, `name`). |
| `GET /api/connections` | The connection-tracking table. Parameters: `q` (text search), `proto`, `kind` (`forwarded`, `incoming`, `outgoing`), `state`, `client`, `sort` (`client`, `data`, `expiry`, `dest`), `limit` (default 500, at most 5000). Returns `info` (`available`, `count`, `max`, `acct`), a `summary` (totals, `by_state`, `clients`, `exits`, byte totals) and `conns`. Each connection has the addresses and ports in both directions, `state`, `timeout` (seconds left), optional `bytes_out` and `bytes_in` (when counting is on), and `kind`, `client`, `nat` and `via` worked out by the server. When tracking isn't active, `info.available` is `false` and `conns` is empty. |
| `GET /api/firewall/ruleset` | `{"desired": "...", "live": "..."}`: the nft text mini-net-man would load, and what is loaded now. |
| `GET /api/generated` | Routes, rules and firewall entries produced by client routing. |
| `GET /api/me` | `{"user": "token:<name>"}` for a token, or the login name for a session. A cheap way to test a token. |

## Panel, accounts and updates

| Call | Notes |
|---|---|
| `GET /api/settings/web` | `{"listen", "port", "allowed_ips", "users", "tls"}`. Readable with a token. |
| `PUT /api/settings/web` | Session only. Refuses an allowed-IP list that would lock out the caller. |
| `GET /api/update` | Installed and latest version, whether one is available, `notes`, `can_install` and the `reason` if not. `?refresh=1` asks GitHub now; otherwise it is cached. |
| `POST /api/update/install` | Session only. |
| `POST /api/import/scan` | Looks for existing `ip` routes and rules, iptables and ufw rules, and proposes how to import them (`routes`, `rules`, `firewall`, `policy`, `notes`, and `skipped` with a reason for each rule that can't be imported). Changes nothing. |
| `POST /api/import/apply` | `{"routes": ["id"], "rules": ["id"], "firewall": ["id"], "policy": true}` adds the chosen items from the last scan to the config (`409` if you haven't scanned). |
| `POST /api/import/disable-ufw` | Turns ufw off so it stops fighting mini-net-man. Returns `{"output": "..."}` with what `ufw disable` printed. |
| `GET /api/tokens`, `POST /api/tokens`, `DELETE /api/tokens/{id}` | Session only: list, create (`{"name", "read_only", "password"}`, returns the secret once) and delete tokens. |
| `POST /api/login`, `/api/logout`, `/api/password`, `/api/username` | For the panel's own login; passwords and names can't be changed with a token. |

## Examples

**Python: add a route, then undo it if the machine stops answering.**

```python
import requests, time

BASE, H = "https://panel.example:8443", {"Authorization": "Bearer mnm_..."}
api = lambda m, p, **kw: requests.request(m, BASE + p, headers=H, timeout=10, **kw)

api("POST", "/api/safe/start", json={"timeout_secs": 60}).raise_for_status()
r = api("POST", "/api/routes", json={"dst": "default", "gateway": "10.8.0.1", "dev": "wg0", "table": "200"})
r.raise_for_status()
print(r.json())                       # {'id': '...', 'issues': []}

time.sleep(5)                         # ...check that traffic still flows...
api("POST", "/api/safe/heartbeat")    # (only if the check takes longer than the timeout)
api("POST", "/api/safe/confirm")      # keep it; without this it reverts after 60 s
```

**Shell: the same change to one field.**

```sh
ID=$(curl -s -H "Authorization: Bearer $TOKEN" $URL/api/routes | jq -r '.[] | select(.dst=="10.9.0.0/24") | .id')
curl -s -H "Authorization: Bearer $TOKEN" $URL/api/routes \
  | jq '.[] | select(.id=="'$ID'") | .metric = 200' \
  | curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d @- $URL/api/routes/$ID
```

**Build a bridge and put the address on it.**

```sh
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"name":"br0","ports":["eth1","eth2"]}' $URL/api/bridges
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"interface":"br0","address":"192.168.50.1/24"}' $URL/api/addresses
```

**Send one client out through a different exit.**

```sh
curl -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"enabled": true}' $URL/api/client-routing
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"name":"laptop","src":"10.0.0.7","in":"wgServer","out":"wgBridge1","kill_switch":true}' \
     $URL/api/client-routing/clients
```
