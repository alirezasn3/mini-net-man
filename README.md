# mini-net-man

A small web-managed Linux networking tool in the style of MikroTik RouterOS. One Go binary, one YAML file, one systemd unit.

- **Interfaces & addresses**: see interfaces, add extra IPs.
- **Routes** and **policy rules**: `ip route … table N` and `ip rule … priority N`, created by hand.
- **Interfaces and bridges**: bring interfaces up or down, set their MTU, build bridges and choose their ports, all kept in place by the reconcile loop. The page also says what else manages the network (NetworkManager, systemd-networkd, netplan, ifupdown, ...) and which interfaces each one claims.
- **Address lists**: named lists of IPs, networks and ranges, like MikroTik's address lists. Firewall rules match a list (or "not in" it) and can add the source or destination of matching traffic to a list for a while: blocklists, whitelists, and "block anyone who keeps trying SSH".
- **Sorting**: click a column heading on any list (routes, policy rules, firewall rules, …) to sort it ascending, again for descending, a third time to go back. It only changes the view, is remembered in your browser, and never changes the order rules are applied in; moving firewall rules is off while a sort is active.
- **HTTP API**: everything the panel does is a JSON API that other programs can call with an API token (made in Settings, optionally read-only).
- **Firewall + NAT**: a dedicated dual-stack nftables table (`inet mini-net-man`), replaced atomically. Interface fields take a trailing `*` as a wildcard (`wg*` matches `wg0` and `wgBridge1`). Each chain's default action (accept, drop or reject) is the last row of the rule list and editable there.
- **MSS clamping**: shrink the TCP segment size of connections passing through, so a tunnel or PPPoE exit with a smaller MTU doesn't stall large transfers (MikroTik's `change-mss` mangle rule).
- **Connection marking**: tag connections by the interface they arrived on and route replies by that tag, for a machine with several links that carry the same client addresses.
- **Health checks**: ping an address out of an interface, and make policy rules depend on the result. A rule is switched off while its check fails (say, an exit tunnel that has silently died) and back on when it recovers.
- **Client routing** (optional): send chosen clients out through a chosen interface. It only generates ordinary routes, rules and firewall entries, shown as *generated*.
- **Ports**: which program is listening on which port (like `ss -tulnp`), and whether it is reachable from every interface or only this machine.
- **Connections**: the kernel's connection-tracking table: every connection, including your VPN clients' traffic passing through. Each is labelled with its client, the exit interface and the NAT applied, and optionally bytes up and down. Filter by client, state or protocol.
- **Tuning**: a curated set of kernel settings for a VPN gateway or router: BBR congestion control, queue discipline, socket buffers, MTU probing, connection-tracking size and timeouts, reverse-path filtering, ICMP redirects. Each has an explanation and a recommended value.
- **Import**: adopts existing `ip rule`/`ip route`, `iptables-save`, ufw and iptables-persistent rules, and lists the ones it can't convert with the reason for each (a module with no equivalent, a jump to another chain, a negated match, ufw rate limiting, ...).
- **Safe mode**: changes revert automatically unless you confirm, or if the browser disconnects.

IPv4 and IPv6 are both supported. Linux only for the real backend (`-mock` runs anywhere).

## Install

Download the binary from the [latest release](https://github.com/alirezasn3/mini-net-man/releases/latest) into its own folder (the config is created beside it), then run `install` as root. That is the whole setup. On the server (use `mini-net-man-linux-arm64` on ARM; `uname -m` says `aarch64`):

```sh
mkdir -p ~/mini-net-man && cd ~/mini-net-man
curl -fL -o mini-net-man https://github.com/alirezasn3/mini-net-man/releases/latest/download/mini-net-man-linux-amd64
chmod +x mini-net-man
sudo ./mini-net-man install
```

Each release also has a `checksums.txt` to verify the download against (`sha256sum -c`). To build from source instead, run `make linux` and copy `bin/mini-net-man-linux-*` over.

`install` creates `config.yaml` **next to the binary** (unless you pass `-config`), writes and starts a systemd service that runs the binary in place, and prints the login. Re-run it after replacing the binary to restart on the new one. `uninstall` removes the service and keeps your config.

By default only the server itself may open the panel, so reach it through an SSH tunnel (`ssh -L 8080:127.0.0.1:8080 server`, then browse to `http://127.0.0.1:8080`). To open it to your own address instead:

```sh
sudo ~/mini-net-man/mini-net-man install -allow 203.0.113.7 -port 8080
```

`-allow` takes IPs or CIDRs, comma separated, and adds to localhost rather than replacing it. If ufw is active you also need `ufw allow from 203.0.113.7 to any port 8080`. Change the password with `mini-net-man passwd admin`, or the username and password from **Settings** in the panel. The login page doesn't suggest a username.

To try it first without installing anything, run `sudo ~/mini-net-man/mini-net-man run` in the foreground. Stopping it does not undo the rules it created.

## Updating

Updates come from GitHub Releases. Once a release build is installed (see *Releasing* below), update it in place:

```sh
sudo ~/mini-net-man/mini-net-man update          # install the latest release and restart the service
sudo ~/mini-net-man/mini-net-man update -check   # only say whether a newer one exists
sudo ~/mini-net-man/mini-net-man update -rollback   # go back to the version before
```

The panel does the same from **Settings → Updates**: it looks up the latest release when you log in, shows an *Update available* badge, and installs on one click. Either way the new binary is checked against the release's `checksums.txt`, test-run (`<binary> version` must print the release tag), and only then swapped in; the old one is kept as `mini-net-man.old`. Your rules stay in the kernel while the service restarts, and the config is untouched. The panel refuses to update during safe mode.

`update -version v0.1.0` installs a specific release (also to go back), `update -force` reinstalls. A binary built from a branch has no release version and refuses plain `update`; install a release build once and it works from then on. To turn off the lookup at login, set `update: {no_auto_check: true}` in the config.

Private repository or GitHub Enterprise: set `MINI_NET_MAN_GITHUB_TOKEN` and/or `MINI_NET_MAN_API` in the service's environment, and `update: {repo: owner/name}` in the config.

## Releasing

Push a tag; `.github/workflows/release.yml` tests, builds `mini-net-man-linux-amd64` and `-arm64` with the tag stamped in as the version, and publishes them with a `checksums.txt`:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

A tag with a dash (`v1.0.0-rc1`) is published as a pre-release and is not offered as the latest. `make linux VERSION=v0.1.0` builds the same binaries locally. The repository defaults to `alirezasn3/mini-net-man`; change `DefaultRepo` in `internal/update/update.go` if yours differs.

## Conditional rules (health checks)

Add a health check on the **Policy rules** page (name, address to ping, interface to ping out of), then pick it under a rule's **Condition**. The check sends one ICMP echo out of that interface every few seconds. After `fail_after` misses in a row (default 3) it is *down* and every rule that depends on it is taken out of the kernel, so traffic falls through to the next rule, for instance back to the main table. After `recover_after` replies in a row (default 2) it is *up* again and the rules return. A single lost ping changes nothing.

- The configured rule is never edited; it just isn't in the kernel while the check is down. The rule list shows an **off: check failing** chip.
- A check that hasn't been measured yet (just after a restart) counts as up, so a restart never switches rules off by itself; a dead exit is noticed within `fail_after` x `interval` seconds.
- Ping something that should always answer and sits beyond the exit, such as `1.1.1.1`, so it proves the whole path rather than just the tunnel's first hop.
- The ping is bound to the interface, so it goes out through it even if no route covers the target, which is what a WireGuard exit with `Table = off` needs. If an exit is reached through a **gateway** whose route is in a custom routing table, put that table in the check's *Routing table* field: mini-net-man then adds a helper rule `oif <interface> lookup <table>` (priority 1, shown as *generated*) that applies only to the check's own pings.
- The reply has to get past Linux's reverse-path filter (`rp_filter`). In Ubuntu's default loose mode (2) that only needs the target to have *some* route on the machine, which a normal default route in the main table gives it. If a check times out although the exit clearly works, and `rp_filter` is 1 (strict) or the main table has no default route, set `net.ipv4.conf.<interface>.rp_filter=2` (or 0) on the exit interface.
- IPv4 and IPv6 targets both work. A rule can't be saved if its check doesn't exist, and a check in use can't be deleted.

## Replying on the interface a request came in on

Normally the routing table alone decides where a reply goes. If two links carry the same client addresses (say two servers that both serve `10.0.0.0/16`, load-balanced), the table has one way back to that range, so the reply to a client that arrived on the *other* link leaves by the wrong one and is lost. The fix is to remember which link each connection came in on. In this setup the panel server has `ens70` and `ens71`:

1. **Routing tables**, one per link, on the **Routes** page: `10.0.0.0/16 via <that link's gateway>` in table 70, and the same through the other gateway in table 71.
2. **Policy rules** on the **Policy rules** page: *Firewall mark* 70 looks up table 70, mark 71 looks up table 71.
3. **Firewall rules**:
   - chain `mangle-in`, action `mark-connection`, *In interface* `ens70`, *Mark* 70, and the same with `ens71` and 71. These stamp the mark on every connection that arrives there.
   - chain `mangle-out`, action `restore-mark`. This gives each reply the mark of its connection, and the kernel routes it again with the new mark.
4. Set `rp_filter` to loose (2) or off under **Tuning**, because packets from `10.0.0.0/16` arrive on a link the main table doesn't point at, and strict mode drops them.

**Rules in `mangle-in` and `mangle-out` don't stop at the first match.** Marking and adding to a list are not verdicts: after one matches, the following rules in the chain are still checked. If several `mark-connection` rules match the same packet, the **last** one wins (it overwrites the mark), so put the general rule first and the more specific one after it. There is no "passthrough: no" (a rule that ends the chain); to keep a packet out of a later rule, make that rule's match exclude it (for example `!` in front of an address list).

Forwarded traffic works the same way: add `restore-mark` to `mangle-in` (after the `mark-connection` rules) so the reply direction of a forwarded connection is routed by the mark too. Marks are also what other tools such as WireGuard's `FwMark` use, so pick numbers that don't clash with them.

## Interfaces and bridges

The **Interfaces** page lists every interface the kernel has (state, MTU, bridge, addresses) and what manages it, then lets you keep things the way you want them. Like everything else here, what you enter is kept true: if something changes it, the next reconcile puts it back.

- **Interface settings** keep an existing interface *up* or *down* and/or at an *MTU*. A field you leave empty isn't touched. Deleting an entry stops managing the interface; it doesn't undo the change. The **Take down / Bring up** buttons in the list are a shortcut that makes such an entry.
- **Bridges** make a software switch from the interfaces in *Ports*. The bridge is created if it doesn't exist and brought up; ports that exist are joined and brought up (unless an interface setting keeps them down); ports you remove from the list are released. Spanning tree (*STP*) is off unless you turn it on. An interface can be in only one bridge.
- **Put the IP address on the bridge**, not on its ports: a port that keeps its own address stops answering on it. Add the address on this page (Addresses) to the bridge once it exists.
- A bridge mini-net-man **created** is deleted again when you delete its entry. A bridge that already existed (docker0, a bridge from netplan) is only joined to and released from, never deleted, and only the ports mini-net-man joined are released.
- Taking down the interface this panel is reached through cuts you off. Use **Safe mode**: it reverts everything unless you confirm, and a bridge setup that goes wrong is undone with it. `lo` can't be taken down.

### What manages the network

At the top of the page, mini-net-man reports what else configures this machine: **NetworkManager**, **systemd-networkd**, **netplan** (and the daemon it renders for), **ifupdown**, **ConnMan**, **dhcpcd**, **netctl**, **wicd**, DHCP clients, and **cloud-init**, each marked running and/or configured. In the list, each interface shows who claims it: NetworkManager's device status (anything not *unmanaged*), systemd-networkd's link state, and *mini-net-man* if it is in your config.

When an interface is claimed by NetworkManager or systemd-networkd **and** by mini-net-man, the list shows *both*: that daemon may undo what you set (and you will see the two fight, as the kernel changes again and again). Tell it to leave the interface alone (`nmcli device set <name> managed no`, or an `unmanaged-devices` entry; for networkd, remove or narrow its `.network` file) or don't manage that interface here. This is detection only: mini-net-man never edits those tools' configuration.

## Address lists

An address list is a named set of addresses, like MikroTik's `/ip firewall address-list`. On the **Address lists** page each row puts one IP, network (`10.0.0.0/8`), range (`10.0.0.5-10.0.0.20`) or **domain name** (`example.com`) in a list. A list can hold IPv4 and IPv6 together. **Add many at once** takes a pasted blocklist (one entry per line, `#` starts a comment) and is all or nothing, so one typo adds nothing.

On the **Firewall** page a rule can use lists:

- **Source in address list** and **Destination in address list** match traffic from or to anything in the list. Put `!` in front (`!allowed`) for "not in the list". A rule that doesn't name a family applies to both: it looks up the IPv4 half of the list for IPv4 packets and the IPv6 half for IPv6.
- Actions **add-src-to-list** and **add-dst-to-list** put the packet's source or destination address into a list, for a number of seconds (0 keeps it until you remove it; seeing the address again starts the time over). The rule doesn't stop the packet: matching carries on with the next rule, as in MikroTik, so adding and dropping take two rules. The list is created if it doesn't exist.

Rules that add to a list, in order, are how you build the usual MikroTik patterns. For example, blocking an address that keeps opening SSH connections (the strictest stage goes first, because every rule sees the packet):

| # | Chain | Match | Action |
|---|---|---|---|
| 1 | input | source in list `ssh-blocked` | drop |
| 2 | input | tcp dport 22, state new, source in list `ssh-stage2` | add-src-to-list `ssh-blocked`, 86400 s |
| 3 | input | tcp dport 22, state new, source in list `ssh-stage1` | add-src-to-list `ssh-stage2`, 60 s |
| 4 | input | tcp dport 22, state new | add-src-to-list `ssh-stage1`, 60 s |

Within a minute the first new connection puts the sender in `ssh-stage1`, the second in `ssh-stage2`, the third in `ssh-blocked`, and from the fourth on it is dropped. A whitelist is the same idea in reverse: a *drop* rule with *Source in address list* `!trusted` on the ports you want closed to everyone else.

What to know:

- **Domain names** are looked up by this machine, using the resolvers in `/etc/resolv.conf`, for both IPv4 (A) and IPv6 (AAAA), following CNAMEs. Their addresses go into the list with a timeout, and the name is looked up again by the DNS TTL (never more often than every 30 seconds, never less often than hourly). An address stays 30 seconds longer than that, so a slow lookup leaves no gap, and it leaves by itself when DNS stops returning it. Each name shows what it resolved to; a name that fails to resolve shows *lookup failed* with the reason and is retried every 30 seconds, backing off to 5 minutes, while the addresses it already has stay until they expire. A name covers **exactly that name**: not its subdomains (add those too), and only the addresses this machine's DNS returns for it. A site that hands different addresses to different places or rotates through many (CDNs) may send your clients to addresses this machine never sees, so a name is a good fit for a handful of stable hosts and a poor one for large CDN-backed sites. Names with non-ASCII letters must be written in punycode (`xn--...`).
- The entries you write are in your config. What rules add, and the addresses of domain names, are **not**: it lives in the kernel (a set with timeouts), so it is gone after a reboot (names are looked up again within seconds of starting; rules start from nothing), and it is shown separately under **Added by rules and domain names**, where you can remove one address or empty a list. It stays while you change the firewall; the table is rebuilt with those addresses and their remaining time. Taking a name out of a list takes its addresses out at once.
- Overlapping entries are merged (the kernel refuses overlaps), so `10.0.0.0/24` and `10.0.0.128-10.0.0.200` together are one range. The same range written two ways counts as a duplicate.
- A rule that names a list nobody has filled just matches nothing (`!list` matches everything).
- Under the hood each list is four nftables sets (`<name>.s4`, `.s6` for your entries; `.d4`, `.d6` for what rules add). Because one comparison can't ask "in this set or that", a rule that matches a list is written once per set and family: a positive match on a list can be up to four rules in `nft list ruleset`, all with the same action. A dynamic set holds at most 131072 addresses; when it is full, new ones are not added.
- List names start with a letter and have at most 24 characters (letters, digits, `_`, `-`, `.`).

## MSS clamping

MikroTik's `/ip firewall mangle ... action=change-mss new-mss=1300` is a rule with action **clamp-mss** in the **mangle** chain. It rewrites the MSS in the SYN (and SYN-ACK) of TCP connections passing through, so both ends send packets that fit the smallest link on the path. Without it, a client with a 1500 MTU talking through a WireGuard exit (1420) or PPPoE (1492) relies on path-MTU discovery, and when an ICMP "fragmentation needed" message gets lost the symptom is a connection that works for small pages and then hangs on large downloads or TLS handshakes.

- **MSS 0** (the default) fits the MTU of the route the packet is about to leave on, so it follows the interface instead of a number you have to keep right. A fixed value (say 1300) is the same as the MikroTik rule.
- An MSS that is already lower is never raised.
- Match with *Out interface* set to the exit (`wgBridge0`, `ppp0`). A rule with no interface clamps every forwarded connection, each to its own outgoing route.
- It acts on forwarded traffic only. The machine's own connections already pick their MSS from the route.
- A rule with *Out interface* set to the exit only sees what leaves through it: the SYN going out, which is what keeps downloads from stalling. The far side's SYN-ACK comes back in through the exit and leaves towards the client, so that rule doesn't touch it. If uploads still stall, add a second rule with *In interface* set to the exit and a fixed MSS 40 below its MTU (1380 for MTU 1420; 1360 for IPv6).

## Kernel tuning

The **Tuning** page lists settings that matter for a VPN or router box, each with what it does, the current value and a recommended one. They are `sysctl` values, saved under `sysctl.tuning` in the config.

- A setting you **manage** is applied at boot and put back if something else changes it. One you don't manage is left exactly as the system has it. **Stop managing** does not undo the change: the value stays until the next reboot.
- **BBR** (`tcp_congestion_control`) only speeds up connections that end on this machine (the panel, a proxy running here). Your clients' traffic that merely passes through is paced by its two ends. The `tcp_bbr` module is loaded for you; if the kernel doesn't have it, the page says so and the other settings still apply. It is usually paired with the `fq` queue discipline.
- **Default queue discipline** only affects interfaces that come up after it is set; an existing interface keeps its queue until it is brought down and up.
- A setting the system won't let it change (read-only `/proc/sys`, as inside some containers) is reported on the page instead of failing the rest.
- Only the keys in the page's list can be read or written; the API doesn't accept arbitrary sysctls.

## HTTP API

The panel is a thin layer over a JSON API, so any program can do what the panel does. Make a token under **Settings → API tokens** (one per program, so you can revoke one without touching the rest) and send it on every call:

```sh
curl -H "Authorization: Bearer mnm_..." http://panel:8080/api/routes

curl -X POST -H "Authorization: Bearer mnm_..." -H "Content-Type: application/json" \
     -d '{"dst":"10.9.0.0/24","dev":"wg0"}' http://panel:8080/api/routes
# {"id":"13349acc","issues":[]}
```

**[docs/API.md](docs/API.md) is the full reference**: every endpoint, the fields of every item (routes, rules, firewall rules, bridges, ...) with their allowed values, error and `issues` handling, safe mode from a script, and examples in curl and Python.

The essentials:

- The secret is shown once and only its hash is stored. A **read-only** token can use `GET` and nothing else. No token can manage logins or tokens, change the allowed IPs, or install updates.
- The caller's address must be in **Allowed client IPs**, and wrong tokens count towards the same lockout as wrong passwords (5 in a minute). Changes made with a token are logged with its name. Browsers on other sites can't call it (no CORS): use it from a server or script, and use TLS (`tls_cert`/`tls_key`) when the token crosses an untrusted network.
- Every list (`routes`, `rules`, `addresses`, `bridges`, `interfaces`, `checks`, `firewall/rules`, `client-routing/clients`) has the same calls: `GET`, `POST` (returns the new `id`), `PUT /{id}` (replaces the item), `DELETE /{id}` and `POST /{id}/move`.
- A change is validated first (`400` and nothing saved if it is wrong), then applied. Items the kernel can't apply yet are returned as `issues` and retried.

## IPv6

Everything works for both families. The family of a route comes from its destination (`::/0` is the IPv6 default; `default` with an IPv6 gateway also works). The family of a policy rule comes from its `from`/`to`, or its Family field. Firewall rules live in one `inet` table: a rule with no address and no Family applies to **both** families, so set Family to `IPv4` for things like a v4-only masquerade. Client routing routes each client within its own family. Imported iptables/ufw rules are pinned to the family they came from. Serve the panel over IPv6 by setting `listen` to `::`.

Enabling IPv6 forwarding makes Linux ignore router advertisements on interfaces where `accept_ra` is 1. If this machine gets its IPv6 address by SLAAC, set `accept_ra=2` on that interface first.

## Develop (any OS)

```sh
go run ./cmd/mini-net-man -mock -config mock-config.yaml   # fake kernel on :8080
cd web && npm run dev                                       # hot-reloading UI on :5173
go test ./...
make integration                                            # real kernel, needs Docker (see below)
```

### Integration tests

`make integration` builds a Debian image with `iproute2` and `nftables`, starts it `--privileged`, and runs `internal/integration` against a live Linux kernel, each test in its own network namespace. It checks the real `ip rule`, `ip route` and `nft list` output, and sends real packets across a veth pair to prove firewall rules behave (address and port matching, per family, ct state, reject, DNAT). Run a single test with `make integration T=TestFirewallBehavior`.

## How reconciliation works

The config is the source of truth. On start, on every change and on every link/address/route event, the engine makes the kernel match it:

- Routes and rules we create carry protocol tag `201`; only tagged objects are ever deleted. Existing identical rules made by hand are adopted.
- Addresses have no owner tag, so the last applied set is remembered in `config.yaml.state`.
- The firewall is one nftables table, replaced in a single transaction.

## Using it next to ufw

nftables evaluates every base chain, so a packet must be accepted by ufw's chains **and** mini-net-man's. Use *Import*, then disable ufw.
