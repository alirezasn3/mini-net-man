# mini-net-man

A small web-managed Linux networking tool in the style of MikroTik RouterOS. One Go binary, one YAML file, one systemd unit.

- **Interfaces & addresses**: see interfaces, add extra IPs.
- **Routes** and **policy rules**: `ip route … table N` and `ip rule … priority N`, created by hand.
- **Firewall + NAT**: a dedicated dual-stack nftables table (`inet mini-net-man`), replaced atomically. Each chain's default action (accept, drop or reject) is the last row of the rule list and editable there.
- **Health checks**: ping an address out of an interface, and make policy rules depend on the result. A rule is switched off while its check fails (say, an exit tunnel that has silently died) and back on when it recovers.
- **Client routing** (optional): send chosen clients out through a chosen interface. It only generates ordinary routes, rules and firewall entries, shown as *generated*.
- **Ports**: which program is listening on which port (like `ss -tulnp`), and whether it is reachable from every interface or only this machine.
- **Connections**: the kernel's connection-tracking table: every connection, including your VPN clients' traffic passing through. Each is labelled with its client, the exit interface and the NAT applied, and optionally bytes up and down. Filter by client, state or protocol.
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

`-allow` takes IPs or CIDRs, comma separated, and adds to localhost rather than replacing it. If ufw is active you also need `ufw allow from 203.0.113.7 to any port 8080`. Change the password with `mini-net-man passwd admin`.

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
