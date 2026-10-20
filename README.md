# mini-net-man

A small web-managed Linux networking tool in the style of MikroTik RouterOS. One Go binary, one YAML file, one systemd unit.

- **Interfaces & addresses**: see interfaces, add extra IPs.
- **Routes** and **policy rules**: `ip route … table N` and `ip rule … priority N`, created by hand.
- **Firewall + NAT**: a dedicated dual-stack nftables table (`inet mini-net-man`), replaced atomically.
- **Client routing** (optional): send chosen clients out through a chosen interface. It only generates ordinary routes, rules and firewall entries, shown as *generated*.
- **Import**: adopts existing `ip rule`/`ip route`, `iptables-save`, ufw and iptables-persistent rules.
- **Safe mode**: changes revert automatically unless you confirm, or if the browser disconnects.

IPv4 and IPv6 are both supported. Linux only for the real backend (`-mock` runs anywhere).

## Run

```sh
make linux                                   # bin/mini-net-man-linux-{amd64,arm64}
scp bin/mini-net-man-linux-amd64 server:/usr/local/bin/mini-net-man
ssh server 'mini-net-man install'            # installs and starts the systemd service
ssh server 'journalctl -u mini-net-man | head'   # first-run admin password is printed here
```

The config lives at `/etc/mini-net-man/config.yaml`. The panel listens on `web.listen:web.port` and answers only addresses in `web.allowed_ips` (default: localhost). Change the password with `mini-net-man passwd admin`.

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
