# mini-net-man

A small web-managed Linux networking tool in the style of MikroTik RouterOS. One Go binary, one YAML file, one systemd unit.

- **Interfaces & addresses**: see interfaces, add extra IPs.
- **Routes** and **policy rules**: `ip route … table N` and `ip rule … priority N`, created by hand.
- **Firewall + NAT**: a dedicated dual-stack nftables table (`inet mini-net-man`), replaced atomically.
- **Client routing** (optional): send chosen clients out through a chosen interface. It only generates ordinary routes, rules and firewall entries, shown as *generated*.
- **Ports**: which program is listening on which port (like `ss -tulnp`), and whether it is reachable from every interface or only this machine.
- **Import**: adopts existing `ip rule`/`ip route`, `iptables-save`, ufw and iptables-persistent rules.
- **Safe mode**: changes revert automatically unless you confirm, or if the browser disconnects.

IPv4 and IPv6 are both supported. Linux only for the real backend (`-mock` runs anywhere).

## Install

Put the binary in its own folder (the config is created beside it), then run `install` as root. That is the whole setup:

```sh
ssh server 'mkdir -p ~/mini-net-man'
scp bin/mini-net-man-linux-amd64 server:mini-net-man/mini-net-man
ssh -t server 'sudo ~/mini-net-man/mini-net-man install'
```

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
