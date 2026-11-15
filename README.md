# tknet

A self-hosted Linux mesh client. No public DNS record, HTTPS server, or public
certificate authority is needed. Nebula connects directly over UDP when possible
and uses tkserver as a relay when direct connectivity fails. Existing high-port
SSH handles admission.

## Install and join

```sh
curl -fsSL https://raw.githubusercontent.com/tinkerfuroc/tknet/main/install.sh | sh
tknet join laptop-name.tknet
ssh tinker@tkmain
```

Requires Linux with systemd, Python 3.9+, OpenSSH, curl, tar, iproute2, ping and
sudo. The installer supports amd64 and arm64. It installs pinned Nebula 1.12.0
binaries under /opt/tknet/bin and the client under ~/.local/bin. Software downloads
use GitHub HTTPS; the running mesh has no HTTPS or public-DNS dependency.

The guest receives a private invitation file from tkserver. Alternatively,
`tknet join` prompts for a tk2 encoded invitation. Each invitation expires after
24 hours and is bound to the first device's public keys. Lost-response retries
with the same keys are allowed. Device private keys never leave the device.

```sh
tknet status
tknet leave
tknet join
```

Leaving keeps the identity but disables mesh SSH overrides. Rejoining reuses it.
The original SSH configuration is preserved and backed up before the first join.
Friendly names are local SSH aliases; other applications can use mesh IPs.

## Admission on tkserver

Run as tinker after the authority has been initialized:

```sh
tknet invite laptop-name
```

Send laptop-name.tknet privately to that guest. It permits enrollment only,
not an interactive server login. The device creates its own keys and receives
Nebula membership and a user certificate restricted to the tinker SSH principal.

All hosts accept traffic from approved hosts and guests. No role may initiate
new connections to a guest. The overlay SSH server accepts only tinker and
trusts the tkserver SSH CA; no pairwise authorized_keys management is needed.
The separate native recovery SSH configuration is preserved.

## Current acceptance and limits

The tkserver / tkmain / wkj-pi path has passed invitation redemption, join,
SSH login, direct transport and forced relay tests. tkbox and tkmini are not yet
enrolled in this version. Guest membership is currently valid for one year;
automated renewal and operational revocation commands are pending. The existing
FRP fallback remains available. UDP reachability is required even when relaying.

## Development

```sh
python3 -m unittest -v test_tknet.py
```

Tests use real Nebula/OpenSSH certificate tools when installed, with temporary
keys and files. They do not alter live network configuration.
