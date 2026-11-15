# tknet

A self-hosted Linux mesh client. No public DNS record, HTTPS server, or public
certificate authority is needed. Nebula connects directly over UDP when possible
and uses tkserver as a relay when direct connectivity fails. Existing high-port
SSH handles admission.

## Install and connect

```sh
curl -fsSL https://raw.githubusercontent.com/tinkerfuroc/tknet/main/install.sh | sh
tknet up <invitation-code>
ssh tinker@tkmain
```

Requires Linux with TUN support, system Python 3.9+ at `/usr/bin/python3`,
OpenSSH, system OpenSSL, ping and sudo. Python uses only its standard library;
there is no pip, venv, cryptography or iproute2 dependency. Route rules use the
Linux rtnetlink interface directly. The virtual interface is named `tktun`.

Installation also uses curl and tar. The installer supports amd64 and arm64.
It downloads pinned Nebula 1.12.0 from the official `slackhq/nebula` GitHub
release, selects the matching architecture, and extracts `nebula` and
`nebula-cert` into `/opt/tknet/bin`. If both binaries already exist and the
Nebula version matches, it skips this download. The CLI is installed under
`~/.local/bin` and the administrative library under `/opt/tknet/lib`. Software downloads
use GitHub HTTPS; the running mesh has no HTTPS or public-DNS dependency.

The guest receives a 47-character invitation code beginning with `tk3_`.
`tknet up` can also prompt for the code without echoing it. Each code expires after
24 hours and is bound to the first device's public keys. Lost-response retries
with the same keys are allowed. Permanent device private keys never leave the
device and existing keys are reused. Server IP, port, and the existing SSH host
public key ship with the client, so they do not need to be copied with each code.
The code is a restricted bootstrap credential, not a general SSH login key.
Earlier invitation files and tk2 encodings remain readable for compatibility.

```sh
tknet status
tknet down
tknet up
```

`up` starts the connection in the background and returns the terminal. Clients
do not install or depend on systemd services and do not start at boot. After a
reboot, run `tknet up`. It reuses the saved identity without another invitation.
Repeated `up` calls reuse the running connection instead of starting duplicates.

`down` stops the client, removes its temporary routing rules, and disables mesh
SSH overrides. It preserves the identity. Hosts still use persistent services.
The original SSH configuration is preserved and backed up before the first join.
Friendly names are local SSH aliases; other applications can use mesh IPs.

The client runtime is under `/run/tknet-client`; logs are in
`/var/log/tknet-client.log`. Creating a virtual network interface requires root,
so the tool requests sudo when needed. No separate service setup is needed.

For clients upgrading from v0.2.x, stop and disable the old `tknet.service` once
before the first `up`. The already-deployed wkj-pi client has been migrated.
The v0.3 CLI uses `up` and `down` in place of `join` and `leave`.

## Admission on tkserver

Run as tinker after the authority has been initialized:

```sh
tknet invite laptop-name
```

The command prints the code to stdout and its 24-hour validity to stderr.
Send the code privately to that guest. It permits enrollment only,
not an interactive server login. The device creates its own keys and receives
Nebula membership and a user certificate restricted to the tinker SSH principal.

All hosts accept traffic from approved hosts and guests. No role may initiate
new connections to a guest. The overlay SSH server accepts only tinker and
trusts the tkserver SSH CA; no pairwise authorized_keys management is needed.
The separate native recovery SSH configuration is preserved.

## Current acceptance and limits

The v0.3.0 guest runtime was tested on wkj-pi with the legacy systemd unit
removed: down, up, SSH to tkmain and repeated up all passed. Down removed the
interface and owned policy rules; repeated up kept the same runtime process.
The client does not change the persistent services running on hosts.

The tkserver / tkmain / wkj-pi path has passed invitation redemption, join,
SSH login, direct transport and forced relay tests. tkbox and tkmini are not yet
enrolled in this version. Guest membership is currently valid for one year;
automated renewal and operational revocation commands are pending. The existing
FRP fallback remains available. UDP reachability is required even when relaying.

The invitation-code flow was separately verified against tkserver with an isolated
temporary identity: redemption, signed SSH login to tkmain, same-key retry, and
rejection of different-device replay and expired codes. This test preserved the existing network
service and device keys. The 47-character code is unchanged. System OpenSSL
derives the Ed25519 public key; Python serializes the documented
[OpenSSH key envelope](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key).

## Development

```sh
/usr/bin/python3 -S -m unittest -v test_tknet.py
```

Tests use real Nebula/OpenSSH certificate tools when installed, with temporary
keys and files. They do not alter live network configuration.
