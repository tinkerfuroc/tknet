# tknet

A self-hosted Linux mesh client. No public DNS record, HTTPS server, or public
certificate authority is needed. Nebula connects directly over UDP when possible
and uses tkserver as a relay when direct connectivity fails. Existing high-port
SSH handles admission.

## Install and connect

```sh
curl -fsSL https://raw.githubusercontent.com/tinkerfuroc/tknet/main/install.sh | sh
tknet up <invitation-code>
ssh tkmain
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
Version v0.3.3 also manages a marked block in `/etc/hosts`, so browsers and
other applications using the system resolver can use names such as
`http://tkmain:9860/`. No DNS server is required. Guest `up` refreshes the block;
`down` and normal runtime exit remove only that block, preserving unrelated
entries and edits. Hosts maintain the block through their network service.
When UFW is already active, host setup allows traffic from `10.27.0.0/24`
on `tktun` only. This does not open physical interfaces. Services must listen
on the mesh IP or `0.0.0.0`; names do not expose localhost-only services.
The approved hosts are tkserver (`10.27.0.1`), tkmain (`10.27.0.2`), tkbox
(`10.27.0.3`) and tkmini (`10.27.0.4`). Each alias selects the `tinker` user.
After upgrading the client, run `tknet up` to refresh aliases without replacing
the existing identity or requesting another invitation.

The client runtime is under `/run/tknet-client`; logs are in
`/var/log/tknet-client.log`. Creating a virtual network interface requires root,
so the tool requests sudo when needed. No separate service setup is needed.

For clients upgrading from v0.2.x, stop and disable the old `tknet.service` once
before the first `up`. The already-deployed wkj-pi client has been migrated.
The v0.3 CLI uses `up` and `down` in place of `join` and `leave`.

## Admission on tkserver

The same source supports two installation roles. The default client has only
`up`, `down` and `status`; it does not install the management module. Install
the server role on tkserver with:

```sh
curl -fsSL https://raw.githubusercontent.com/tinkerfuroc/tknet/main/install.sh | sh -s -- --server
```

An ordinary upgrade preserves the installed role. `--client` explicitly
selects the client role and removes a previously installed management module.
Installation role is separate from Nebula membership: tkmain, tkbox and tkmini
are network hosts but use the client CLI. Internal root helpers are not shown
as user commands. Guests still need no systemd service.

Run management commands as tinker on tkserver after authority initialization:

```sh
tknet list
tknet list --json
tknet invite laptop-name
tknet renew laptop-name
tknet revoke laptop-name
```

The command prints the code to stdout and its 24-hour validity to stderr.
Send the code privately to that guest. It permits enrollment only,
not an interactive server login. The device creates its own keys and receives
Nebula membership and a user certificate restricted to the tinker SSH principal.

`list` shows admission records, not online status. `renew` issues another year
using the existing device public keys, address and role. Online hosts receive
their certificates immediately. Connected v0.4 guests refresh certificates
and policy through the existing native SSH endpoint every 30 seconds; allow
up to 60 seconds while the authority is reachable. Disconnected clients fetch
them at the next `tknet up`. The restricted refresh key remains usable after
certificate expiry, but can only retrieve that device's records, not a shell.
An offline host can fetch its renewed certificates with `tknet up` too.

`revoke` cancels unredeemed invitations, refuses future renewal/refresh, and
blocks all recorded Nebula certificate versions plus the device's SSH public
key. It distributes a full Nebula blocklist and OpenSSH KRL to every remaining
host. Nebula tears down blocked tunnels. If any host cannot be updated, the
command reports it as `pending` and returns nonzero; that host has not yet
enforced the revocation. Run the same revoke command again after connectivity
is restored. It is idempotent. Guest policy refresh requires v0.4 clients.
Revoking tkserver itself is not supported. Native personal recovery SSH keys
are outside mesh membership and are not removed.

The operator accepts that anyone able to log in as tinker on tkserver can
manage admission. This is an installation-role split, not a separate human
administrator privilege model. Device private keys remain on each device;
authority records and refresh responses contain only public credentials.

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
SSH login, direct transport and forced relay tests. Version v0.3.2 enrolls tkbox
and tkmini. Both passed SSH login from wkj-pi, tkserver and tkmain, outbound SSH
to existing hosts, and rejection of new connections to the guest. tkbox briefly
became unreachable through both native and mesh SSH, then recovered; the cause
is not established. The v0.3.3 rollout verified tkbox-to-tkmini SSH in both
directions and HTTP 200 from wkj-pi, tkbox and tkmini at `http://tkmain:9860/`.
Guest up/down/repeated-up tests preserved unrelated hosts entries and installed
only one managed block. Version v0.4.0 passed isolated live guest enrollment,
automatic renewal, revoked SSH-certificate rejection, HTTP denial, and active
session termination. Normal guest HTTP remained available; tkmini host renewal
was installed successfully. Guest membership is valid for one year. FRP was
retired on 2026-11-15: server and client services are stopped and disabled.
Native direct SSH remains available through the local `*-ssh` aliases.
UDP reachability is required even when relaying.

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
