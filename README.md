# tknet guest client

A Linux guest client for the TK mesh. It uses Python 3.9 or newer and the official Tailscale client.

## Install

```bash
curl -fsSL https://github.com/tinkerfuroc/tknet/releases/latest/download/install.sh | sh
```

The installer puts `tknet` in `~/.local/bin` without sudo. Set `TKNET_INSTALL_DIR`
in the installer's environment to choose a different directory. Run the same
command to upgrade. If needed, add the installation directory to your `PATH`.

Joining requires the [official Tailscale client](https://tailscale.com/download/linux)
and its running system service. The default Headscale endpoint is `https://hs.wkj24.top`.
For another endpoint, use `tknet --config /path/to/config.json join`, or set
`server_url` in `/etc/tknet/config.json`. See `config.json` for the file format.

## Use

```bash
tknet join
tknet status
tknet leave
tknet join
```

For first enrollment, `tknet join` prompts for the invitation
without echoing it or placing it in shell history. An invitation is a Headscale
one-use key issued with `tag:guest`. Once connected, use `ssh tinker@tkmain`.

The client enables DNS, disables accepted subnet routes and its Tailscale SSH
server, and enables shields-up for incoming connections. Existing authenticated
TK guest profiles are reused on reconnect. `leave` disconnects while retaining
the identity. Server-side revocation remains a Headscale administration operation.

First enrollment passes the invitation to Tailscale through a temporary mode-0600
file which is removed on success or failure. The CLI checks assigned role and
connectivity to tkserver before reporting success. A failed connectivity check
can leave an enrolled client connected; inspect `tknet status` and retry after
resolving the network problem. An interrupted enrollment may also have completed
at the server, so inspect state before requesting another invitation.

Administrative invitation generation is outside this client implementation.
Install and service startup are handled by the official Tailscale package.

## Offline validation

```bash
python3 -m unittest -v test_tknet.py
```

Tests substitute Tailscale responses and perform no network configuration.
Live enrollment and SSH acceptance require the deployed Headscale service.
