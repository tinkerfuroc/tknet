#!/usr/bin/env python3
"""Join the TK mesh as a guest using the installed Tailscale client."""

import argparse
import getpass
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit


DEFAULT_SERVER_URL = "https://hs.wkj24.top"
SYSTEM_CONFIG = Path("/etc/tknet/config.json")


class Client:
    def __init__(self, config):
        self.server = config["server_url"].rstrip("/")
        parsed = urlsplit(self.server)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("server_url must be an HTTPS URL")
        self.hostname = parsed.hostname
        self.port = parsed.port or 443
        self.binary = shutil.which("tailscale")
        if not self.binary:
            raise RuntimeError("Install the official Tailscale client first, then retry.")

    def run(self, arguments, privileged=False, secret=""):
        command = [self.binary, *arguments]
        if privileged and os.geteuid() != 0:
            command = ["sudo", *command]
        result = subprocess.run(command, text=True, capture_output=True, timeout=100)
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip()
            if secret:
                detail = detail.replace(secret, "[redacted]")
            raise RuntimeError(detail or "Tailscale command failed")
        return result.stdout

    def state(self):
        return json.loads(self.run(["status", "--json"]))

    def check_profile(self, state):
        if not (state.get("Self") or {}).get("ID"):
            return
        prefs = json.loads(self.run(["debug", "prefs"]))
        if prefs.get("ControlURL", "").rstrip("/") != self.server:
            raise RuntimeError(
                "This device has another Tailscale profile. "
                "Log out of that profile before joining the TK mesh."
            )
        tags = (state.get("Self") or {}).get("Tags") or []
        if tags and tags != ["tag:guest"]:
            raise RuntimeError("This tool joins guest devices. The current device has another role.")

    def show_status(self, state):
        print("State:", state.get("BackendState", "Unknown"))
        print("Addresses:", ", ".join(state.get("TailscaleIPs") or []) or "none")
        peers = (state.get("Peer") or {}).values()
        for peer in sorted(peers, key=lambda peer: peer.get("HostName", "")):
            if "tag:host" in (peer.get("Tags") or []):
                name = peer.get("DNSName", "").rstrip(".") or peer.get("HostName", "")
                print(f"  {name}: {'online' if peer.get('Online') else 'offline'}")

    def join(self, invitation):
        state = self.state()
        self.check_profile(state)
        settings = [
            "--ssh=false",
            "--shields-up=true",
            "--accept-dns=true",
            "--accept-routes=false",
        ]
        has_identity = bool((state.get("Self") or {}).get("ID"))
        if state.get("BackendState") in ("Running", "Stopped") and has_identity:
            self.run(["set", *settings], privileged=True)
            self.run(["up", "--timeout=60s"], privileged=True)
        else:
            try:
                socket.getaddrinfo(self.hostname, self.port, type=socket.SOCK_STREAM)
            except socket.gaierror as error:
                raise RuntimeError(
                    f"Cannot resolve {self.hostname}. Configure the server DNS first."
                ) from error
            invitation = (invitation or getpass.getpass("Invitation: ")).strip()
            if not invitation:
                raise ValueError("An invitation is required for first enrollment")
            with tempfile.TemporaryDirectory(prefix="tknet-") as directory:
                key = Path(directory) / "auth.key"
                key.touch(mode=0o600)
                key.write_text(invitation)
                self.run(
                    [
                        "up",
                        f"--login-server={self.server}",
                        f"--auth-key=file:{key}",
                        f"--hostname={socket.gethostname().split('.')[0]}",
                        *settings,
                        "--timeout=60s",
                    ],
                    privileged=True,
                    secret=invitation,
                )
        state = self.state()
        if state.get("BackendState") != "Running" or not state.get("TailscaleIPs"):
            raise RuntimeError(f"Enrollment is incomplete: {state.get('BackendState', 'Unknown')}")
        if "tag:guest" not in ((state.get("Self") or {}).get("Tags") or []):
            self.run(["down"], privileged=True)
            raise RuntimeError("The enrolled device has no guest role. Ask tkserver to check the invitation.")
        self.check_profile(state)
        self.run([
            "ping", "--c=1", "--until-direct=false", "--timeout=10s", "tkserver"
        ])
        print("Connected. Log in with: ssh tinker@tkmain")
        self.show_status(state)

    def leave(self):
        state = self.state()
        self.check_profile(state)
        self.run(["down"], privileged=True)
        print("Disconnected. Run tknet join to reconnect using the saved identity.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="Override the Headscale endpoint configuration")
    commands = parser.add_subparsers(dest="command", required=True)
    join = commands.add_parser("join", help="Join or reconnect to the TK mesh")
    join.add_argument("invitation", nargs="?", help="One-use guest enrollment key")
    commands.add_parser("status", help="Show connection state and available hosts")
    commands.add_parser("leave", help="Disconnect while retaining the device identity")
    args = parser.parse_args()
    try:
        config = {"server_url": DEFAULT_SERVER_URL}
        config_path = args.config or SYSTEM_CONFIG
        try:
            config = json.loads(config_path.read_text())
        except FileNotFoundError:
            if args.config is not None:
                raise
        client = Client(config)
        if args.command == "join":
            client.join(args.invitation)
        elif args.command == "leave":
            client.leave()
        else:
            state = client.state()
            client.check_profile(state)
            client.show_status(state)
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as error:
        message = str(error)
        if isinstance(error, subprocess.TimeoutExpired):
            message = "Tailscale operation timed out. Run tknet status before retrying."
        print(f"tknet: {message}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ntknet: Interrupted. Run tknet status to inspect the connection.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
