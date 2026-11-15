#!/usr/bin/env python3
"""TK admission authority. Run as tinker on tkserver."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time

from tknet import BIN, HOSTS, run, valid_name, write

ADMIN = Path.home() / ".local/share/tknet/admin"


def initialize():
    ADMIN.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not (ADMIN / "ca.key").exists():
        run([BIN / "nebula-cert", "ca", "-name", "TK Mesh", "-duration", "43800h",
             "-networks", "10.27.0.0/24", "-out-key", ADMIN / "ca.key", "-out-crt", ADMIN / "ca.crt"])
    for kind in ("user", "host"):
        key = ADMIN / f"ssh-{kind}-ca"
        if not key.exists():
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key])


def sign(name, address, role, request, directory):
    valid_name(name)
    if role not in ("guest", "host"):
        raise ValueError("Invalid role")
    write(directory / "node.pub", request["nebula_public"])
    write(directory / "ssh.pub", request["ssh_public"])
    if not request["ssh_public"].startswith("ssh-ed25519 ") or "\n" in request["ssh_public"].strip():
        raise ValueError("Expected one Ed25519 public key")
    run([BIN / "nebula-cert", "sign", "-ca-crt", ADMIN / "ca.crt", "-ca-key", ADMIN / "ca.key",
         "-name", name, "-networks", address, "-groups", role, "-duration", "8760h",
         "-in-pub", directory / "node.pub", "-out-crt", directory / "node.crt"])
    run(["ssh-keygen", "-q", "-s", ADMIN / "ssh-user-ca", "-I", name, "-n", "tinker",
         "-V", "-5m:+52w", directory / "ssh.pub"])
    return {"name": name, "address": address, "role": role, "hosts": HOSTS,
            "ca.crt": (ADMIN / "ca.crt").read_text(), "node.crt": (directory / "node.crt").read_text(),
            "ssh-user-cert.pub": (directory / "ssh-cert.pub").read_text(),
            "ssh-user-ca.pub": (ADMIN / "ssh-user-ca.pub").read_text(),
            "ssh-host-ca.pub": (ADMIN / "ssh-host-ca.pub").read_text()}


def issue_host(name, request):
    if name not in HOSTS:
        raise ValueError("Unknown host")
    with tempfile.TemporaryDirectory(dir=ADMIN) as temp:
        directory = Path(temp)
        bundle = sign(name, HOSTS[name] + "/24", "host", request, directory)
        write(directory / "host.pub", request["ssh_host_public"])
        run(["ssh-keygen", "-q", "-s", ADMIN / "ssh-host-ca", "-I", name, "-h", "-n",
             f"{name},{HOSTS[name]}", "-V", "-5m:+52w", directory / "host.pub"])
        bundle["ssh-host-cert.pub"] = (directory / "host-cert.pub").read_text()
        return bundle


def invite(name, output):
    valid_name(name)
    if name in HOSTS:
        raise ValueError("This name is reserved for a host")
    invitations = ADMIN / "invitations"
    invitations.mkdir(exist_ok=True, mode=0o700)
    with (ADMIN / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        existing = [json.loads(p.read_text()) for p in invitations.glob("*/record.json")]
        if any(r["name"] == name for r in existing):
            raise ValueError("Device name already reserved")
        used = {r["address"] for r in existing}
        address = next((f"10.27.0.{i}/24" for i in range(100, 250) if f"10.27.0.{i}/24" not in used), None)
        if not address:
            raise ValueError("Guest address pool exhausted")
        token = secrets.token_hex(16)
        directory = invitations / token
        directory.mkdir(mode=0o700)
        expires = int(time.time()) + 86400
        write(directory / "record.json", json.dumps({"name": name, "address": address, "expires": expires}))
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", directory / "bootstrap"])
        authority = Path(__file__).resolve()
        expiry = time.strftime("%Y%m%d%H%M%S", time.localtime(expires))
        key = (directory / "bootstrap.pub").read_text().strip()
        authorized = Path.home() / ".ssh/authorized_keys"
        previous = authorized.read_text() if authorized.exists() else ""
        line = f'restrict,expiry-time="{expiry}",command="/usr/bin/python3 {authority} enroll {token}" {key}\n'
        write(authorized, previous.rstrip("\n") + "\n" + line)
        data = {"server": "166.111.192.92", "port": 12002, "expires": expires,
                "key": (directory / "bootstrap").read_text(),
                "host_key": Path("/etc/ssh/ssh_host_ed25519_key.pub").read_text().strip()}
        write(output, json.dumps(data))
        (directory / "bootstrap").unlink()
        print(f"Invitation written to {output}; expires in 24 hours.")


def enroll(token, request):
    if len(token) != 32 or any(c not in "0123456789abcdef" for c in token):
        raise ValueError("Invalid invitation")
    directory = ADMIN / "invitations" / token
    with (directory / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        record = json.loads((directory / "record.json").read_text())
        if record["expires"] < time.time():
            raise ValueError("Invitation expired")
        saved = directory / "request.json"
        # Bind to the first public keys; allow retries after a dropped response.
        if saved.exists() and json.loads(saved.read_text()) != request:
            raise ValueError("Invitation already used by another device")
        if (directory / "response.json").exists():
            return json.loads((directory / "response.json").read_text())
        write(saved, json.dumps(request))
        with tempfile.TemporaryDirectory(dir=directory) as temp:
            response = sign(record["name"], record["address"], "guest", request, Path(temp))
        write(directory / "response.json", json.dumps(response))
        return response


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    invite_parser = commands.add_parser("invite")
    invite_parser.add_argument("name")
    invite_parser.add_argument("--output", type=Path, required=True)
    commands.add_parser("enroll").add_argument("token")
    commands.add_parser("issue-host").add_argument("name")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command == "init":
            initialize()
        elif args.command == "invite":
            invite(args.name, args.output)
        else:
            request = json.loads(sys.stdin.read(16384))
            response = enroll(args.token, request) if args.command == "enroll" else issue_host(args.name, request)
            print(json.dumps(response))
        return 0
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print(f"tknet-admin: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
