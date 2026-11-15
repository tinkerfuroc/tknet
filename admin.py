#!/usr/bin/python3 -Es
"""TK admission authority. Run as tinker on tkserver."""

import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import secrets
import sys
import subprocess
from concurrent.futures import ThreadPoolExecutor
import tempfile
import time

from tknet import BIN, ENROLLMENT_HOST_KEY, HOSTS, certificate_info, invitation_key, run, valid_name, write

ADMIN = Path.home() / ".local/share/tknet/admin"
SERVER_HOST_KEY_FILE = Path("/etc/ssh/ssh_host_ed25519_key.pub")
DELIVERY_TIMEOUT = 45


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
        bundle["refresh_token"] = "host-" + name
        write(ADMIN / "hosts" / (name + "-request.json"), json.dumps(request))
        write(ADMIN / "hosts" / (name + ".json"), json.dumps(bundle))
        remember_certificate(name, bundle)
        authorize_refresh(bundle["refresh_token"], request["ssh_public"])
        return bundle


def invite(name):
    valid_name(name)
    if name in HOSTS:
        raise ValueError("This name is reserved for a host")
    if " ".join(SERVER_HOST_KEY_FILE.read_text().split()[:2]) != ENROLLMENT_HOST_KEY:
        raise ValueError("Server SSH identity differs from the client configuration")
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
        seed = secrets.token_bytes(32)
        code = "tk3_" + base64.urlsafe_b64encode(seed).decode("ascii").rstrip("=")
        key = invitation_key(seed)[1]
        token = secrets.token_hex(16)
        directory = invitations / token
        directory.mkdir(mode=0o700)
        expires = int(time.time()) + 86400
        write(directory / "record.json", json.dumps({"name": name, "address": address, "expires": expires}))
        authority = Path(__file__).resolve()
        expiry = time.strftime("%Y%m%d%H%M%S", time.localtime(expires))
        authorized = Path.home() / ".ssh/authorized_keys"
        previous = authorized.read_text() if authorized.exists() else ""
        line = f'restrict,expiry-time="{expiry}",command="/usr/bin/python3 -Es {authority} enroll {token}" {key}\n'
        write(authorized, previous.rstrip("\n") + "\n" + line)
        return code


def enroll(token, request):
    with (ADMIN / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return enroll_locked(token, request)


def enroll_locked(token, request):
    if len(token) != 32 or any(c not in "0123456789abcdef" for c in token):
        raise ValueError("Invalid invitation")
    directory = ADMIN / "invitations" / token
    with (directory / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        record = json.loads((directory / "record.json").read_text())
        if record.get("revoked"):
            raise ValueError("Device revoked")
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
        response["refresh_token"] = token
        write(directory / "response.json", json.dumps(response))
        remember_certificate(record["name"], response)
        authorize_refresh(token, request["ssh_public"])
        return response


def remember_certificate(name, bundle):
    path = ADMIN / "history" / (name + ".json")
    history = json.loads(path.read_text()) if path.exists() else []
    fingerprint = certificate_info(bundle["node.crt"])["fingerprint"]
    if fingerprint not in history:
        history.append(fingerprint)
    write(path, json.dumps(history))


def authorize_refresh(token, public_key):
    authority = Path(__file__).resolve()
    line = f'restrict,command="/usr/bin/python3 -Es {authority} refresh {token}" {public_key.strip()}\n'
    authorized = Path.home() / ".ssh/authorized_keys"
    previous = authorized.read_text() if authorized.exists() else ""
    if line not in previous:
        write(authorized, previous.rstrip("\n") + "\n" + line)


def policy_snapshot():
    path = ADMIN / "policy.json"
    return json.loads(path.read_text()) if path.exists() else {"version": 0, "fingerprints": [], "ssh_keys": [], "revoked_names": []}


def member_files(name):
    valid_name(name)
    if name in HOSTS:
        bundle = ADMIN / "hosts" / (name + ".json")
        request = ADMIN / "hosts" / (name + "-request.json")
        if not bundle.exists() or not request.exists():
            raise ValueError("Host admission record is missing")
        return bundle, request, None
    for path in (ADMIN / "invitations").glob("*/record.json"):
        if json.loads(path.read_text())["name"] == name:
            return path.parent / "response.json", path.parent / "request.json", path
    raise ValueError("Unknown device")


def refresh(token):
    if token.startswith("host-"):
        name = valid_name(token[5:])
        response, _, _ = member_files(name)
    elif len(token) == 32 and all(c in "0123456789abcdef" for c in token):
        record = json.loads((ADMIN / "invitations" / token / "record.json").read_text())
        name = record["name"]
        response = ADMIN / "invitations" / token / "response.json"
        if record.get("revoked"):
            raise ValueError("Device revoked")
    else:
        raise ValueError("Invalid refresh identity")
    policy = policy_snapshot()
    if name in policy["revoked_names"]:
        raise ValueError("Device revoked")
    bundle = json.loads(response.read_text())
    bundle["policy"] = policy
    return bundle


def delivery_status(name, expected):
    try:
        path = "/opt/tknet/public/sync.json"
        if name == "tkserver":
            acknowledgement = json.loads(Path(path).read_text())
        else:
            acknowledgement = json.loads(run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3",
                                               name, "cat", path], timeout=5))
        if acknowledgement.get("name") == name and all(acknowledgement.get(k) == v for k, v in expected.items()):
            return "applied"
        return "pending: waiting for the host sync service"
    except (RuntimeError, ValueError, subprocess.SubprocessError, OSError) as error:
        return "pending: " + str(error)


def wait_for_hosts(expected):
    deadline = time.monotonic() + DELIVERY_TIMEOUT
    results = {name: "pending" for name in expected}
    while results:
        pending = [name for name, state in results.items() if state != "applied"]
        with ThreadPoolExecutor(max_workers=max(1, len(pending))) as executor:
            replies = executor.map(lambda name: delivery_status(name, expected[name]), pending)
            results.update(zip(pending, replies))
        if all(value == "applied" for value in results.values()) or time.monotonic() >= deadline:
            break
        time.sleep(1)
    return results


def synchronize_policy(policy):
    results = wait_for_hosts({name: {"policy_version": policy["version"]}
                             for name in HOSTS if name not in policy["revoked_names"]})
    write(ADMIN / "policy-delivery.json", json.dumps(results))
    return results


def revoke(name):
    if name == "tkserver":
        raise ValueError("The admission authority cannot revoke itself")
    with (ADMIN / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        bundle_path, request_path, record_path = member_files(name)
        policy = policy_snapshot()
        if name not in policy["revoked_names"]:
            if bundle_path.exists():
                bundle = json.loads(bundle_path.read_text())
                remember_certificate(name, bundle)
                history = json.loads((ADMIN / "history" / (name + ".json")).read_text())
                policy["fingerprints"] = sorted(set(policy["fingerprints"] + history))
                key = " ".join(json.loads(request_path.read_text())["ssh_public"].split()[:2])
                policy["ssh_keys"] = sorted(set(policy["ssh_keys"] + [key]))
            policy["revoked_names"].append(name)
            policy["version"] += 1
            write(ADMIN / "policy.json", json.dumps(policy))
        if record_path:
            with (record_path.parent / "lock").open("a") as member_lock:
                fcntl.flock(member_lock, fcntl.LOCK_EX)
                record = json.loads(record_path.read_text())
                record["revoked"] = True
                write(record_path, json.dumps(record))
        return synchronize_policy(policy)


def renew(name):
    with (ADMIN / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if name in policy_snapshot()["revoked_names"]:
            raise ValueError("Revoked devices cannot be renewed")
        response_path, request_path, record_path = member_files(name)
        if not response_path.exists():
            raise ValueError("Device has not enrolled")
        request = json.loads(request_path.read_text())
        old = json.loads(response_path.read_text())
        remember_certificate(name, old)
        if name in HOSTS:
            bundle = issue_host(name, request)
        else:
            with tempfile.TemporaryDirectory(dir=ADMIN) as temporary:
                bundle = sign(name, old["address"], "guest", request, Path(temporary))
            bundle["refresh_token"] = record_path.parent.name
            write(response_path, json.dumps(bundle))
            remember_certificate(name, bundle)
        authorize_refresh(bundle["refresh_token"], request["ssh_public"])
    info = certificate_info(bundle["node.crt"])
    result = {"name": name, "expires": info["details"]["notAfter"], "delivery": "client refresh (within 60 seconds while connected, or tknet up)"}
    if name in HOSTS:
        delivery = wait_for_hosts({name: {"certificate_fingerprint": info["fingerprint"]}})[name]
        result["delivery"] = "installed" if delivery == "applied" else delivery
    return result


def list_members():
    """List admission records, not inferred online or certificate-valid status."""
    rows = []
    revoked = policy_snapshot()["revoked_names"]
    for name, address in HOSTS.items():
        issued = ADMIN / "hosts" / (name + ".json")
        rows.append({"name": name, "role": "host", "address": address,
                     "state": "revoked" if name in revoked else ("issued" if issued.is_file() else "configured")})
    for path in sorted((ADMIN / "invitations").glob("*/record.json")):
        record = json.loads(path.read_text())
        if record.get("revoked") or record["name"] in revoked:
            state = "revoked"
        elif (path.parent / "response.json").is_file():
            state = "issued"
        else:
            state = "invitation-expired" if record["expires"] <= time.time() else "invited"
        rows.append({"name": record["name"], "role": "guest",
                     "address": record["address"].split("/")[0], "state": state})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    invite_parser = commands.add_parser("invite")
    invite_parser.add_argument("name")
    commands.add_parser("enroll").add_argument("token")
    commands.add_parser("issue-host").add_argument("name")
    listing = commands.add_parser("list")
    listing.add_argument("--json", action="store_true")
    listing.add_argument("-a", "--all", action="store_true", help="Include revoked devices")
    for name in ("refresh", "revoke", "renew"):
        commands.add_parser(name).add_argument("name")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command == "init":
            initialize()
        elif args.command == "invite":
            print(invite(args.name))
            print("Expires in 24 hours; bound to the first device that redeems it.", file=sys.stderr)
        elif args.command == "list":
            rows = list_members()
            if not args.all:
                rows = [row for row in rows if row["state"] != "revoked"]
            if args.json:
                print(json.dumps(rows))
            else:
                print(f"{'NAME':<30} {'ROLE':<7} {'ADDRESS':<16} ADMISSION")
                for row in rows:
                    print(f"{row['name']:<30} {row['role']:<7} {row['address']:<16} {row['state']}")
        elif args.command == "refresh":
            print(json.dumps(refresh(args.name)))
        elif args.command == "revoke":
            results = revoke(args.name)
            for host, result in results.items():
                print(f"{host}: {result}")
            print("Connected guests refresh policy within 60 seconds while the authority is reachable.")
            return 1 if any(result != "applied" for result in results.values()) else 0
        elif args.command == "renew":
            result = renew(args.name)
            print(json.dumps(result))
            return 1 if result["delivery"].startswith("pending:") else 0
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
