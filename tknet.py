#!/usr/bin/env python3
"""TK mesh: direct IP enrollment over SSH and encrypted Nebula networking."""

import argparse
import base64
import getpass
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

VERSION = "0.3.0"
BIN = Path("/opt/tknet/bin")
CONFIG = Path("/etc/tknet")
STATE = Path.home() / ".local/share/tknet/client"
RUNTIME = Path("/run/tknet-client")
CLIENT_LOG = Path("/var/log/tknet-client.log")
NETWORK = "10.27.0.0/24"
SERVER = "10.27.0.1"
HOSTS = {"tkserver": SERVER, "tkmain": "10.27.0.2"}
ENROLLMENT_SERVER = "166.111.192.92"
ENROLLMENT_PORT = 12002
ENROLLMENT_HOST_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExLLSHxjV/IoCbPG8vMowC0sArXXxFLKEYmMmKCu6rR"
)


def run(args, **kwargs):
    result = subprocess.run([str(a) for a in args], text=True, capture_output=True,
                            timeout=kwargs.pop("timeout", 60), **kwargs)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Command failed")
    return result.stdout


def write(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as f:
        temporary = Path(f.name)
        os.fchmod(f.fileno(), mode)
        f.write(text)
    temporary.replace(path)


def valid_name(name):
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", name):
        raise ValueError("Invalid device name")
    return name


def invitation_key(seed):
    """Serialize a bootstrap identity using the OpenSSH-compatible key format."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as error:
        raise RuntimeError("Install python3-cryptography, or rerun the tknet installer") from error
    private = Ed25519PrivateKey.from_private_bytes(seed)
    private_text = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()).decode("ascii")
    public_text = private.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode("ascii")
    return private_text, public_text


def nebula_config(role, lighthouse=False, config_dir=CONFIG):
    if role not in ("host", "guest"):
        raise ValueError("Invalid role")
    rules = [{"port": "any", "proto": "any", "group": g} for g in ("host", "guest")]
    return {
        "pki": {"ca": str(config_dir / "ca.crt"), "cert": str(config_dir / "node.crt"),
                "key": str(config_dir / "node.key"), "disconnect_invalid": True},
        "static_host_map": {} if lighthouse else {SERVER: ["166.111.192.92:3478"]},
        "lighthouse": {"am_lighthouse": lighthouse, "hosts": [] if lighthouse else [SERVER],
                       "local_allow_list": {"interfaces": {"Meta": False, "docker.*": False,
                                                           "br-.*": False, "tailscale.*": False}}},
        "listen": {"host": "0.0.0.0", "port": 3478 if lighthouse else 0, "so_mark": 2555904},
        "punchy": {"punch": True},
        "relay": {"am_relay": lighthouse, "use_relays": True,
                  "relays": [] if lighthouse else [SERVER]},
        "tun": {"dev": "tknet0", "mtu": 1300},
        "logging": {"level": "info", "format": "json"},
        "firewall": {"inbound": rules if role == "host" else [], "outbound": [rules[0]]},
    }


def service_unit():
    return """[Unit]
Description=TK private mesh
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStartPre=-/usr/sbin/ip -4 rule add pref 8906 fwmark 0x270000 lookup main
ExecStartPre=-/usr/sbin/ip -4 rule add pref 8907 to 10.27.0.0/24 lookup main
ExecStart=/opt/tknet/bin/nebula -config /etc/tknet/nebula.json
ExecReload=/bin/kill -HUP $MAINPID
ExecStopPost=-/usr/sbin/ip -4 rule del pref 8906 fwmark 0x270000 lookup main
ExecStopPost=-/usr/sbin/ip -4 rule del pref 8907 to 10.27.0.0/24 lookup main
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
"""


def write_network_config(bundle, directory):
    if os.geteuid():
        raise RuntimeError("Network installation requires root")
    if str(ipaddress.IPv4Interface(bundle["address"]).network) != NETWORK:
        raise ValueError("Unexpected mesh subnet")
    config = nebula_config(bundle["role"], bundle["name"] == "tkserver", directory)
    for name in ("ca.crt", "node.crt", "node.key"):
        write(directory / name, bundle[name])
    write(directory / "nebula.json", json.dumps(config, indent=2) + "\n")
    run([BIN / "nebula", "-test", "-config", directory / "nebula.json"])


def check_route_rules():
    for rule in json.loads(run(["ip", "-j", "-4", "rule"])):
        priority = rule.get("priority")
        if priority == 8906 and (rule.get("fwmark") != "0x270000" or rule.get("table") != "main"):
            raise RuntimeError("Policy rule 8906 is occupied")
        if priority == 8907 and (rule.get("dst") != NETWORK or rule.get("table") != "main"):
            raise RuntimeError("Policy rule 8907 is occupied")


def install_network(bundle):
    """Install persistent networking for hosts only."""
    if bundle["role"] != "host":
        raise ValueError("Guest clients use up, not a system service")
    write_network_config(bundle, CONFIG)
    check_route_rules()
    write("/etc/systemd/system/tknet.service", service_unit(), 0o644)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "tknet.service"])
    run(["systemctl", "restart", "tknet.service"])


def process_start(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return None if fields[0] == "Z" else fields[19]
    except (FileNotFoundError, ProcessLookupError):
        return None


def client_state():
    try:
        state = json.loads((RUNTIME / "state.json").read_text())
        if process_start(state["pid"]) == state["start"]:
            return state
    except FileNotFoundError:
        pass
    return None


def client_run(bundle):
    """Own a single on-demand Nebula process and clean up its routes on exit."""
    if os.geteuid() or bundle["role"] != "guest":
        raise RuntimeError("Client runtime requires root and guest membership")
    with (RUNTIME / "runtime.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        child = None
        stopping = False
        added = []

        def stop(signum, frame):
            nonlocal stopping
            stopping = True
            if child is not None and child.poll() is None:
                child.terminate()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        rules = [("8906", "fwmark", "0x270000"), ("8907", "to", NETWORK)]
        try:
            if Path("/sys/class/net/tknet0").exists():
                raise RuntimeError("tknet0 is already managed by another process")
            directory = RUNTIME / "config"
            write_network_config(bundle, directory)
            check_route_rules()
            existing = {r.get("priority") for r in json.loads(run(["ip", "-j", "-4", "rule"]))}
            for priority, kind, value in rules:
                if int(priority) not in existing:
                    run(["ip", "-4", "rule", "add", "pref", priority, kind, value, "lookup", "main"])
                    added.append((priority, kind, value))
            if stopping:
                return
            child = subprocess.Popen([str(BIN / "nebula"), "-config", str(directory / "nebula.json")],
                                     stdin=subprocess.DEVNULL)
            # Publish state only after Nebula has created the interface.
            for _ in range(100):
                if child.poll() is not None or stopping:
                    raise RuntimeError("Nebula exited during startup")
                if Path("/sys/class/net/tknet0").exists():
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError("Nebula did not create tknet0")
            write(RUNTIME / "state.json", json.dumps({"pid": os.getpid(),
                  "start": process_start(os.getpid()), "address": bundle["address"]}), 0o644)
            child.wait()
        finally:
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            for priority, kind, value in reversed(added):
                subprocess.run(["ip", "-4", "rule", "del", "pref", priority,
                                kind, value, "lookup", "main"], capture_output=True)
            (RUNTIME / "state.json").unlink(missing_ok=True)
            for name in ("node.key", "node.crt", "ca.crt", "nebula.json"):
                (RUNTIME / "config" / name).unlink(missing_ok=True)


def client_start(bundle):
    if os.geteuid() or bundle["role"] != "guest":
        raise RuntimeError("Client startup requires root and guest membership")
    RUNTIME.mkdir(mode=0o755, exist_ok=True)
    with (RUNTIME / "start.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = client_state()
        if state:
            if state["address"] != bundle["address"]:
                raise RuntimeError("Another identity is connected; disconnect it first")
            print(json.dumps({"started": False}))
            return
        with CLIENT_LOG.open("a") as log:
            child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "client-run"],
                                     stdin=subprocess.PIPE, stdout=log, stderr=log,
                                     text=True, start_new_session=True)
            child.stdin.write(json.dumps(bundle))
            child.stdin.close()
        for _ in range(200):
            state = client_state()
            if state and state["pid"] == child.pid:
                print(json.dumps({"started": True}))
                return
            if child.poll() is not None:
                raise RuntimeError("Client startup failed: " + "\n".join(CLIENT_LOG.read_text().splitlines()[-8:]))
            time.sleep(0.05)
        child.terminate()
        child.wait(timeout=10)
        raise RuntimeError(f"Client startup timed out; inspect {CLIENT_LOG}")


def client_stop():
    if os.geteuid():
        raise RuntimeError("Client shutdown requires root")
    state = client_state()
    if not state:
        return
    os.kill(state["pid"], signal.SIGTERM)
    for _ in range(100):
        if process_start(state["pid"]) != state["start"]:
            return
        time.sleep(0.1)
    raise RuntimeError("Client shutdown timed out")


def install_host(bundle):
    if bundle["role"] != "host":
        raise ValueError("Host setup requires the host role")
    install_network(bundle)
    for name in ("ssh-user-ca.pub", "ssh-host-cert.pub"):
        write(CONFIG / name, bundle[name], 0o644)
    address = str(ipaddress.IPv4Interface(bundle["address"]).ip)
    sshd = f"""Port 22
ListenAddress {address}
HostKey /etc/ssh/ssh_host_ed25519_key
HostCertificate /etc/tknet/ssh-host-cert.pub
PidFile /run/tknet-sshd.pid
AllowUsers tinker
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
TrustedUserCAKeys /etc/tknet/ssh-user-ca.pub
AuthorizedKeysFile none
UsePAM yes
Subsystem sftp internal-sftp
"""
    write(CONFIG / "sshd_config", sshd, 0o644)
    run(["/usr/sbin/sshd", "-t", "-f", CONFIG / "sshd_config"])
    write("/etc/systemd/system/tknet-sshd.service", """[Unit]
Description=TK mesh SSH for tinker
After=tknet.service
Requires=tknet.service
PartOf=tknet.service

[Service]
ExecStartPre=/usr/sbin/sshd -t -f /etc/tknet/sshd_config
ExecStart=/usr/sbin/sshd -D -f /etc/tknet/sshd_config
Restart=on-failure
RestartSec=2

[Install]
WantedBy=tknet.service
""", 0o644)
    # Restrict the recovery listener when reached through the overlay too.
    write("/etc/ssh/sshd_config.d/80-tknet.conf", "Match LocalAddress 10.27.0.0/24\n    AllowUsers tinker\nMatch all\n", 0o644)
    run(["/usr/sbin/sshd", "-t"])
    run(["systemctl", "reload", "ssh"])
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "tknet-sshd.service"])


def invitation_data(value):
    value = value.strip()
    if value.startswith("tk3_"):
        encoded = value[4:]
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded):
            raise ValueError("Invalid invitation code")
        seed = base64.b64decode(encoded + "=", altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(seed).decode("ascii").rstrip("=") != encoded:
            raise ValueError("Invalid invitation code")
        return {"server": ENROLLMENT_SERVER, "port": ENROLLMENT_PORT,
                "host_key": ENROLLMENT_HOST_KEY,
                "key": invitation_key(seed)[0]}
    if not value.startswith("tk2_") and len(value) <= 240 and Path(value).is_file():
        return json.loads(Path(value).read_text())
    if not value.startswith("tk2_"):
        raise ValueError("Expected a tk3 invitation code")
    return json.loads(base64.urlsafe_b64decode(value[4:] + "=" * (-len(value[4:]) % 4)))


def enrollment(invite, state):
    ipaddress.IPv4Address(invite["server"])
    if not isinstance(invite["port"], int) or not 1024 <= invite["port"] <= 65535:
        raise ValueError("Invalid enrollment port")
    if "expires" in invite and invite["expires"] <= time.time():
        raise ValueError("Invitation expired")
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not (state / "node.key").exists():
        run([BIN / "nebula-cert", "keygen", "-out-key", state / "node.key", "-out-pub", state / "node.pub"])
    if not (state / "id_ed25519").exists():
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", state / "id_ed25519"])
    request = {"nebula_public": (state / "node.pub").read_text(),
               "ssh_public": (state / "id_ed25519.pub").read_text()}
    with tempfile.TemporaryDirectory(prefix="tknet-enroll-") as temporary:
        path = Path(temporary)
        write(path / "key", invite["key"])
        write(path / "known_hosts", f"[{invite['server']}]:{invite['port']} {invite['host_key']}\n")
        response = run(["ssh", "-F", "/dev/null", "-T", "-p", str(invite["port"]),
                        "-i", path / "key", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                        "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15",
                        "-o", f"UserKnownHostsFile={path / 'known_hosts'}",
                        f"tinker@{invite['server']}", "enroll"], input=json.dumps(request), timeout=45)
    bundle = json.loads(response)
    if bundle["role"] != "guest":
        raise ValueError("Expected guest membership")
    bundle["node.key"] = (state / "node.key").read_text()
    write(state / "bundle.json", json.dumps(bundle))
    return bundle


def configure_ssh(bundle, state, ssh_dir):
    ssh_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    write(state / "id_ed25519-cert.pub", bundle["ssh-user-cert.pub"], 0o644)
    lines, known = [], []
    for name, address in bundle["hosts"].items():
        valid_name(name)
        ipaddress.IPv4Address(address)
        lines.extend([f"Host {name}", f"    HostName {address}", "    Port 22", "    User tinker",
                      f'    IdentityFile "{state}/id_ed25519"',
                      f'    CertificateFile "{state}/id_ed25519-cert.pub"',
                      f'    UserKnownHostsFile "{state}/known_hosts"', "    StrictHostKeyChecking yes",
                      "    IdentitiesOnly yes", ""])
        known.append(f"@cert-authority {address} {bundle['ssh-host-ca.pub'].strip()}")
    write(state / "known_hosts", "\n".join(known) + "\n", 0o644)
    write(ssh_dir / "tknet.conf", "\n".join(lines), 0o600)
    config = ssh_dir / "config"
    old = config.read_text() if config.exists() else ""
    include = 'Include "' + str(ssh_dir / "tknet.conf") + '"\n'
    if include not in old:
        if old and not (ssh_dir / "config.before-tknet").exists():
            write(ssh_dir / "config.before-tknet", old)
        write(config, include + old)


def privileged(command, bundle=None):
    ready = subprocess.run(["sudo", "-n", "true"], capture_output=True)
    if ready.returncode:
        subprocess.run(["sudo", "-v"], check=True)
    return run(["sudo", "-n", sys.executable, Path(__file__).resolve(), command],
               input=json.dumps(bundle) if bundle is not None else None)


def up(value=None):
    if not (BIN / "nebula").is_file():
        raise RuntimeError("Run the tknet installer to install Nebula first")
    if (STATE / "bundle.json").exists() and not value:
        bundle = json.loads((STATE / "bundle.json").read_text())
    else:
        value = value or getpass.getpass("Invitation: ")
        bundle = enrollment(invitation_data(value), STATE)
    started = json.loads(privileged("client-start", bundle))["started"]
    try:
        for attempt in range(15):
            ping = subprocess.run(["ping", "-n", "-c", "1", "-W", "1", SERVER], capture_output=True)
            if ping.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("tkserver is unreachable")
        configure_ssh(bundle, STATE, Path.home() / ".ssh")
    except BaseException:
        if started:
            privileged("client-stop")
        raise
    print("Connected. Log in with: ssh tinker@tkmain")


def down():
    privileged("client-stop")
    conf = Path.home() / ".ssh/tknet.conf"
    if conf.exists():
        write(conf, "# Disconnected; original SSH configuration remains active.\n")
    print("Disconnected. Run tknet up to reconnect.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    commands = parser.add_subparsers(dest="command", required=True,
                                    metavar="{up,down,status,invite}")
    commands.add_parser("up", help="Connect on demand").add_argument("invitation", nargs="?")
    commands.add_parser("down", help="Stop this connection")
    commands.add_parser("status", help="Show the current connection")
    invite = commands.add_parser("invite", help="Approve a guest on tkserver")
    invite.add_argument("name")
    commands.add_parser("install-network")
    commands.add_parser("install-host")
    for command in ("client-start", "client-run", "client-stop"):
        commands.add_parser(command)
    args = parser.parse_args()
    try:
        if args.command == "up":
            up(args.invitation)
        elif args.command == "invite":
            result = subprocess.run([sys.executable, "/opt/tknet/lib/admin.py", "invite", args.name])
            return result.returncode
        elif args.command.startswith("install-"):
            bundle = json.loads(sys.stdin.read(131072))
            (install_host if args.command == "install-host" else install_network)(bundle)
        elif args.command == "down":
            down()
        elif args.command == "client-stop":
            client_stop()
        elif args.command in ("client-start", "client-run"):
            bundle = json.loads(sys.stdin.read(131072))
            (client_start if args.command == "client-start" else client_run)(bundle)
        else:
            state = client_state()
            print(f"Connected: {state['address']} (PID {state['pid']})" if state else "Client disconnected")
            subprocess.run(["ip", "-br", "address", "show", "tknet0"], check=False)
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"tknet: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
