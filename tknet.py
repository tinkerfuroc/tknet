#!/usr/bin/python3 -Es
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
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

VERSION = "0.3.3"
SYSTEM_PYTHON = ["/usr/bin/python3", "-Es"]
TUN_NAME = "tktun"
BIN = Path("/opt/tknet/bin")
CONFIG = Path("/etc/tknet")
STATE = Path.home() / ".local/share/tknet/client"
RUNTIME = Path("/run/tknet-client")
CLIENT_LOG = Path("/var/log/tknet-client.log")
NETWORK = "10.27.0.0/24"
SERVER = "10.27.0.1"
HOSTS = {"tkserver": SERVER, "tkmain": "10.27.0.2", "tkbox": "10.27.0.3", "tkmini": "10.27.0.4"}
HOSTS_FILE = Path("/etc/hosts")
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
    """Use system OpenSSL for Ed25519; encode the documented OpenSSH envelope."""
    if len(seed) != 32:
        raise ValueError("An Ed25519 seed must contain 32 bytes")
    # RFC 8410 PKCS#8 private key and SubjectPublicKeyInfo encodings.
    der = bytes.fromhex("302e020100300506032b657004220420") + seed
    result = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                            input=der, capture_output=True, timeout=10)
    prefix = bytes.fromhex("302a300506032b6570032100")
    if result.returncode or len(result.stdout) != 44 or not result.stdout.startswith(prefix):
        raise RuntimeError("System OpenSSL could not derive an Ed25519 public key")
    public = result.stdout[len(prefix):]

    def field(value):
        return struct.pack(">I", len(value)) + value

    # OpenSSH PROTOCOL.key: an unencrypted key, repeated checkint and 8-byte padding.
    public_blob = field(b"ssh-ed25519") + field(public)
    check = os.urandom(4)
    private_blob = check * 2 + public_blob + field(seed + public) + field(b"")
    private_blob += bytes(range(1, (-len(private_blob) % 8) + 1))
    envelope = (b"openssh-key-v1\0" + field(b"none") + field(b"none") + field(b"")
                + struct.pack(">I", 1) + field(public_blob) + field(private_blob))
    encoded = base64.b64encode(envelope).decode("ascii")
    lines = "\n".join(encoded[i:i + 70] for i in range(0, len(encoded), 70))
    return (f"-----BEGIN OPENSSH PRIVATE KEY-----\n{lines}\n-----END OPENSSH PRIVATE KEY-----\n",
            "ssh-ed25519 " + base64.b64encode(public_blob).decode("ascii"))


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
        "tun": {"dev": TUN_NAME, "mtu": 1300},
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
ExecStartPre=/usr/bin/python3 -Es /opt/tknet/lib/tknet.py routes-up
ExecStart=/opt/tknet/bin/nebula -config /etc/tknet/nebula.json
ExecReload=/bin/kill -HUP $MAINPID
ExecStopPost=/usr/bin/python3 -Es /opt/tknet/lib/tknet.py routes-down
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


def netlink_rules(message_type, payload, flags):
    """Exchange Linux rtnetlink rule messages without the iproute2 executable."""
    results = []
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as sock:
        sock.settimeout(5)
        sock.bind((0, 0))
        header = struct.pack("=IHHII", 16 + len(payload), message_type, flags | 1, 1, sock.getsockname()[0])
        sock.sendto(header + payload, (0, 0))
        while True:
            data, _, received_flags, sender = sock.recvmsg(1024 * 1024)
            if sender[0] != 0:
                continue
            if received_flags & socket.MSG_TRUNC:
                raise RuntimeError("Truncated routing-rule response")
            offset = 0
            while offset + 16 <= len(data):
                size, kind, reply_flags, sequence, _ = struct.unpack_from("=IHHII", data, offset)
                if size < 16 or offset + size > len(data):
                    raise RuntimeError("Invalid routing-rule response")
                body = data[offset + 16:offset + size]
                offset += (size + 3) & ~3
                if sequence != 1:
                    continue
                if reply_flags & 0x10:
                    raise RuntimeError("Routing rules changed while being read; retry")
                if kind in (2, 3):  # NLMSG_ERROR (including ACK) or NLMSG_DONE.
                    error = struct.unpack_from("=i", body)[0] if len(body) >= 4 else 0
                    if error:
                        raise OSError(-error, os.strerror(-error))
                    return results
                if kind == 32:  # RTM_NEWRULE.
                    results.append(body)


def rule_attributes(payload):
    attrs = {}
    offset = 12  # sizeof(struct fib_rule_hdr), linux/fib_rules.h.
    while offset + 4 <= len(payload):
        size, kind = struct.unpack_from("=HH", payload, offset)
        if size < 4 or offset + size > len(payload):
            raise RuntimeError("Invalid routing-rule attribute")
        attrs[kind] = payload[offset + 4:offset + size]
        offset += (size + 3) & ~3
    return attrs


def desired_rules():
    def attribute(kind, value):
        data = struct.pack("=HH", 4 + len(value), kind) + value
        return data + b"\0" * (-len(data) % 4)

    def header(prefix):
        return struct.pack("=BBBBBBBBI", socket.AF_INET, prefix, 0, 0, 254, 0, 0, 1, 0)

    return {
        8906: header(0) + attribute(6, struct.pack("=I", 8906))
              + attribute(10, struct.pack("=I", 0x270000))
              + attribute(16, struct.pack("=I", 0xffffffff)),
        8907: header(24) + attribute(6, struct.pack("=I", 8907))
              + attribute(1, socket.inet_aton("10.27.0.0")),
    }


def list_route_rules():
    return netlink_rules(34, struct.pack("=BBBBBBBBI", socket.AF_INET, 0, 0, 0, 0, 0, 0, 0, 0), 0x300)


def same_rule(actual, expected):
    attrs = rule_attributes(actual)
    # Ignore only non-selecting metadata and the kernel's explicit defaults.
    attrs.pop(21, None)  # FRA_PROTOCOL records the rule's origin.
    for kind, neutral in ((15, 254), (13, 0xffffffff), (14, 0xffffffff)):
        if attrs.get(kind) == struct.pack("=I", neutral):
            attrs.pop(kind)
    if 10 in attrs:
        attrs.setdefault(16, struct.pack("=I", 0xffffffff))
    return actual[:12] == expected[:12] and attrs == rule_attributes(expected)


def check_route_rules():
    desired = desired_rules()
    existing = set()
    for payload in list_route_rules():
        priority = struct.unpack("=I", rule_attributes(payload).get(6, b"\0" * 4))[0]
        if priority in desired:
            if priority in existing or not same_rule(payload, desired[priority]):
                raise RuntimeError(f"Policy rule {priority} is occupied")
            existing.add(priority)
    return existing


def routes_up():
    existing = check_route_rules()
    added = []
    try:
        for priority, payload in desired_rules().items():
            if priority not in existing:
                netlink_rules(32, payload, 0x604)  # ACK | CREATE | EXCL.
                added.append(priority)
        return added
    except BaseException:
        routes_down(added)
        raise


def routes_down(priorities=None):
    desired = desired_rules()
    selected = set(desired if priorities is None else priorities)
    if not selected:
        return
    for payload in list_route_rules():
        priority = struct.unpack("=I", rule_attributes(payload).get(6, b"\0" * 4))[0]
        if priority in selected and same_rule(payload, desired[priority]):
            netlink_rules(33, payload, 4)  # RTM_DELRULE | ACK.


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
        names_owned = False

        def stop(signum, frame):
            nonlocal stopping
            stopping = True
            if child is not None and child.poll() is None:
                child.terminate()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        try:
            if Path(f"/sys/class/net/{TUN_NAME}").exists():
                raise RuntimeError(f"{TUN_NAME} is already managed by another process")
            directory = RUNTIME / "config"
            write_network_config(bundle, directory)
            added = routes_up()
            if stopping:
                return
            child = subprocess.Popen([str(BIN / "nebula"), "-config", str(directory / "nebula.json")],
                                     stdin=subprocess.DEVNULL)
            # Publish state only after Nebula has created the interface.
            for _ in range(100):
                if child.poll() is not None or stopping:
                    raise RuntimeError("Nebula exited during startup")
                if Path(f"/sys/class/net/{TUN_NAME}").exists():
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError(f"Nebula did not create {TUN_NAME}")
            configure_hostnames(True)
            names_owned = True
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
            routes_down(added)
            if names_owned:
                configure_hostnames(False)
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
            configure_hostnames(True)
            print(json.dumps({"started": False}))
            return
        with CLIENT_LOG.open("a") as log:
            child = subprocess.Popen([*SYSTEM_PYTHON, str(Path(__file__).resolve()), "client-run"],
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
        configure_hostnames(False)
        return
    os.kill(state["pid"], signal.SIGTERM)
    for _ in range(100):
        if process_start(state["pid"]) != state["start"]:
            configure_hostnames(False)
            return
        time.sleep(0.1)
    raise RuntimeError("Client shutdown timed out")


def install_host(bundle):
    if bundle["role"] != "host":
        raise ValueError("Host setup requires the host role")
    install_network(bundle)
    configure_host_firewall()
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


def configure_host_firewall():
    """Let authenticated mesh traffic reach host services when UFW is active."""
    ufw = shutil.which("ufw")
    if ufw and "Status: active" in run([ufw, "status"]):
        run([ufw, "allow", "in", "on", TUN_NAME, "from", NETWORK,
             "comment", "TK authenticated mesh"])


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


def configure_hostnames(enabled):
    """Manage only the TK block, preserving other hosts entries and permissions."""
    begin, end = "# BEGIN TKNET HOSTS\n", "# END TKNET HOSTS\n"
    with HOSTS_FILE.open("r+", encoding="utf-8", newline="") as hosts:
        fcntl.flock(hosts, fcntl.LOCK_EX)
        old = hosts.read()
        base = old
        if begin in base or end in base:
            if base.count(begin) != 1 or base.count(end) != 1:
                raise RuntimeError("Malformed TK hosts block")
            start, stop = base.index(begin), base.index(end)
            if stop < start:
                raise RuntimeError("Malformed TK hosts block")
            base = base[:start] + base[stop + len(end):]
        block = begin + "".join(f"{address}\t{name}\n" for name, address in HOSTS.items()) + end
        updated = block + base if enabled else base
        if updated != old:
            hosts.seek(0)
            hosts.write(updated)
            hosts.truncate()
            hosts.flush()
            os.fsync(hosts.fileno())


def configure_ssh(bundle, state, ssh_dir):
    ssh_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    write(state / "id_ed25519-cert.pub", bundle["ssh-user-cert.pub"], 0o644)
    lines, known = [], []
    # Refresh known hosts after a client upgrade without reissuing its identity.
    for name, address in {**bundle["hosts"], **HOSTS}.items():
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
    return run(["sudo", "-n", *SYSTEM_PYTHON, Path(__file__).resolve(), command],
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
    print("Connected. Log in with: ssh tkmain")


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
    for command in ("client-start", "client-run", "client-stop", "routes-up", "routes-down", "names-up"):
        commands.add_parser(command)
    args = parser.parse_args()
    try:
        if args.command == "up":
            up(args.invitation)
        elif args.command == "invite":
            result = subprocess.run([*SYSTEM_PYTHON, "/opt/tknet/lib/admin.py", "invite", args.name])
            return result.returncode
        elif args.command.startswith("install-"):
            bundle = json.loads(sys.stdin.read(131072))
            (install_host if args.command == "install-host" else install_network)(bundle)
        elif args.command == "down":
            down()
        elif args.command == "client-stop":
            client_stop()
        elif args.command in ("routes-up", "routes-down"):
            (routes_up if args.command == "routes-up" else routes_down)()
            configure_hostnames(args.command == "routes-up")
        elif args.command == "names-up":
            configure_hostnames(True)
        elif args.command in ("client-start", "client-run"):
            bundle = json.loads(sys.stdin.read(131072))
            (client_start if args.command == "client-start" else client_run)(bundle)
        else:
            state = client_state()
            print(f"Connected: {state['address']} (PID {state['pid']})" if state else "Client disconnected")
            if Path(f"/sys/class/net/{TUN_NAME}").exists():
                print(f"Interface: {TUN_NAME}")
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"tknet: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
