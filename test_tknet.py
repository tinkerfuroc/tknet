"""Offline checks using real Nebula and OpenSSH certificate tools."""

import base64
from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

import admin
import tknet


class ConfigurationTests(unittest.TestCase):
    def test_openssl_seed_matches_rfc8032_vector(self):
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        _, public = tknet.invitation_key(seed)
        raw = base64.b64decode(public.split()[1])[-32:]
        self.assertEqual(raw.hex(), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

    def test_guest_cannot_accept_new_connections(self):
        cfg = tknet.nebula_config("guest")
        self.assertEqual(cfg["tun"]["dev"], "tktun")
        self.assertEqual(cfg["firewall"]["inbound"], [])
        self.assertEqual(cfg["firewall"]["outbound"], [{"port": "any", "proto": "any", "group": "host"}])

    def test_hosts_accept_both_roles_but_cannot_initiate_to_guests(self):
        cfg = tknet.nebula_config("host")
        self.assertEqual([r["group"] for r in cfg["firewall"]["inbound"]], ["host", "guest"])
        self.assertEqual([r["group"] for r in cfg["firewall"]["outbound"]], ["host"])

    def test_no_dns_or_https_bootstrap(self):
        cfg = tknet.nebula_config("guest")
        self.assertEqual(cfg["static_host_map"], {"10.27.0.1": ["166.111.192.92:3478"]})
        self.assertEqual(cfg["listen"]["so_mark"], 0x270000)
        self.assertEqual(cfg["relay"]["relays"], ["10.27.0.1"])
        server = tknet.nebula_config("host", True)
        self.assertTrue(server["lighthouse"]["am_lighthouse"])
        self.assertTrue(server["relay"]["am_relay"])
        self.assertEqual(server["relay"]["relays"], [])

    def test_encoded_invitation(self):
        data = {"server": "166.111.192.92", "key": "a" * 1000}
        encoded = "tk2_" + base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
        self.assertEqual(tknet.invitation_data(encoded), data)

    def test_invalid_codes_fail_before_network_access(self):
        for value in ("tk3_", "tk3_" + "a" * 63, "tk3_" + "!" * 64, "a" * 1024):
            with self.subTest(value_length=len(value)), self.assertRaises(ValueError):
                tknet.invitation_data(value)

    def test_enrollment_reuses_existing_private_keys(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d)
            originals = {"node.key": "network-key", "id_ed25519": "ssh-key",
                         "node.pub": "network-public", "id_ed25519.pub": "ssh-public"}
            for name, text in originals.items():
                tknet.write(state / name, text)
            invite = {"server": tknet.ENROLLMENT_SERVER, "port": tknet.ENROLLMENT_PORT,
                      "host_key": tknet.ENROLLMENT_HOST_KEY, "key": "bootstrap-key"}
            with patch("tknet.run", return_value=json.dumps({"role": "guest"})) as run:
                tknet.enrollment(invite, state)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][0], "ssh")
            for name, text in originals.items():
                self.assertEqual((state / name).read_text(), text)

    def test_ssh_include_preserves_existing_configuration(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            ssh = root / "ssh"
            ssh.mkdir()
            original = "Host old\n    HostName 1.2.3.4\n"
            (ssh / "config").write_text(original)
            bundle = {"hosts": tknet.HOSTS, "ssh-user-cert.pub": "test", "ssh-host-ca.pub": "ssh-ed25519 test"}
            for _ in range(2):
                tknet.configure_ssh(bundle, root / "state", ssh)
            self.assertEqual((ssh / "config").read_text().count("Include "), 1)
            self.assertIn(original, (ssh / "config").read_text())
            self.assertEqual((ssh / "config.before-tknet").read_text(), original)
            resolved = tknet.run(["ssh", "-G", "-F", ssh / "config", "tkmain"])
            self.assertIn("hostname 10.27.0.2\n", resolved)
            self.assertIn("port 22\n", resolved)


class ClientLifecycleTests(unittest.TestCase):
    def test_stale_pid_is_not_signalled(self):
        with tempfile.TemporaryDirectory() as d, patch.object(tknet, "RUNTIME", Path(d)):
            tknet.write(Path(d) / "state.json", json.dumps({"pid": 999999, "start": "old"}))
            with patch("tknet.process_start", return_value="new"), patch("tknet.os.geteuid", return_value=0), patch("tknet.os.kill") as kill:
                tknet.client_stop()
            kill.assert_not_called()

    def test_repeat_start_does_not_spawn_a_second_process(self):
        with tempfile.TemporaryDirectory() as d, patch.object(tknet, "RUNTIME", Path(d)):
            with patch("tknet.client_state", return_value={"address": "10.27.0.100/24"}), patch("tknet.os.geteuid", return_value=0), patch("tknet.subprocess.Popen") as popen, patch("builtins.print"):
                tknet.client_start({"role": "guest", "address": "10.27.0.100/24"})
            popen.assert_not_called()

    def test_failed_up_cleans_up_only_a_new_connection(self):
        for started in (True, False):
            with self.subTest(started=started), tempfile.TemporaryDirectory() as d, ExitStack() as stack:
                state = Path(d)
                tknet.write(state / "bundle.json", json.dumps({"role": "guest"}))
                stack.enter_context(patch.object(tknet, "STATE", state))
                privileged = stack.enter_context(patch("tknet.privileged", return_value=json.dumps({"started": started})))
                stack.enter_context(patch("tknet.subprocess.run", return_value=subprocess.CompletedProcess([], 1)))
                stack.enter_context(patch("tknet.time.sleep"))
                with self.assertRaisesRegex(RuntimeError, "unreachable"):
                    tknet.up()
                commands = [call.args[0] for call in privileged.call_args_list]
                self.assertEqual(commands, ["client-start", "client-stop"] if started else ["client-start"])

    def test_guest_cannot_install_a_system_service(self):
        with patch("tknet.run") as run:
            with self.assertRaisesRegex(ValueError, "Guest clients"):
                tknet.install_network({"role": "guest"})
            run.assert_not_called()


class RouteTests(unittest.TestCase):
    def test_same_priority_with_extra_selector_is_rejected(self):
        desired = tknet.desired_rules()[8906]
        extra = struct.pack("=HH4s", 8, 2, bytes([10, 0, 0, 1]))
        self.assertFalse(tknet.same_rule(desired + extra, desired))
        with patch("tknet.list_route_rules", return_value=[desired + extra]):
            with self.assertRaisesRegex(RuntimeError, "occupied"):
                tknet.check_route_rules()

    def test_partial_add_failure_rolls_back(self):
        calls = []

        def exchange(kind, payload, flags):
            calls.append(kind)
            if len(calls) == 2:
                raise OSError("simulated failure")
            return []

        with patch("tknet.check_route_rules", return_value=set()), patch("tknet.netlink_rules", side_effect=exchange), patch("tknet.list_route_rules", return_value=[tknet.desired_rules()[8906]]):
            with self.assertRaisesRegex(OSError, "simulated failure"):
                tknet.routes_up()
        self.assertEqual(calls, [32, 32, 33])


@unittest.skipUnless((tknet.BIN / "nebula-cert").exists(), "Nebula certificate tool is required")
class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patch = patch.object(admin, "ADMIN", self.root / "authority")
        self.patch.start()
        admin.initialize()
        tknet.run([tknet.BIN / "nebula-cert", "keygen", "-out-key", self.root / "node.key", "-out-pub", self.root / "node.pub"])
        tknet.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.root / "ssh"])
        self.request = {"nebula_public": (self.root / "node.pub").read_text(), "ssh_public": (self.root / "ssh.pub").read_text()}
        self.token = "a" * 32
        self.directory = admin.ADMIN / "invitations" / self.token
        self.directory.mkdir(parents=True)
        tknet.write(self.directory / "record.json", json.dumps({"name": "test-guest", "address": "10.27.0.100/24", "expires": time.time() + 60}))

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_enrollment_and_retry_use_same_certificates(self):
        first = admin.enroll(self.token, self.request)
        self.assertEqual(first, admin.enroll(self.token, self.request))
        self.assertEqual(first["role"], "guest")
        self.assertNotIn("node.key", first)
        tknet.write(self.root / "user-cert.pub", first["ssh-user-cert.pub"])
        info = tknet.run(["ssh-keygen", "-L", "-f", self.root / "user-cert.pub"])
        self.assertIn("tinker", info)
        tknet.write(self.root / "ca.crt", first["ca.crt"])
        tknet.write(self.root / "node.crt", first["node.crt"])
        tknet.run([tknet.BIN / "nebula-cert", "verify", "-ca", self.root / "ca.crt", "-crt", self.root / "node.crt"])

    def test_used_invitation_cannot_enroll_different_keys(self):
        admin.enroll(self.token, self.request)
        with self.assertRaisesRegex(ValueError, "already used"):
            admin.enroll(self.token, {**self.request, "ssh_public": "ssh-ed25519 other"})

    def test_expired_invitation_cannot_issue_membership(self):
        record = json.loads((self.directory / "record.json").read_text())
        record["expires"] = time.time() - 1
        tknet.write(self.directory / "record.json", json.dumps(record))
        with self.assertRaisesRegex(ValueError, "expired"):
            admin.enroll(self.token, self.request)

    def test_code_matches_restricted_ssh_key_without_invitation_file(self):
        host_key = self.root / "host.pub"
        host_key.write_text(tknet.ENROLLMENT_HOST_KEY + " test-host\n")
        ssh = self.root / ".ssh"
        ssh.mkdir()
        original = "ssh-ed25519 existing-key\n"
        (ssh / "authorized_keys").write_text(original)
        with patch.object(admin, "SERVER_HOST_KEY_FILE", host_key), patch("admin.Path.home", return_value=self.root):
            code = admin.invite("code-guest")
        self.assertEqual(len(code), 47)
        invite = tknet.invitation_data(code)
        tknet.write(self.root / "reconstructed.pem", invite["key"])
        public_key = tknet.run(["ssh-keygen", "-y", "-f", self.root / "reconstructed.pem"]).strip()
        authorized = (ssh / "authorized_keys").read_text()
        self.assertTrue(authorized.startswith(original))
        self.assertIn(public_key, authorized)
        self.assertIn("restrict,expiry-time=", authorized)
        self.assertIn("admin.py enroll ", authorized)
        self.assertEqual(invite["server"], tknet.ENROLLMENT_SERVER)
        self.assertEqual(invite["host_key"], tknet.ENROLLMENT_HOST_KEY)
        self.assertFalse(list(admin.ADMIN.glob("bootstrap-*")))
        self.assertFalse(list(self.root.rglob("*.tknet")))
        records = [json.loads(p.read_text()) for p in admin.ADMIN.glob("invitations/*/record.json")]
        record = next(r for r in records if r["name"] == "code-guest")
        self.assertAlmostEqual(record["expires"] - time.time(), 86400, delta=3)


if __name__ == "__main__":
    unittest.main()
