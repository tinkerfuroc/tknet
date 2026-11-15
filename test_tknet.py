"""Offline checks using real Nebula and OpenSSH certificate tools."""

import base64
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import admin
import tknet


class ConfigurationTests(unittest.TestCase):
    def test_guest_cannot_accept_new_connections(self):
        cfg = tknet.nebula_config("guest")
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


if __name__ == "__main__":
    unittest.main()
