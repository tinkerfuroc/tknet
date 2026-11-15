"""Offline checks using real Nebula and OpenSSH certificate tools."""

import base64
from contextlib import ExitStack
import json
import io
import os
from pathlib import Path
import subprocess
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

import admin
import tknet


class InstallationRoleTests(unittest.TestCase):
    def test_installer_client_server_and_upgrade_roles(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = root / "opt"
            binaries = prefix / "bin"
            binaries.mkdir(parents=True)
            for name in ("nebula", "nebula-cert"):
                tknet.write(binaries / name, "#!/bin/sh\necho 'Version: 1.12.0'\n", 0o755)
            fakebin = root / "fakebin"
            fakebin.mkdir()
            tknet.write(fakebin / "sudo", '#!/bin/sh\nexec "$@"\n', 0o755)
            fixture = Path(__file__).parent.resolve()
            downloader = "#!/usr/bin/python3\nimport pathlib,shutil,sys\na=sys.argv[1:]\nu=next(x for x in a if x.startswith('https:'))\nname=u.rsplit('/',1)[-1]\nassert name in ('tknet.py','admin.py')\nshutil.copyfile(pathlib.Path(" + repr(str(fixture)) + ")/name,a[a.index('-o')+1])\n"
            tknet.write(fakebin / "curl", downloader, 0o755)
            script = root / "install.sh"
            content = (fixture / "install.sh").read_text().replace("/opt/tknet", str(prefix)).replace("/etc/tknet", str(root / "etc"))
            script.write_text(content)
            environment = {**os.environ, "PATH": str(fakebin) + ":" + os.environ["PATH"], "TKNET_INSTALL_DIR": str(root / "cli")}
            for arguments, role in (([], "client"), (["--server"], "server"), ([], "server"), (["--client"], "client")):
                subprocess.run(["sh", str(script), *arguments], env=environment, capture_output=True, check=True)
                self.assertEqual((prefix / "role").read_text().strip(), role)
                self.assertEqual((prefix / "lib/admin.py").exists(), role == "server")

    def test_client_does_not_offer_or_accept_admin_commands(self):
        with patch("tknet.server_installation", return_value=False):
            help_text = tknet.command_parser([]).format_help()
            self.assertNotIn("invite", help_text)
            self.assertNotIn("install-host", help_text)
            self.assertNotIn("client-run", help_text)
            for command in ("invite", "list", "revoke", "renew"):
                with patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit) as error:
                    tknet.command_parser([command]).parse_args([command])
                self.assertEqual(error.exception.code, 2)

    def test_server_offers_only_implemented_management_commands(self):
        with patch("tknet.server_installation", return_value=True):
            parser = tknet.command_parser([])
            self.assertEqual(parser.parse_args(["invite", "laptop"]).name, "laptop")
            self.assertTrue(parser.parse_args(["list", "--json"]).json)
            self.assertNotIn("client-run", parser.format_help())

    def test_internal_commands_require_root(self):
        with patch("tknet.server_installation", return_value=False):
            with patch("tknet.os.geteuid", return_value=0):
                self.assertEqual(tknet.command_parser(["client-run"]).parse_args(["client-run"]).command, "client-run")
            with patch("tknet.os.geteuid", return_value=1000), patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit):
                tknet.command_parser(["client-run"]).parse_args(["client-run"])

    def test_host_commands_exclude_network_controls_and_payload_submission(self):
        for server in (False, True):
            with patch("tknet.host_installation", return_value=True), patch("tknet.server_installation", return_value=server):
                help_text = tknet.command_parser([]).format_help()
                self.assertNotIn("up", help_text)
                self.assertNotIn("down", help_text)
                for command in ("up", "down", "apply-policy", "install-renewal", "accept-renewal"):
                    with patch("tknet.os.geteuid", return_value=0), patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit):
                        tknet.command_parser([command]).parse_args([command])

    def test_guest_keeps_on_demand_commands(self):
        with patch("tknet.host_installation", return_value=False), patch("tknet.server_installation", return_value=False):
            for command in ("up", "down", "status"):
                self.assertEqual(tknet.command_parser([command]).parse_args([command]).command, command)


class HostSyncTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.public = self.root / "public"
        self.bundle = {"name": "tkmini", "node.crt": "certificate", "ssh-host-cert.pub": "host cert",
                       "ssh-user-cert.pub": "user cert", "policy": {"version": 3, "fingerprints": [], "ssh_keys": []}}
        for name, value in (("member.json", json.dumps(self.bundle)), ("policy.json", json.dumps(self.bundle["policy"])),
                            ("nebula.json", json.dumps({"pki": {"blocklist": []}})),
                            ("node.crt", "certificate"), ("ssh-host-cert.pub", "host cert")):
            tknet.write(self.root / name, value)
        self.stack = ExitStack()
        self.stack.enter_context(patch("tknet.CONFIG", self.root))
        self.stack.enter_context(patch("tknet.PUBLIC_STATE", self.public))
        self.stack.enter_context(patch("tknet.os.geteuid", return_value=0))
        self.fetch = self.stack.enter_context(patch("tknet.fetch_refresh", return_value=self.bundle))
        self.run = self.stack.enter_context(patch("tknet.run"))
        self.apply = self.stack.enter_context(patch("tknet.apply_policy"))
        self.stack.enter_context(patch("tknet.certificate_info", return_value={"fingerprint": "fp"}))

    def tearDown(self):
        self.stack.close()
        self.tmp.cleanup()

    def test_unchanged_refresh_acknowledges_without_service_reload(self):
        tknet.write(self.public / "sync.json", json.dumps({"policy_version": 3, "certificate_fingerprint": "fp"}))
        tknet.host_sync()
        self.fetch.assert_called_once_with(self.bundle, self.root / "identity")
        self.apply.assert_not_called()
        self.run.assert_not_called()
        self.assertEqual(json.loads((self.public / "sync.json").read_text())["policy_version"], 3)

    def test_reload_failure_is_retried_before_acknowledging(self):
        self.run.side_effect = RuntimeError("reload failed")
        with self.assertRaisesRegex(RuntimeError, "reload failed"):
            tknet.host_sync()
        self.assertFalse((self.public / "sync.json").exists())
        self.run.side_effect = None
        tknet.host_sync()
        self.assertTrue((self.public / "sync.json").exists())

    def test_authority_recovers_accidentally_inflated_local_version(self):
        tknet.write(self.root / "policy.json", json.dumps({"version": 999999}))
        tknet.host_sync()
        self.apply.assert_called_once_with(self.bundle["policy"], directory=self.root, reload=False, authoritative=True)

    def test_failed_fetch_keeps_installed_policy_and_has_no_acknowledgement(self):
        self.fetch.side_effect = RuntimeError("authority unavailable")
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            tknet.host_sync()
        self.apply.assert_not_called()
        self.run.assert_not_called()
        self.assertFalse((self.public / "sync.json").exists())

    def test_changed_certificate_installs_once_and_reloads(self):
        self.fetch.return_value = {**self.bundle, "node.crt": "renewed"}
        with patch("tknet.install_renewal") as renewal:
            tknet.host_sync()
        self.assertEqual(renewal.call_args.kwargs, {"reload": False})
        self.assertNotIn("policy", renewal.call_args.args[0])
        self.assertEqual(self.run.call_count, 2)


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
            bundle = {"hosts": {"tkserver": tknet.SERVER, "tkmain": "10.27.0.2"},
                      "ssh-user-cert.pub": "test", "ssh-host-ca.pub": "ssh-ed25519 test"}
            for _ in range(2):
                tknet.configure_ssh(bundle, root / "state", ssh)
            self.assertEqual((ssh / "config").read_text().count("Include "), 1)
            self.assertIn(original, (ssh / "config").read_text())
            self.assertEqual((ssh / "config.before-tknet").read_text(), original)
            resolved = tknet.run(["ssh", "-G", "-F", ssh / "config", "tkmain"])
            self.assertIn("hostname 10.27.0.2\n", resolved)
            self.assertIn("port 22\n", resolved)
            for name, address in tknet.HOSTS.items():
                resolved = tknet.run(["ssh", "-G", "-F", ssh / "config", name])
                self.assertIn(f"hostname {address}\n", resolved)
                self.assertIn("user tinker\n", resolved)


class ClientLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        hosts = Path(temporary.name) / "hosts"
        hosts.write_text("127.0.0.1 localhost\n")
        replacement = patch.object(tknet, "HOSTS_FILE", hosts)
        replacement.start()
        self.addCleanup(replacement.stop)

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


class PolicyTests(unittest.TestCase):
    def test_policy_install_rejects_rollback_and_keeps_cached_revocations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tknet.write(root / "nebula.json", json.dumps({"pki": {}}))
            policy = {"version": 2, "fingerprints": ["a" * 64], "ssh_keys": [], "revoked_names": ["lost-device"]}
            with patch("tknet.os.geteuid", return_value=0), patch("tknet.run"):
                tknet.apply_policy(policy, root, reload=False)
                tknet.apply_policy(policy, root, reload=False)
                with self.assertRaisesRegex(ValueError, "older"):
                    tknet.apply_policy({**policy, "version": 1}, root, reload=False)
                with self.assertRaisesRegex(ValueError, "Conflicting"):
                    tknet.apply_policy({**policy, "fingerprints": []}, root, reload=False)
                with self.assertRaisesRegex(ValueError, "blocklist"):
                    tknet.apply_policy({**policy, "fingerprints": ["invalid"]}, root, reload=False)
            self.assertEqual(json.loads((root / "policy.json").read_text()), policy)
            self.assertEqual(json.loads((root / "nebula.json").read_text())["pki"]["blocklist"], ["a" * 64])


class HostnameTests(unittest.TestCase):
    def test_firewall_rule_is_scoped_to_the_mesh(self):
        with patch("tknet.shutil.which", return_value="/usr/sbin/ufw"), patch("tknet.run", return_value="Status: active\n") as run:
            tknet.configure_host_firewall()
            self.assertEqual(run.call_args.args[0], ["/usr/sbin/ufw", "allow", "in", "on", "tktun",
                             "from", "10.27.0.0/24", "comment", "TK authenticated mesh"])
        with patch("tknet.shutil.which", return_value="/usr/sbin/ufw"), patch("tknet.run", return_value="Status: inactive\n") as run:
            tknet.configure_host_firewall()
            self.assertEqual(run.call_count, 1)

    def test_refresh_and_disconnect_preserve_other_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory) / "hosts"
            original = "127.0.0.1 localhost\n::1 localhost\n192.0.2.1 custom # keep\n"
            hosts.write_text(original)
            hosts.chmod(0o644)
            with patch.object(tknet, "HOSTS_FILE", hosts):
                tknet.configure_hostnames(True)
                tknet.configure_hostnames(True)
                self.assertEqual(hosts.read_text().count("# BEGIN TKNET HOSTS"), 1)
                for name, address in tknet.HOSTS.items():
                    self.assertIn(f"{address}\t{name}\n", hosts.read_text())
                # Preserve an unrelated edit made while the connection is active.
                with hosts.open("a") as stream:
                    stream.write("192.0.2.2 added\n")
                tknet.configure_hostnames(False)
                tknet.configure_hostnames(False)
                self.assertEqual(hosts.read_text(), original + "192.0.2.2 added\n")
                self.assertEqual(hosts.stat().st_mode & 0o777, 0o644)

    def test_malformed_block_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory) / "hosts"
            original = "127.0.0.1 localhost\n# BEGIN TKNET HOSTS\n"
            hosts.write_text(original)
            with patch.object(tknet, "HOSTS_FILE", hosts):
                with self.assertRaisesRegex(RuntimeError, "Malformed"):
                    tknet.configure_hostnames(True)
            self.assertEqual(hosts.read_text(), original)


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
        self.home_patch = patch("admin.Path.home", return_value=self.root)
        self.home_patch.start()
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
        self.home_patch.stop()
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

    def test_list_reports_admission_without_exposing_credentials(self):
        def guest():
            return next(row for row in admin.list_members() if row["name"] == "test-guest")
        self.assertEqual(guest()["state"], "invited")
        record = json.loads((self.directory / "record.json").read_text())
        record["expires"] = time.time() - 1
        tknet.write(self.directory / "record.json", json.dumps(record))
        self.assertEqual(guest()["state"], "invitation-expired")
        record["expires"] = time.time() + 60
        tknet.write(self.directory / "record.json", json.dumps(record))
        admin.enroll(self.token, self.request)
        self.assertEqual(guest()["state"], "issued")
        self.assertEqual(set(guest()), {"name", "role", "address", "state"})

    def test_renew_preserves_keys_and_revocation_blocks_all_entry_points(self):
        old = admin.enroll(self.token, self.request)
        outcome = admin.renew("test-guest")
        self.assertEqual(outcome["name"], "test-guest")
        new = admin.refresh(self.token)
        for key in ("name", "address", "role"):
            self.assertEqual(old[key], new[key])
        self.assertEqual(tknet.certificate_info(old["node.crt"])["publicKey"], tknet.certificate_info(new["node.crt"])["publicKey"])
        with patch("admin.synchronize_policy", return_value={"tkserver": "applied"}):
            admin.revoke("test-guest")
            version = admin.policy_snapshot()["version"]
            admin.revoke("test-guest")
        self.assertEqual(admin.policy_snapshot()["version"], version)
        self.assertIn(tknet.certificate_info(old["node.crt"])["fingerprint"], admin.policy_snapshot()["fingerprints"])
        for operation in (lambda: admin.enroll(self.token, self.request), lambda: admin.refresh(self.token), lambda: admin.renew("test-guest")):
            with self.assertRaisesRegex(ValueError, "[Rr]evoked"):
                operation()

    def test_revoke_unused_invitation_prevents_enrollment(self):
        with patch("admin.synchronize_policy", return_value={}):
            admin.revoke("test-guest")
        with self.assertRaisesRegex(ValueError, "revoked"):
            admin.enroll(self.token, self.request)

    def test_failed_policy_delivery_is_reported(self):
        with patch("admin.DELIVERY_TIMEOUT", 0), patch("admin.run", side_effect=RuntimeError("unreachable")):
            result = admin.synchronize_policy(admin.policy_snapshot())
        self.assertTrue(all(value.startswith("pending:") for value in result.values()))

    def test_real_ssh_revocation_rejects_device_certificate(self):
        bundle = admin.enroll(self.token, self.request)
        certificate = self.root / "device-cert.pub"
        key = self.root / "revoked.pub"
        krl = self.root / "revoked.krl"
        tknet.write(certificate, bundle["ssh-user-cert.pub"])
        tknet.write(key, self.request["ssh_public"])
        tknet.run(["ssh-keygen", "-k", "-f", krl, key])
        result = subprocess.run(["ssh-keygen", "-Q", "-f", str(krl), str(certificate)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("REVOKED", result.stdout)

    def test_host_issuance_records_public_membership(self):
        request = {**self.request, "ssh_host_public": self.request["ssh_public"]}
        bundle = admin.issue_host("tkbox", request)
        self.assertEqual(json.loads((admin.ADMIN / "hosts/tkbox.json").read_text()), bundle)
        self.assertNotIn("node.key", bundle)
        self.assertEqual(next(row for row in admin.list_members() if row["name"] == "tkbox")["state"], "issued")

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
