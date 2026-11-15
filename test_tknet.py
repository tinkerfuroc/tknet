"""Offline checks for enrollment, retries and guest role handling."""

import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tknet import Client


RUNNING = {
    "BackendState": "Running",
    "Self": {"ID": "device-1", "Tags": ["tag:guest"]},
    "TailscaleIPs": ["100.96.0.2"],
}


class JoinTests(unittest.TestCase):
    def setUp(self):
        with patch("tknet.shutil.which", return_value="/usr/bin/tailscale"):
            self.client = Client({"server_url": "https://hs.example.test"})
        self.commands = []
        self.key_path = None

    def fake_command(self, args, **kwargs):
        self.commands.append(args)
        if args == ["debug", "prefs"]:
            return json.dumps({"ControlURL": self.client.server})
        for arg in args:
            if arg.startswith("--auth-key=file:"):
                self.key_path = Path(arg.removeprefix("--auth-key=file:"))
                self.assertEqual(self.key_path.read_text(), "test-invitation")
                self.assertEqual(self.key_path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("test-invitation", args)
        return ""

    def test_first_join_handles_null_self_and_removes_key_file(self):
        with patch.object(self.client, "state", side_effect=[{"BackendState": "NeedsLogin", "Self": None}, RUNNING]), patch.object(self.client, "run", side_effect=self.fake_command), patch("tknet.socket.getaddrinfo"), patch("builtins.print"):
            self.client.join("test-invitation")
        self.assertFalse(self.key_path.exists())
        self.assertIn("--shields-up=true", self.commands[0])
        self.assertIn("--ssh=false", self.commands[0])

    def test_repeat_join_reuses_identity_without_consuming_invitation(self):
        with patch.object(self.client, "state", return_value=RUNNING), patch.object(self.client, "run", side_effect=self.fake_command), patch("builtins.print"):
            self.client.join("used-invitation")
        self.assertIsNone(self.key_path)
        self.assertIn(["up", "--timeout=60s"], self.commands)

    def test_other_network_is_not_modified(self):
        with patch.object(self.client, "state", return_value=RUNNING), patch.object(self.client, "run", return_value='{"ControlURL":"https://other.test"}') as command:
            with self.assertRaisesRegex(RuntimeError, "another Tailscale profile"):
                self.client.join("test-invitation")
        command.assert_called_once_with(["debug", "prefs"])

    def test_wrong_role_after_enrollment_disconnects(self):
        wrong_role = {**RUNNING, "Self": {"ID": "device-1", "Tags": ["tag:host"]}}
        with patch.object(self.client, "state", side_effect=[{"BackendState": "NeedsLogin"}, wrong_role]), patch.object(self.client, "run", side_effect=self.fake_command), patch("tknet.socket.getaddrinfo"):
            with self.assertRaisesRegex(RuntimeError, "no guest role"):
                self.client.join("test-invitation")
        self.assertEqual(self.commands[-1], ["down"])
        self.assertFalse(self.key_path.exists())

    def test_failed_enrollment_removes_key_file(self):
        def fail(args, **kwargs):
            self.fake_command(args, **kwargs)
            raise RuntimeError("Invitation expired")

        with patch.object(self.client, "state", return_value={"BackendState": "NeedsLogin"}), patch.object(self.client, "run", side_effect=fail), patch("tknet.socket.getaddrinfo"):
            with self.assertRaisesRegex(RuntimeError, "Invitation expired"):
                self.client.join("test-invitation")
        self.assertFalse(self.key_path.exists())


if __name__ == "__main__":
    unittest.main()
