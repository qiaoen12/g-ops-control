from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

from ops.executor import clean_forced_environment
from ops.gateway import IdentityError, SystemIdentityProvider


FIXTURE = Path(__file__).parents[1] / "fixtures" / "identity" / "mapping.yml"
OWNER = "33333333-3333-4333-8333-333333333333"
OTHER_OWNER = "44444444-4444-4444-8444-444444444444"


class IdentityIntegrationTests(unittest.TestCase):
    def test_fixture_maps_two_credentials_to_one_owner_without_private_key_data(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "etc-ops-control"
            directory.mkdir(mode=0o700)
            target = directory / "identity.yml"
            shutil.copyfile(FIXTURE, target)
            target.chmod(0o600)
            provider = SystemIdentityProvider.from_file(target)
            self.assertEqual(provider.owner_id("ops-call-mac-fixture"), OWNER)
            self.assertEqual(provider.owner_id("ops-call-other-computer-fixture"), OWNER)
            self.assertEqual(provider.owner_id("ops-call-other-owner-fixture"), OTHER_OWNER)

    def test_unknown_credential_and_broad_mapping_permissions_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "etc-ops-control"
            directory.mkdir(mode=0o700)
            target = directory / "identity.yml"
            shutil.copyfile(FIXTURE, target)
            target.chmod(0o600)
            provider = SystemIdentityProvider.from_file(target)
            with self.assertRaises(IdentityError):
                provider.owner_id("unknown-credential")
            target.chmod(0o640)
            provider = SystemIdentityProvider.from_file(target)
            self.assertEqual(provider.owner_id("ops-call-mac-fixture"), OWNER)
            target.chmod(0o644)
            with self.assertRaises(IdentityError):
                SystemIdentityProvider.from_file(target)

    def test_forced_environment_keeps_only_non_secret_system_marker(self) -> None:
        clean = clean_forced_environment(
            {
                "OPS_CONTROL_CREDENTIAL_ID": "ops-call-mac-fixture",
                "PYTHONPATH": "FAKE_SECRET_SENTINEL",
                "LD_PRELOAD": "/tmp/not-used.dylib",
            }
        )
        self.assertEqual(clean["OPS_CONTROL_CREDENTIAL_ID"], "ops-call-mac-fixture")
        self.assertNotIn("PYTHONPATH", clean)
        self.assertNotIn("LD_PRELOAD", clean)

    def test_deploy_templates_bind_key_identity_and_use_root_owned_key_file(self) -> None:
        deploy = Path(__file__).parents[2] / ".." / ".." / "2-infra" / "ops-control" / "deploy"
        authorized_keys = (deploy / "authorized_keys.example").read_text(encoding="utf-8")
        self.assertIn("/usr/bin/python3 -E -s /usr/local/libexec/ops-control/ops-call --credential-id ops-call-mac-example", authorized_keys)
        self.assertIn("/usr/bin/python3 -E -s /usr/local/libexec/ops-control/ops-call --credential-id ops-call-windows-example", authorized_keys)
        sshd = (deploy / "sshd_config.fragment.example").read_text(encoding="utf-8")
        self.assertIn("AuthorizedKeysFile /etc/ssh/ops-control/authorized_keys/%u", sshd)
        self.assertIn("PermitUserEnvironment no", sshd)
        self.assertIn("PermitUserRC no", sshd)
        self.assertLess(sshd.index("PermitUserRC no"), sshd.index("Match User ops-call"))
        self.assertNotIn("PermitUserEnvironment yes", sshd)

        layout = yaml.safe_load((deploy / "layout.yml").read_text(encoding="utf-8"))
        paths = {entry["path"]: entry for entry in layout["paths"]}
        self.assertEqual(paths["/etc/ssh/ops-control/authorized_keys"]["mode"], "0750")
        self.assertEqual(paths["/etc/ssh/ops-control/authorized_keys/ops-call"]["mode"], "0640")
        self.assertEqual(paths["/etc/ssh/ops-control/authorized_keys"]["owner"], "root")
        self.assertEqual(paths["/etc/ssh/ops-control/authorized_keys"]["group"], "ops-call")
        self.assertEqual(paths["/usr/local/libexec/ops-control/ops-approve"]["mode"], "0755")
        self.assertEqual(paths["/etc/ops-control/connection.yml"]["mode"], "0640")
        self.assertEqual(paths["/etc/ops-control/connection.yml"]["group"], "ops-exec")
        for shared_projection in (
            "/etc/ops-control/webauthn/trusted/metadata",
            "/etc/ops-control/webauthn/trusted/metadata/credentials",
            "/var/lib/ops-control/approvals",
            "/var/lib/ops-control/logs",
            "/var/lib/ops-control/results",
        ):
            with self.subTest(path=shared_projection):
                self.assertEqual(paths[shared_projection]["mode"], "2750")
        preflight = (deploy / "preflight.sh.example").read_text(encoding="utf-8")
        self.assertIn("check_file /usr/local/libexec/ops-control/ops-approve root root 755", preflight)
        self.assertIn("check_file /etc/ops-control/connection.yml root ops-exec 640", preflight)
        self.assertEqual(
            preflight.count("check_dir /etc/ops-control/webauthn/trusted/counters ops-approve ops-approve 700"),
            1,
        )
        self.assertIsNone(paths["/opt/ops-control/current"]["mode"])
        self.assertEqual(layout["boundaries"]["ops-maint"]["privileged_write_via"], "root")
        self.assertIn(
            "/etc/ssh/ops-control/authorized_keys",
            layout["boundaries"]["ops-call"]["denied_write"],
        )


if __name__ == "__main__":
    unittest.main()
