"""Pruebas de privacidad y no destructividad para la nueva v1.6.0."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cookieguard import forensics, honeypot, stix_export, dns_canary
from cookieguard.browsers import Profile


class PrivacyHardeningTests(unittest.TestCase):
    def test_snapshot_sanitize_redacts_username_and_token(self):
        username = os.environ.get("USERNAME") or os.environ.get("USER") or "testuser"
        with tempfile.TemporaryDirectory() as td:
            with patch.object(forensics, "data_dir", return_value=Path(td)), \
                 patch.object(forensics, "_collect_processes", return_value=[
                     {"pid": 1, "name": "demo", "cmd": f"/home/{username}/app --token abcdefghijklmnop", "exe": "/tmp/demo"}
                 ]), \
                 patch.object(forensics, "_collect_network_connections", return_value=[]), \
                 patch.object(forensics, "_collect_dns_cache", return_value=[]), \
                 patch.object(forensics, "_collect_suspicious_hashes", return_value=[]):
                path = Path(forensics.capture_volatile_snapshot(output_dir=Path(td), sanitize=True))
                import zipfile
                with zipfile.ZipFile(path) as zf:
                    system = json.loads(zf.read("entorno_sistema.json"))
                    procs = json.loads(zf.read("procesos.json"))
                self.assertEqual(system["usuario"], "<REDACTED_USER>")
                self.assertNotIn(username, procs[0]["cmd"])
                self.assertIn("<REDACTED>", procs[0]["cmd"])

    def test_snapshot_cipher_authenticates_and_roundtrips(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("Dependencia opcional cryptography no instalada")
        payload = b"safe forensic data"
        encrypted = forensics._encrypt_payload(payload, "correct horse battery staple")
        with tempfile.TemporaryDirectory() as td:
            enc_path = Path(td) / "snapshot.cgenc"
            enc_path.write_bytes(encrypted)
            out = Path(forensics.decrypt_snapshot(enc_path, "correct horse battery staple"))
            self.assertEqual(out.read_bytes(), payload)
            with self.assertRaises(ValueError):
                forensics.decrypt_snapshot(enc_path, "wrong password")

    def test_honeypot_never_modifies_or_deletes_preexisting_dir(self):
        with tempfile.TemporaryDirectory() as td, patch.object(honeypot, "_get_baseline_path", return_value=Path(td) / "baseline.json"):
            root = Path(td) / "browser"
            trap = root / honeypot.HONEYPOT_PROFILE_NAME
            trap.mkdir(parents=True)
            user_file = trap / "my-important-file.txt"
            user_file.write_text("keep me", encoding="utf-8")
            profile = Profile(browser="test", family="chromium", profile="Default", root=root, path=root, cookies_db=None)
            result = honeypot.setup_honeypot([profile])
            self.assertEqual(result["perfiles_creados"], 0)
            self.assertEqual(user_file.read_text(encoding="utf-8"), "keep me")
            remove_result = honeypot.remove_honeypot([profile])
            self.assertEqual(remove_result["eliminados"], 0)
            self.assertTrue(user_file.exists())

    def test_capture_encrypted_snapshot_leaves_no_plaintext_zip_and_refuses_overwrite(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("Dependencia opcional cryptography no instalada")
        with tempfile.TemporaryDirectory() as td:
            encrypted_path = Path(forensics.capture_volatile_snapshot(
                reason="prueba de privacidad", output_dir=Path(td), password="una clave larga y segura"
            ))
            self.assertEqual(encrypted_path.suffix, ".cgenc")
            self.assertFalse(encrypted_path.with_suffix(".zip").exists())
            recovered = Path(forensics.decrypt_snapshot(encrypted_path, "una clave larga y segura"))
            self.assertTrue(recovered.exists())
            with self.assertRaises(FileExistsError):
                forensics.decrypt_snapshot(encrypted_path, "una clave larga y segura")

    def test_stix_bundle_contains_only_heuristic_notes_not_fake_iocs(self):
        result = {"indicadores": [{"id": "I01_acceso_ficheros", "nombre": "Acceso", "estado": "alerta", "resumen": "Lectura sospechosa", "puntos": 10, "hallazgos": ["evidencia local"]}]}
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "events.json"
            bundle = stix_export.export_stix_bundle(result, out)
            self.assertEqual(bundle["type"], "bundle")
            self.assertTrue(out.is_file())
            self.assertTrue(any(obj["type"] == "note" for obj in bundle["objects"]))
            self.assertFalse(any(obj["type"] == "indicator" for obj in bundle["objects"]))
            self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["id"], bundle["id"])

    def test_dns_canary_only_generates_user_domain_and_never_contacts_network(self):
        with tempfile.TemporaryDirectory() as td, patch.object(dns_canary, "_get_store_path", return_value=Path(td) / "canaries.json"):
            record = dns_canary.generate_dns_canary_token("example.org", "test local")
            self.assertTrue(record["fqdn"].endswith(".example.org"))
            self.assertEqual(dns_canary.check_dns_cache_for_canaries([record["fqdn"]])[0]["token_id"], record["token_id"])
            with self.assertRaises(ValueError):
                dns_canary.generate_dns_canary_token("not a domain")


if __name__ == "__main__":
    unittest.main()
