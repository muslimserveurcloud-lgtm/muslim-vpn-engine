import base64
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from msc_protocol.v2ray_import import import_config


class ImportTests(unittest.TestCase):
    def test_vless(self):
        result = import_config(
            "vless://12345678-1234-1234-1234-123456789abc"
            "@example.com:443?type=ws&security=tls&sni=example.com#test"
        )
        self.assertEqual(result["protocol"], "vless")
        self.assertEqual(result["port"], 443)
        self.assertEqual(result["transport"], "ws")
        self.assertEqual(result["sni"], "example.com")

    def test_vmess(self):
        data = {
            "add": "example.com", "port": "443",
            "id": "12345678-1234-1234-1234-123456789abc",
            "net": "ws", "tls": "tls", "ps": "test",
        }
        encoded = base64.b64encode(json.dumps(data).encode()).decode()
        result = import_config("vmess://" + encoded)
        self.assertEqual(result["protocol"], "vmess")
        self.assertTrue(result["tls"])

    def test_json(self):
        result = import_config('{"outbounds":[]}')
        self.assertEqual(result["format"], "v2ray-json")

    def test_unknown_scheme_rejected(self):
        with self.assertRaises(ValueError):
            import_config("unknown://example.com")

if __name__ == "__main__":
    unittest.main()
