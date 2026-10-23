import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from msc_core.network import resolve, tcp_check, udp_exchange


class NetworkCoreTests(unittest.TestCase):
    def test_resolve_localhost(self):
        results = resolve("localhost")
        self.assertTrue(results)
        self.assertTrue(
            any(item["address"] in ("127.0.0.1", "::1") for item in results)
        )

    def test_tcp_rejects_invalid_port(self):
        result = tcp_check("127.0.0.1", 0.5, timeout=0.5)
        self.assertFalse(result["ok"])

    def test_udp_returns_structured_result(self):
        result = udp_exchange(
            "127.0.0.1", 9, b"MSC-TEST", timeout=0.2
        )
        self.assertIn("sent", result)


if __name__ == "__main__":
    unittest.main()
