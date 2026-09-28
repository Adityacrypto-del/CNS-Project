"""Web frontend tests: static server hardening, and the browser crypto modules (frontend/js)
run under Node against a live server (tests/web_client_test.mjs).

Uses its own freshly initialised data directory and server process, because the Node
script expects the untouched demo data. The Node part is skipped when Node 20+ is missing.
"""

import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _node_version() -> int:
    node = shutil.which("node")
    if not node:
        return 0
    out = subprocess.run([node, "--version"], capture_output=True, text=True).stdout
    m = re.match(r"v(\d+)", out)
    return int(m.group(1)) if m else 0


class TestWebClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = Path(tempfile.mkdtemp(prefix="secure-exam-web-"))
        cls.env = {**os.environ, "SECURE_EXAM_DATA": str(cls.data)}
        subprocess.run([sys.executable, "-m", "secure_exam.init_system", "--force"], cwd=ROOT,
                       env=cls.env, check=True, capture_output=True)
        cls.server = subprocess.Popen(
            [sys.executable, "-u", "-m", "secure_exam.server", "--port", "0", "--api-port", "0", "--web-port", "0"],
            cwd=ROOT, env=cls.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        urls = {}
        for line in cls.server.stdout:
            if m := re.search(r"(HTTPS JSON API|Web frontend)\s+on (https://\S+)", line):
                urls[m.group(1)] = m.group(2)
            if "Ctrl+C" in line or len(urls) == 2:
                break
        if len(urls) != 2:
            cls.tearDownClass()
            raise RuntimeError("server did not start")
        cls.api = urls["HTTPS JSON API"].removesuffix("/api/v1")
        cls.web = urls["Web frontend"].rstrip("/")
        cls.ca = cls.data / "pki" / "ca_cert.pem"
        cls.tls = ssl.create_default_context(cafile=str(cls.ca))

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        cls.server.wait(timeout=10)
        cls.server.stdout.close()
        shutil.rmtree(cls.data, ignore_errors=True)

    def _get(self, path: str):
        try:
            with urllib.request.urlopen(self.web + path, context=self.tls, timeout=10) as r:
                return r.status, dict(r.headers), r.read().decode()
        except urllib.error.HTTPError as exc:
            exc.close()
            return exc.code, dict(exc.headers), ""

    def test_static_server_headers(self):
        status, headers, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn('<script type="module" src="/js/app.js">', body)
        csp = headers["Content-Security-Policy"]
        for directive in ("default-src 'none'", "script-src 'self'", "frame-ancestors 'none'",
                          f"connect-src {self.api}"):
            self.assertIn(directive, csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("max-age", headers["Strict-Transport-Security"])

    def test_config_pins_server_key(self):
        status, headers, body = self._get("/config.js")
        self.assertEqual(status, 200)
        self.assertIn("javascript", headers["Content-Type"])
        pem = (self.data / "pki" / "server_sign_pub.pem").read_text().strip()
        self.assertIn(pem.replace("\n", "\\n"), body)
        self.assertIn(f'"apiBase": "{self.api}"', body)

    def test_static_server_refuses_traversal_and_unknown_files(self):
        for path in ("/../secure_exam/config.py", "/%2e%2e/data/pki/ca_key.pem", "/js/../../README.md",
                     "/.git/config", "/nothing.js", "/index.html.bak"):
            with self.subTest(path=path):
                self.assertEqual(self._get(path)[0], 404)

    @unittest.skipIf(_node_version() < 20, "Node.js 20+ not installed")
    def test_browser_crypto_interoperates_with_server(self):
        env = {**self.env, "API_BASE": self.api, "NODE_EXTRA_CA_CERTS": str(self.ca)}
        run = subprocess.run(["node", "tests/web_client_test.mjs"], cwd=ROOT, env=env,
                             capture_output=True, text=True, timeout=300)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("web client checks passed", run.stdout)

        # Files produced by the browser code are accepted by the Python tools.
        check = (
            "from secure_exam.client import verify_receipt_file;"
            "from secure_exam.crypto_utils import load_private_key;"
            "import sys, pathlib;"
            "d = pathlib.Path(sys.argv[1]);"
            "print(verify_receipt_file(d / 'browser_receipt.json')['exam_id']);"
            "load_private_key((d / 'browser_key.pem').read_bytes(), b'New#Password2026')"
        )
        out = subprocess.run([sys.executable, "-c", check, str(self.data)], cwd=ROOT, env=self.env,
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "CNS-MIDTERM-2026")


if __name__ == "__main__":
    unittest.main()
