import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HEALTHCHECK = ROOT / "vpn-healthcheck.sh"


@unittest.skipUnless(shutil.which("timeout"), "timeout command required")
class VpnHealthcheckTests(unittest.TestCase):
    def run_healthcheck(self, protonvpn_script, python_script=None, timeout="1"):
        with tempfile.TemporaryDirectory() as tmpdir:
            bindir = Path(tmpdir)
            self.write_executable(bindir / "protonvpn", protonvpn_script)
            self.write_executable(
                bindir / "python3",
                python_script
                or """#!/bin/sh
exit 0
""",
            )

            env = os.environ.copy()
            env["PATH"] = f"{bindir}{os.pathsep}{env['PATH']}"
            env["PROTONVPN_HEALTH_TIMEOUT"] = timeout
            env["PROTONVPN_HEALTHCHECK_URL"] = "https://example.invalid/health"

            return subprocess.run(
                [str(HEALTHCHECK)],
                capture_output=True,
                text=True,
                env=env,
                timeout=5,
            )

    def write_executable(self, path, content):
        path.write_text(textwrap.dedent(content))
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def test_passes_when_status_connected_and_outbound_probe_succeeds(self):
        result = self.run_healthcheck(
            """#!/bin/sh
printf 'Status:       Connected\\n'
"""
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VPN healthcheck passed", result.stdout)

    def test_fails_when_status_exits_zero_without_connected_state(self):
        result = self.run_healthcheck(
            """#!/bin/sh
printf '[!] Could not reach the VPN Server\\n'
printf "[!] You may want to reconnect with 'protonvpn reconnect'\\n"
exit 0
"""
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not report Connected", result.stderr)

    def test_fails_when_status_times_out(self):
        result = self.run_healthcheck(
            """#!/bin/sh
sleep 2
printf 'Status:       Connected\\n'
""",
            timeout="1",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("timed out", result.stderr)

    def test_fails_when_outbound_probe_fails(self):
        result = self.run_healthcheck(
            """#!/bin/sh
printf 'Status:       Connected\\n'
""",
            python_script="""#!/bin/sh
printf 'probe failed\\n' >&2
exit 1
""",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outbound connectivity probe failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
