import asyncio
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

import httpx

from protonvpn_cli import api, locking

# Avoid writing to a real user's VPN log/configuration during imports.
with patch.dict(sys.modules, {"protonvpn_cli.logger": Mock()}):
    from protonvpn_cli import cli, connection, utils


class StatusTests(unittest.TestCase):
    def test_disconnected_status_has_no_network_dependencies(self):
        output = io.StringIO()
        with patch.object(connection, "check_init"), \
                patch.object(connection, "local_tunnel_connected", return_value=False), \
                patch.object(connection, "get_ip_info") as ip_info, \
                patch.object(connection, "pull_server_data") as refresh, \
                patch.object(connection.os.path, "isfile", return_value=False), \
                contextlib.redirect_stdout(output):
            started = time.monotonic()
            connection.status()
        self.assertLess(time.monotonic() - started, 0.2)
        self.assertIn("Disconnected", output.getvalue())
        ip_info.assert_not_called()
        refresh.assert_not_called()

    def test_connected_status_uses_cache_and_tolerates_missing_metadata(self):
        output = io.StringIO()
        with patch.object(connection, "check_init"), \
                patch.object(connection, "local_tunnel_connected", return_value=True), \
                patch.object(connection, "get_ip_info") as ip_info, \
                patch.object(connection, "pull_server_data") as refresh, \
                patch.object(connection, "get_config_value", side_effect=KeyError), \
                patch.object(connection, "get_servers", side_effect=FileNotFoundError), \
                patch.object(connection, "get_transferred_data", return_value=("0B", "0B")), \
                patch.object(connection.os.path, "isfile", return_value=False), \
                contextlib.redirect_stdout(output):
            connection.status()
        self.assertIn("Status:       Connected", output.getvalue())
        self.assertIn("Connectivity: Not verified", output.getvalue())
        self.assertIn("Server:       Unknown", output.getvalue())
        ip_info.assert_not_called()
        refresh.assert_not_called()

    def test_details_retains_public_ip_lookup(self):
        with patch.object(connection, "check_init"), \
                patch.object(connection, "local_tunnel_connected", return_value=False), \
                patch.object(connection, "get_ip_info", return_value=("1.2.3.4", "ISP")) as lookup, \
                patch.object(connection.os.path, "isfile", return_value=False), \
                contextlib.redirect_stdout(io.StringIO()):
            connection.status(details=True)
        lookup.assert_called_once()

    def test_saved_process_alone_is_not_connected(self):
        with patch.object(utils.subprocess, "run", return_value=Mock(returncode=0, stdout=b"123")), \
                patch("builtins.open", mock_open(read_data="0")):
            self.assertFalse(utils.local_tunnel_connected())

    def test_hung_local_check_has_a_deadline(self):
        with patch.object(utils.subprocess, "run", side_effect=subprocess.TimeoutExpired("pgrep", 0.5)) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                utils.local_tunnel_connected()
        self.assertEqual(run.call_args.kwargs["timeout"], 0.5)

    def test_live_tunnel_requires_address_and_up_flag(self):
        for addresses, expected in [
            (b'[{"flags": ["UP"], "addr_info": [{"local": "10.0.0.2"}]}]', True),
            (b'[{"flags": ["UP"], "addr_info": []}]', False),
            (b'[{"flags": [], "addr_info": [{"local": "10.0.0.2"}]}]', False),
        ]:
            with self.subTest(addresses=addresses), \
                    patch.object(utils.subprocess, "run", side_effect=[
                        Mock(returncode=0, stdout=b"123"),
                        Mock(returncode=0, stdout=addresses),
                        Mock(returncode=0, stdout=addresses),
                    ]), patch("builtins.open", mock_open(read_data="1")):
                self.assertEqual(utils.local_tunnel_connected(), expected)


class ApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=api.app), base_url="http://vpn"
        )

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_status_response_compatibility(self):
        with patch.object(api, "run_process", return_value=Mock(stdout="Status:     Disconnected\n")) as run:
            response = await self.client.get("/status")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"success": True, "output": "Status:     Disconnected\n"})
        self.assertEqual(run.call_args.kwargs["timeout"], 2)
        self.assertEqual(run.call_args.args[0], ["protonvpn", "status"])

    async def test_actual_hung_subprocess_is_killed(self):
        # Exercise the real subprocess deadline without running protonvpn.
        started = time.monotonic()
        with self.assertRaises(api.HTTPException) as error:
            await asyncio.to_thread(api.run_cli_command, [sys.executable, "-c", "import time; time.sleep(5)"], 0.1)
        self.assertEqual(error.exception.status_code, 504)
        self.assertLess(time.monotonic() - started, 1)

    async def test_timeout_stops_descendants_before_another_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory, "late-mutation")
            child = "import time; from pathlib import Path; time.sleep(0.5); Path({!r}).touch()".format(str(marker))
            parent = "import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', {!r}]); time.sleep(5)"
            with self.assertRaises(api.HTTPException):
                await asyncio.to_thread(
                    api.run_cli_command, [sys.executable, "-c", parent.format(child)], 0.2,
                )
            await asyncio.sleep(0.6)
            self.assertFalse(marker.exists(), "timed-out command left a child mutating VPN state")

    async def test_health_status_timeout_and_failure(self):
        for result in [subprocess.TimeoutExpired("protonvpn", 0.1),
                       Mock(returncode=0, stdout="Status: Disconnected\n", stderr=""),
                       Mock(returncode=1, stdout="", stderr="status error")]:
            with self.subTest(result=result), patch.object(api, "run_process", side_effect=[result]) as run:
                response = await self.client.get("/healthz")
                self.assertEqual(response.status_code, 503)
                self.assertEqual(run.call_count, 1)

    async def test_probe_total_deadline_and_compatible_success(self):
        connected = Mock(returncode=0, stdout="Status:       Connected\n", stderr="")
        for probe, expected in [(Mock(returncode=0), 200),
                                (Mock(returncode=1, stderr="DNS failed"), 503),
                                (subprocess.TimeoutExpired("probe", 0.1), 503)]:
            with self.subTest(expected=expected), \
                    patch.object(api, "run_process", side_effect=[connected, probe]) as run, \
                    patch.dict(os.environ, {"PROTONVPN_HEALTH_TIMEOUT": "0.1"}):
                response = await self.client.get("/healthz")
                self.assertEqual(response.status_code, expected)
                self.assertEqual(run.call_args.kwargs["timeout"], 0.1)
                if expected == 200:
                    self.assertEqual(response.json(), {"success": True, "status": "healthy"})

    async def test_hung_probe_including_dns_is_killed(self):
        original_run = api.run_process

        def run(command, **kwargs):
            if command == ["protonvpn", "status"]:
                return subprocess.CompletedProcess(command, 0, "Status: Connected\n", "")
            return original_run(command, **kwargs)

        # A fake requests module models a DNS call ignoring the HTTP timeout.
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "requests.py").write_text(
                "import time\nclass RequestException(Exception): pass\n"
                "def get(*args, **kwargs): time.sleep(10)\n"
            )
            with patch.dict(os.environ, {"PYTHONPATH": directory, "PROTONVPN_HEALTH_TIMEOUT": "0.2"}), \
                    patch.object(api, "run_process", side_effect=run):
                started = time.monotonic()
                response = await self.client.get("/healthz")
                self.assertLess(time.monotonic() - started, 1)
                self.assertEqual(response.status_code, 503)
                self.assertIn("probe timed out", response.json()["detail"])

    async def test_status_responsive_during_slow_mutation_and_probe(self):
        for path in ("/connect", "/healthz"):
            entered = threading.Event()
            release = threading.Event()

            def run(command, **kwargs):
                if command[1:2] == ["connect"] or command[1:2] == ["-m"]:
                    entered.set()
                    release.wait(2)
                return Mock(returncode=0, stdout="Status:       Connected\n", stderr="")

            with self.subTest(path=path), patch.object(api, "run_process", side_effect=run):
                slow = asyncio.create_task(self.client.post(path, json={}) if path == "/connect"
                                           else self.client.get(path))
                try:
                    self.assertTrue(await asyncio.to_thread(entered.wait, 1))
                    response = await asyncio.wait_for(self.client.get("/status"), 0.3)
                    self.assertEqual(response.status_code, 200)
                finally:
                    release.set()
                    await slow

    async def test_command_errors_are_useful(self):
        for error, code in [(FileNotFoundError("missing executable"), 503),
                            (subprocess.CalledProcessError(1, "cmd", stderr="failed"), 500)]:
            with patch.object(api, "run_process", side_effect=error):
                response = await self.client.post("/disconnect")
                self.assertEqual(response.status_code, code)
                self.assertTrue(response.json()["detail"])

    async def test_api_mutations_cannot_overlap(self):
        # Run the actual CLI entry point/lock, replacing only the VPN operation.
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory, "protonvpn")
            executable.write_text("#!" + sys.executable + "\n" + """
import sys, time
from protonvpn_cli import constants
constants.CONFIG_DIR = sys.argv[0] + '.config'
from protonvpn_cli import cli
def operation():
    with open(constants.CONFIG_DIR + '/events', 'a') as output:
        output.write('start ' + sys.argv[1] + '\\n'); output.flush()
        time.sleep(0.1)
        output.write('end ' + sys.argv[1] + '\\n')
cli.cli = operation
cli.main()
""")
            executable.chmod(0o700)
            Path(str(executable) + ".config").mkdir()
            with patch.dict(os.environ, {
                "PATH": directory + os.pathsep + os.environ["PATH"],
                "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
            }):
                responses = await asyncio.gather(
                    self.client.post("/connect", json={"random": True}),
                    self.client.post("/disconnect"), self.client.post("/reconnect"),
                )
            self.assertEqual([response.status_code for response in responses], [200] * 3,
                             [response.text for response in responses])
            events = Path(str(executable) + ".config", "events").read_text().splitlines()
            self.assertEqual(len(events), 6)
            for index in range(0, 6, 2):
                self.assertEqual(events[index].replace("start ", "end "), events[index + 1])


class LockTests(unittest.TestCase):
    def test_cli_dispatch_locks_all_mutations_and_leaves_status_unlocked(self):
        for command in ("connect", "disconnect", "reconnect", "c", "d", "r", "init", "status"):
            with self.subTest(command=command), patch.object(cli, "cli"), \
                    patch.object(cli, "mutation_lock") as lock, \
                    patch.object(sys, "argv", ["protonvpn", command]):
                cli.main()
                self.assertEqual(lock.call_count, int(command != "status"))

    def test_separate_cli_processes_cannot_overlap(self):
        script = """
import sys, time
from protonvpn_cli import locking
locking.CONFIG_DIR = sys.argv[1]
with locking.mutation_lock():
    with open(sys.argv[1] + '/events', 'a') as output:
        output.write('start\\n'); output.flush()
        time.sleep(0.1)
        output.write('end\\n')
"""
        with tempfile.TemporaryDirectory() as directory:
            processes = [subprocess.Popen([sys.executable, "-c", script, directory]) for _ in range(3)]
            for process in processes:
                self.assertEqual(process.wait(timeout=3), 0)
            self.assertEqual(Path(directory, "events").read_text().splitlines(), ["start", "end"] * 3)

    def test_busy_lock_times_out_and_releases_after_error(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(locking, "CONFIG_DIR", directory):
            with locking.mutation_lock():
                with self.assertRaises(TimeoutError):
                    with locking.mutation_lock(timeout=0.01):
                        self.fail("lock overlap")
            with self.assertRaises(ValueError):
                with locking.mutation_lock():
                    raise ValueError("operation failed")
            with locking.mutation_lock(timeout=0.01):
                pass

    def test_invalid_timeouts_use_defaults(self):
        for value in ("nan", "inf", "0", "-1", "invalid"):
            with patch.dict(os.environ, {"PROTONVPN_HEALTH_TIMEOUT": value}):
                self.assertEqual(api.get_health_timeout(), 10)


if __name__ == "__main__":
    unittest.main()
