from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import os
from typing import Optional, List
import uvicorn
import sys
import math
import signal

app = FastAPI(title="ProtonVPN CLI API")


class InitRequest(BaseModel):
    username: str
    password: str
    tier: int
    protocol: Optional[str] = "udp"
    force: Optional[bool] = False


class ConnectRequest(BaseModel):
    server: Optional[str] = None
    protocol: Optional[str] = None
    fastest: Optional[bool] = False
    random: Optional[bool] = False
    country_code: Optional[str] = None
    secure_core: Optional[bool] = False
    p2p: Optional[bool] = False
    tor: Optional[bool] = False
    split_tunnel: Optional[List[str]] = None
    split_tunnel_type: Optional[str] = None


def run_process(command, timeout, check=False):
    """Limit the whole child process group, including inherited output pipes."""
    with subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True,
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
        result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        if check:
            result.check_returncode()
        return result


def run_cli_command(command: List[str], timeout=None) -> dict:
    """Run a protonvpn-cli command and return the result"""
    timeout = timeout or get_timeout("PROTONVPN_COMMAND_TIMEOUT", 120)
    try:
        result = run_process(command, check=True, timeout=timeout)
        return {"success": True, "output": result.stdout}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="VPN command timed out after {}s".format(timeout))
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Could not run VPN command: {}".format(exc))
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Command failed: {e.stderr}")


@app.post("/init")
def initialize(request: InitRequest):
    """Initialize ProtonVPN with credentials"""
    command = ["protonvpn", "init"]

    if request.username:
        command.extend(["--username", request.username])
    if request.password:
        command.extend(["--password", request.password])
    if request.tier:
        command.extend(["--tier", str(request.tier)])
    if request.protocol:
        command.extend(["--protocol", request.protocol])
    if request.force:
        command.append("--force")

    return run_cli_command(command)


@app.post("/connect")
def connect(request: ConnectRequest):
    """Connect to ProtonVPN"""
    command = ["protonvpn", "connect"]

    if request.server:
        command.append(request.server)
    elif request.fastest:
        command.append("--fastest")
    elif request.random:
        command.append("--random")
    elif request.country_code:
        command.extend(["--cc", request.country_code])
    elif request.secure_core:
        command.append("--sc")
    elif request.p2p:
        command.append("--p2p")
    elif request.tor:
        command.append("--tor")

    if request.protocol:
        command.extend(["--protocol", request.protocol])

    if request.split_tunnel:
        command.extend(["--split-tunnel", ",".join(request.split_tunnel)])

    if request.split_tunnel_type:
        command.extend(["--split-tunnel-type", request.split_tunnel_type])

    return run_cli_command(command)


@app.post("/disconnect")
def disconnect():
    """Disconnect from ProtonVPN"""
    return run_cli_command(["protonvpn", "disconnect"])


@app.get("/status")
def status():
    """Get VPN connection status"""
    return run_cli_command(["protonvpn", "status"], get_timeout("PROTONVPN_STATUS_TIMEOUT", 2))


@app.get("/healthz")
def healthz():
    """Check VPN state and outbound connectivity with hard timeouts"""
    timeout = get_health_timeout()
    status_command = ["protonvpn", "status"]

    try:
        status_result = run_process(
            status_command,
            timeout=min(timeout, get_timeout("PROTONVPN_STATUS_TIMEOUT", 2)),
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=503, detail="protonvpn status timed out")
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Could not run protonvpn status: {}".format(exc))

    status_output = status_result.stdout + status_result.stderr
    if status_result.returncode != 0:
        raise HTTPException(
            status_code=503,
            detail=f"protonvpn status failed: {status_output.strip()}",
        )

    if not any(
        line.startswith("Status:") and line.partition(":")[2].strip() == "Connected"
        for line in status_output.splitlines()
    ):
        raise HTTPException(
            status_code=503,
            detail=f"protonvpn status did not report Connected: {status_output.strip()}",
        )

    health_url = os.environ.get(
        "PROTONVPN_HEALTHCHECK_URL", "https://api.ipify.org?format=json"
    )

    try:
        probe = run_process(
            [sys.executable, "-m", "protonvpn_cli.health_probe", health_url, str(timeout)],
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=503, detail="outbound connectivity probe timed out")
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Could not run connectivity probe: {}".format(exc))
    if probe.returncode != 0:
        raise HTTPException(
            status_code=503,
            detail="outbound connectivity probe failed: {}".format(probe.stderr.strip()),
        )

    return {"success": True, "status": "healthy"}


@app.post("/reconnect")
def reconnect():
    """Reconnect to the last server"""
    return run_cli_command(["protonvpn", "reconnect"])


def get_timeout(name, default):
    """Ignore invalid, nonpositive and nonfinite timeout settings."""
    try:
        timeout = float(os.environ.get(name, default))
    except ValueError:
        return default
    return timeout if math.isfinite(timeout) and timeout > 0 else default


def get_health_timeout() -> float:
    return get_timeout("PROTONVPN_HEALTH_TIMEOUT", 10)


def start_api(host: str = "127.0.0.1", port: int = 8000):
    """Start the API server"""
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_api()
