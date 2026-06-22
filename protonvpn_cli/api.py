from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import os
from typing import Optional, List
import uvicorn
import requests

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


def run_cli_command(command: List[str]) -> dict:
    """Run a protonvpn-cli command and return the result"""
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return {"success": True, "output": result.stdout}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Command failed: {e.stderr}")


@app.post("/init")
async def initialize(request: InitRequest):
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
async def connect(request: ConnectRequest):
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
async def disconnect():
    """Disconnect from ProtonVPN"""
    return run_cli_command(["protonvpn", "disconnect"])


@app.get("/status")
async def status():
    """Get VPN connection status"""
    return run_cli_command(["protonvpn", "status"])


@app.get("/healthz")
async def healthz():
    """Check VPN state and outbound connectivity with hard timeouts"""
    timeout = get_health_timeout()
    status_command = ["protonvpn", "status"]

    try:
        status_result = subprocess.run(
            status_command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=503, detail="protonvpn status timed out")

    status_output = status_result.stdout + status_result.stderr
    if status_result.returncode != 0:
        raise HTTPException(
            status_code=503,
            detail=f"protonvpn status failed: {status_output.strip()}",
        )

    if not any(
        line.startswith("Status:") and "Connected" in line
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
        response = requests.get(
            health_url,
            headers={"User-Agent": "protonvpn-cli-healthcheck/1.0"},
            timeout=timeout,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=503,
            detail=f"outbound connectivity probe failed: {exc}",
        )

    return {"success": True, "status": "healthy"}


@app.post("/reconnect")
async def reconnect():
    """Reconnect to the last server"""
    return run_cli_command(["protonvpn", "reconnect"])


def get_health_timeout() -> float:
    """Return a positive timeout for bounded health probes."""
    raw_timeout = os.environ.get("PROTONVPN_HEALTH_TIMEOUT", "10")
    try:
        timeout = float(raw_timeout)
    except ValueError:
        return 10
    return timeout if timeout > 0 else 10


def start_api(host: str = "127.0.0.1", port: int = 8000):
    """Start the API server"""
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_api()
