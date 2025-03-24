from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import os
from typing import Optional, List
import uvicorn

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
        command.extend(["-p", request.protocol])
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
        command.extend(["-p", request.protocol])

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


@app.post("/reconnect")
async def reconnect():
    """Reconnect to the last server"""
    return run_cli_command(["protonvpn", "reconnect"])


def start_api(host: str = "127.0.0.1", port: int = 8000):
    """Start the API server"""
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_api()
