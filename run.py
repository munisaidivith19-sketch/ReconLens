#!/usr/bin/env python3
"""Run ReconLens locally: backend API + frontend dev server in one command.

    python run.py                 # set up anything missing, start both, open the browser
    python run.py --no-browser    # don't open a browser tab
    python run.py --skip-install  # don't install dependencies even if missing

Press Ctrl+C to stop both servers. Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
API_PORT = 8000
WEB_PORT = 5173
IS_WINDOWS = os.name == "nt"

COLORS = {"api": "\033[36m", "web": "\033[35m", "run": "\033[32m", "err": "\033[31m"}
RESET = "\033[0m"


def log(tag: str, msg: str) -> None:
    print(f"{COLORS.get(tag, '')}[{tag}]{RESET} {msg}", flush=True)


def fail(msg: str) -> None:
    log("err", msg)
    sys.exit(1)


# ---------------------------------------------------------------- checks


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
    return values


def ensure_env_files() -> None:
    """Create .env files from the examples, with a random JWT secret, if they don't exist."""
    backend_env = BACKEND / ".env"
    if not backend_env.exists():
        text = (BACKEND / ".env.example").read_text(encoding="utf-8")
        text = text.replace("JWT_SECRET=\n", f"JWT_SECRET={secrets.token_urlsafe(48)}\n")
        text = text.replace("TRUSTED_PROXY_HOPS=1", "TRUSTED_PROXY_HOPS=0")  # no proxy locally
        backend_env.write_text(text, encoding="utf-8")
        log("run", "Created backend/.env (random JWT_SECRET). Add API keys there for full results.")
    elif len(read_env(backend_env).get("JWT_SECRET", "")) < 32:
        fail("backend/.env has no JWT_SECRET (needs 32+ characters). Add one and try again.")

    frontend_env = FRONTEND / ".env"
    if not frontend_env.exists():
        shutil.copyfile(FRONTEND / ".env.example", frontend_env)
        log("run", "Created frontend/.env")


def check_mongodb() -> None:
    uri = read_env(BACKEND / ".env").get("MONGODB_URI", "mongodb://localhost:27017")
    if uri.startswith("mongodb+srv://"):
        return  # Atlas: the backend health check will report problems
    parts = urlsplit(uri)
    host = (parts.hostname or "localhost").split(",")[0]
    port = parts.port or 27017
    try:
        with socket.create_connection((host, port), timeout=2):
            return
    except OSError:
        hint = "net start MongoDB  (in an administrator terminal)" if IS_WINDOWS else "start mongod"
        fail(f"MongoDB is not reachable at {host}:{port}. Start it first: {hint}")


def find_uv() -> str | None:
    found = shutil.which("uv")
    if found:
        return found
    if IS_WINDOWS:
        appdata = Path(os.environ.get("APPDATA", ""))
        for candidate in appdata.glob("Python/Python3*/Scripts/uv.exe"):
            return str(candidate)
    return None


def venv_python() -> Path:
    return BACKEND / ".venv" / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")


def ensure_backend_deps(skip: bool) -> None:
    if venv_python().exists() or skip:
        return
    log("run", "Installing backend dependencies (first run)...")
    env = {k: v for k, v in os.environ.items() if k != "VIRTUAL_ENV"}
    uv = find_uv()
    if uv:
        subprocess.run([uv, "sync"], cwd=BACKEND, env=env, check=True)
        return
    if sys.version_info < (3, 13):
        fail("Backend needs Python 3.13+. Install uv (https://docs.astral.sh/uv/) or run this with Python 3.13.")
    subprocess.run([sys.executable, "-m", "venv", ".venv"], cwd=BACKEND, check=True)
    subprocess.run([str(venv_python()), "-m", "pip", "install", "-r", "requirements.txt"], cwd=BACKEND, check=True)


def ensure_frontend_deps(npm: str, skip: bool) -> None:
    if (FRONTEND / "node_modules").exists() or skip:
        return
    log("run", "Installing frontend dependencies (first run)...")
    subprocess.run([npm, "ci"], cwd=FRONTEND, check=True)


# ---------------------------------------------------------------- processes


def start(tag: str, cmd: list[str], cwd: Path) -> subprocess.Popen:
    kwargs: dict = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    env = {**os.environ, "PYTHONUNBUFFERED": "1", "FORCE_COLOR": "1"}
    env.pop("VIRTUAL_ENV", None)
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        **kwargs,
    )

    def pump() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            log(tag, line.rstrip())

    threading.Thread(target=pump, daemon=True).start()
    return proc


def stop(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if IS_WINDOWS:
        # Kill the whole tree (npm -> node, uvicorn reloader -> worker).
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
    else:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def wait_for(url: str, procs: list[subprocess.Popen], timeout: float = 90) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(p.poll() is not None for p in procs):
            return False
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:  # noqa: S310 - fixed localhost URL
                if resp.status < 500:
                    return True
        except OSError:
            pass
        time.sleep(0.5)
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Run ReconLens locally.")
    parser.add_argument("--no-browser", action="store_true", help="don't open the browser")
    parser.add_argument("--skip-install", action="store_true", help="don't install missing dependencies")
    args = parser.parse_args()

    # Server output contains Unicode (e.g. Vite's arrows); never crash on a legacy console code page.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if IS_WINDOWS:
        os.system("")  # constant empty command: only enables ANSI colours in the Windows console

    npm = shutil.which("npm")
    if not npm:
        fail("Node.js/npm not found. Install Node.js 22+ from https://nodejs.org")
    for port in (API_PORT, WEB_PORT):
        if port_in_use(port):
            fail(f"Port {port} is already in use. Stop whatever is running there and try again.")

    ensure_env_files()
    check_mongodb()
    ensure_backend_deps(args.skip_install)
    ensure_frontend_deps(npm, args.skip_install)
    if not venv_python().exists():
        fail("backend/.venv is missing. Run without --skip-install.")

    log("run", "Starting backend and frontend... (Ctrl+C to stop)")
    api = start(
        "api",
        [str(venv_python()), "-m", "uvicorn", "app.main:app", "--reload", "--port", str(API_PORT)],
        BACKEND,
    )
    web = start("web", [npm, "run", "dev", "--", "--port", str(WEB_PORT), "--strictPort"], FRONTEND)
    procs = [api, web]

    try:
        api_ok = wait_for(f"http://127.0.0.1:{API_PORT}/api/health", procs)
        web_ok = api_ok and wait_for(f"http://localhost:{WEB_PORT}/", procs)
        if not (api_ok and web_ok):
            log("err", "A server failed to start; see the output above.")
            return
        url = f"http://localhost:{WEB_PORT}"
        log("run", f"ReconLens is running:  {url}   (API: http://localhost:{API_PORT})")
        if not args.no_browser:
            webbrowser.open(url)
        while all(p.poll() is None for p in procs):
            time.sleep(0.5)
        log("err", "A server exited unexpectedly; shutting down.")
    except KeyboardInterrupt:
        print()
        log("run", "Stopping...")
    finally:
        for p in procs:
            stop(p)
        log("run", "Stopped.")


if __name__ == "__main__":
    main()
