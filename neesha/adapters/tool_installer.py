"""Cross-platform (Windows, Linux/Ubuntu, macOS) OSINT CLI tool discovery, auto-installer, and pre-install script generator."""
from __future__ import annotations

import glob
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import threading
from typing import Any
import urllib.parse
import urllib.request
import zipfile

from neesha.collectors.network import _default_context

PROJECT_ROOT = Path(__file__).resolve().parents[2]
_ENV_LOCK = threading.Lock()
_MAX_EXTRACTED_BINARY_BYTES = 128 * 1024 * 1024
_ALLOWED_GITHUB_HOSTS = frozenset({
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
})

INSTALLABLE_TOOLS: dict[str, dict[str, str]] = {
    "subfinder": {
        "binary": "subfinder",
        "method": "brew_or_github",
        "package": "subfinder",
        "github_repo": "projectdiscovery/subfinder",
        "description": "Keyless passive subdomain discovery through Subfinder",
    },
    "amass": {
        "binary": "amass",
        "method": "brew_or_github",
        "package": "amass",
        "github_repo": "owasp-amass/amass",
        "description": "OWASP Amass passive subdomain enumeration",
    },
    "sherlock": {
        "binary": "sherlock",
        "method": "brew_or_pip",
        "brew_package": "sherlock",
        "pip_package": "sherlock-project",
        "description": "Username account enumeration via Sherlock",
    },
    "holehe": {
        "binary": "holehe",
        "method": "pip",
        "package": "holehe",
        "description": "Email account registration check via Holehe",
    },
    "socialscan": {
        "binary": "socialscan",
        "method": "pip",
        "package": "socialscan",
        "description": "Email & username registration check via Socialscan",
    },
    "maigret": {
        "binary": "maigret",
        "method": "pip",
        "package": "maigret",
        "description": "Username OSINT profile checker via Maigret",
    },
    "theHarvester": {
        "binary": "theHarvester",
        "method": "brew_or_pip",
        "brew_package": "theharvester",
        "pip_package": "theHarvester",
        "description": "Passive domain/email OSINT via theHarvester",
    },
    "BBOT": {
        "binary": "bbot",
        "method": "pip",
        "package": "bbot",
        "description": "Recursive OSINT & recon scanner (BBOT)",
    },
    "ollama": {
        "binary": "ollama",
        "method": "ollama",
        "package": "ollama",
        "description": "Local AI model runtime for private $0 OSINT synthesis (Ollama)",
    },
}


def detect_os_platform() -> dict[str, str]:
    """Detect current operating system and CPU architecture."""
    sys_plat = sys.platform.lower()
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    if sys_plat.startswith("win") or os.name == "nt":
        return {"os": "windows", "label": "Windows", "arch": arch}
    if sys_plat == "darwin":
        return {"os": "macos", "label": "macOS", "arch": arch}
    return {"os": "linux", "label": "Linux / Ubuntu", "arch": arch}


def _local_venv_bin_dir() -> Path:
    """Return the local .venv binary folder for the current platform."""
    if os.name == "nt" or sys.platform.startswith("win"):
        scripts = PROJECT_ROOT / ".venv" / "Scripts"
        if scripts.is_dir():
            return scripts
    venv_bin = PROJECT_ROOT / ".venv" / "bin"
    if venv_bin.is_dir():
        return venv_bin
    return Path(sys.executable).resolve().parent


def candidate_bin_dirs() -> list[Path]:
    """Return all standard binary directories across Windows, Linux, and macOS."""
    dirs: list[Path] = [
        PROJECT_ROOT / ".venv" / "bin",
        PROJECT_ROOT / ".venv" / "Scripts",
        Path(sys.executable).resolve().parent,
        Path("/opt/homebrew/bin"),
        Path("/usr/local/bin"),
        Path.home() / ".local" / "bin",
        Path.home() / "go" / "bin",
    ]
    # macOS Python Framework & user Library paths
    for p in sorted(glob.glob("/Library/Frameworks/Python.framework/Versions/*/bin"), reverse=True):
        dirs.append(Path(p))
    for p in sorted(glob.glob(str(Path.home() / "Library/Python/*/bin")), reverse=True):
        dirs.append(Path(p))
    # Windows Python Scripts & WinGet / Scoop paths
    local_app = os.environ.get("LOCALAPPDATA", "")
    roaming_app = os.environ.get("APPDATA", "")
    if local_app:
        for p in sorted(glob.glob(os.path.join(local_app, "Programs", "Python", "*", "Scripts")), reverse=True):
            dirs.append(Path(p))
        dirs.append(Path(local_app) / "Microsoft" / "WinGet" / "Links")
    if roaming_app:
        for p in sorted(glob.glob(os.path.join(roaming_app, "Python", "*", "Scripts")), reverse=True):
            dirs.append(Path(p))
    dirs.append(Path.home() / "scoop" / "shims")

    seen: set[str] = set()
    unique: list[Path] = []
    for d in dirs:
        s = str(d)
        if s not in seen and d.is_dir():
            seen.add(s)
            unique.append(d)
    return unique


def ensure_tool_paths_in_env() -> str:
    """Ensure os.environ['PATH'] includes all candidate binary directories without shadowing system binaries."""
    with _ENV_LOCK:
        current = os.environ.get("PATH", "")
        parts = [p for p in current.split(os.pathsep) if p]
        existing = set(parts)
        append = [str(d) for d in candidate_bin_dirs() if str(d) not in existing]
        if append:
            os.environ["PATH"] = os.pathsep.join(parts + append)
        return os.environ.get("PATH", "")


def find_tool_binary(binary_name: str) -> str | None:
    """Locate an external tool binary across PATH and standard Python/Homebrew/Windows locations."""
    ensure_tool_paths_in_env()
    return shutil.which(binary_name)


def _run_install_cmd(args: list[str], timeout: int = 180) -> tuple[bool, str]:
    ensure_tool_paths_in_env()
    try:
        proc = subprocess.run(
            args,
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        out = (proc.stdout or "").strip()
        tail = "\n".join(out.splitlines()[-6:]) if out else ""
        return proc.returncode == 0, tail
    except subprocess.TimeoutExpired:
        return False, "Installation timed out after 180s."
    except Exception as exc:
        return False, str(exc)


def _install_github_release_binary(repo: str, binary_name: str) -> tuple[bool, str]:
    """Download and extract a prebuilt GitHub release zip binary for Windows, Linux, or macOS."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", binary_name):
        return False, f"Invalid binary name {binary_name!r}."
    plat_info = detect_os_platform()
    os_key = plat_info["os"]
    arch = plat_info["arch"]
    os_tokens = {
        "windows": ("windows", "win64", "win"),
        "macos": ("macos", "darwin", "mac"),
        "linux": ("linux",),
    }[os_key]
    arch_tokens = ("arm64", "aarch64") if arch == "arm64" else ("amd64", "x86_64", "64-bit", "64bit")

    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(
        api_url,
        headers={"User-Agent": "NEESHA-Installer/0.2", "Accept": "application/vnd.github+json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20, context=_default_context()) as resp:
            release = json.loads(resp.read(1024 * 1024).decode("utf-8", errors="replace"))
    except Exception as exc:
        return False, f"GitHub release lookup failed: {exc}"

    assets = release.get("assets") if isinstance(release, dict) else []
    download_url = ""
    for asset in assets or []:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name", "")).lower()
        if not name.endswith(".zip"):
            continue
        if any(t in name for t in os_tokens) and any(a in name for a in arch_tokens):
            download_url = str(asset.get("browser_download_url", ""))
            break

    if not download_url:
        return False, f"No prebuilt {os_key}/{arch} zip asset found in {repo}."

    parsed_dl = urllib.parse.urlsplit(download_url)
    if parsed_dl.scheme != "https" or (parsed_dl.hostname or "").lower() not in _ALLOWED_GITHUB_HOSTS:
        return False, f"Refusing untrusted release asset host: {parsed_dl.hostname!r}"

    try:
        dl_req = urllib.request.Request(download_url, headers={"User-Agent": "NEESHA-Installer/0.2"})
        with urllib.request.urlopen(dl_req, timeout=60, context=_default_context()) as dl_resp:
            zip_bytes = dl_resp.read(64 * 1024 * 1024)
        dest_dir = _local_venv_bin_dir()
        dest_dir.mkdir(parents=True, exist_ok=True)
        exe_name = f"{binary_name}.exe" if os_key == "windows" else binary_name
        dest_path = dest_dir / exe_name

        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            matched_member = None
            for member in zf.namelist():
                base = Path(member).name.lower()
                if base in (binary_name.lower(), f"{binary_name.lower()}.exe"):
                    matched_member = member
                    break
            if not matched_member:
                return False, f"Archive from {repo} did not contain {exe_name}."
            info = zf.getinfo(matched_member)
            if info.file_size > _MAX_EXTRACTED_BINARY_BYTES:
                return False, f"Archive member {matched_member} exceeds 128 MiB limit."
            written = 0
            with zf.open(matched_member) as src, dest_path.open("wb") as dst:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > _MAX_EXTRACTED_BINARY_BYTES:
                        raise ValueError("Extracted binary exceeded 128 MiB limit")
                    dst.write(chunk)
        if os_key != "windows":
            dest_path.chmod(0o755)
        return True, f"Installed {binary_name} from GitHub release to {dest_path}"
    except Exception as exc:
        return False, f"Failed extracting {binary_name}: {exc}"


def install_tool(tool_name: str) -> dict[str, Any]:
    """Install a single allowlisted tool or 'all' missing tools across Windows, Linux, or macOS."""
    ensure_tool_paths_in_env()
    plat = detect_os_platform()
    if tool_name == "all":
        results = []
        for name in INSTALLABLE_TOOLS:
            results.append(install_tool(name))
        installed_count = sum(1 for r in results if r.get("installed"))
        return {
            "tool": "all",
            "platform": plat,
            "installed": installed_count == len(results),
            "installed_count": installed_count,
            "total": len(results),
            "results": results,
        }

    spec = INSTALLABLE_TOOLS.get(tool_name)
    if not spec:
        raise ValueError(f"Unknown installable tool {tool_name!r}. Allowed: {', '.join(INSTALLABLE_TOOLS)}")

    binary = spec["binary"]
    existing = find_tool_binary(binary)
    if existing:
        return {
            "tool": tool_name,
            "binary": binary,
            "platform": plat["label"],
            "installed": True,
            "status": "already_installed",
            "path": existing,
            "message": f"{tool_name} is already installed at {existing}.",
        }

    venv_pip = _local_venv_bin_dir() / ("pip.exe" if plat["os"] == "windows" else "pip")
    pip_cmd_prefix = [str(venv_pip)] if venv_pip.is_file() else [sys.executable, "-m", "pip"]
    brew_exe = find_tool_binary("brew")
    winget_exe = find_tool_binary("winget")

    method = spec["method"]
    ok = False
    log_tail = ""

    if method == "pip":
        pkg = spec["package"]
        ok, log_tail = _run_install_cmd(pip_cmd_prefix + ["install", "--upgrade", pkg])
    elif method in ("brew", "brew_or_github"):
        pkg = spec["package"]
        if brew_exe and plat["os"] in ("macos", "linux"):
            ok, log_tail = _run_install_cmd([brew_exe, "install", pkg])
        if not ok and spec.get("github_repo"):
            ok, log_tail = _install_github_release_binary(spec["github_repo"], binary)
        if not ok and plat["os"] == "linux" and shutil.which("apt-get"):
            apt_cmd = [shutil.which("apt-get") or "apt-get", "install", "-y", pkg]
            if hasattr(os, "geteuid") and os.geteuid() != 0 and shutil.which("sudo"):
                apt_cmd = [shutil.which("sudo") or "sudo", "-n"] + apt_cmd
            ok, log_tail = _run_install_cmd(apt_cmd)
        if not ok and plat["os"] == "windows" and winget_exe and pkg == "subfinder":
            ok, log_tail = _run_install_cmd([winget_exe, "install", "--silent", "ProjectDiscovery.Subfinder"])
    elif method == "brew_or_pip":
        if brew_exe and plat["os"] == "macos" and spec.get("brew_package"):
            ok, log_tail = _run_install_cmd([brew_exe, "install", spec["brew_package"]])
        if not ok and spec.get("pip_package"):
            ok, log_tail = _run_install_cmd(pip_cmd_prefix + ["install", "--upgrade", spec["pip_package"]])
    elif method == "ollama":
        if brew_exe and plat["os"] in ("macos", "linux"):
            ok, log_tail = _run_install_cmd([brew_exe, "install", "ollama"])
        elif plat["os"] == "windows" and winget_exe:
            ok, log_tail = _run_install_cmd(
                [winget_exe, "install", "-e", "--id", "Ollama.Ollama", "--accept-package-agreements", "--accept-source-agreements"]
            )
        elif plat["os"] == "linux" and shutil.which("curl"):
            ok, log_tail = _run_install_cmd(["sh", "-c", "curl -fsSL https://ollama.com/install.sh | sh"])

    resolved = find_tool_binary(binary)
    if resolved:
        return {
            "tool": tool_name,
            "binary": binary,
            "platform": plat["label"],
            "installed": True,
            "status": "installed",
            "path": resolved,
            "message": f"Installed {tool_name} on {plat['label']} ({resolved}).",
        }
    return {
        "tool": tool_name,
        "binary": binary,
        "platform": plat["label"],
        "installed": False,
        "status": "failed",
        "message": log_tail or f"Could not install {tool_name} on {plat['label']}.",
    }


def generate_preinstall_script(target_os: str) -> tuple[str, str, str]:
    """Generate a standalone downloadable pre-install script for Windows (.ps1), Linux (.sh), or macOS (.sh)."""
    os_norm = (target_os or "").strip().lower()
    if os_norm in ("win", "windows", "ps1"):
        script = """# Find3r OSINT & Local AI Pre-Installer for Windows (PowerShell)
# Run in PowerShell: Set-ExecutionPolicy Bypass -Scope Process -Force; .\\find3r-preinstall-windows.ps1
$ErrorActionPreference = "Stop"
$OllamaModel = if ($env:FIND3R_OLLAMA_MODEL) { $env:FIND3R_OLLAMA_MODEL } else { "llama3.1:8b" }
Write-Host "=== Find3r OSINT & Local AI Suite Pre-Installer (Windows) ===" -ForegroundColor Cyan

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Python 3.12 via winget..." -ForegroundColor Yellow
    winget install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements
}

if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Ollama Local AI runtime via winget..." -ForegroundColor Yellow
    winget install -e --id Ollama.Ollama --accept-package-agreements --accept-source-agreements
}

if (-not (Test-Path ".venv")) {
    Write-Host "Creating local Python virtual environment (.venv)..." -ForegroundColor Cyan
    python -m venv .venv
}

$Pip = ".\\.venv\\Scripts\\pip.exe"
$Py  = ".\\.venv\\Scripts\\python.exe"
& $Pip install --upgrade pip wheel setuptools
if (Test-Path "pyproject.toml") {
    & $Pip install -e .
}
Write-Host "Installing Python OSINT CLI tools (holehe, socialscan, maigret, sherlock-project, theHarvester, bbot)..." -ForegroundColor Cyan
& $Pip install --upgrade holehe socialscan maigret sherlock-project theHarvester bbot

Write-Host "Downloading Subfinder & Amass Windows binaries into .venv\\Scripts..." -ForegroundColor Cyan
& $Py -c "from neesha.adapters.tool_installer import install_tool; print(install_tool('all'))"

if (Get-Command ollama -ErrorAction SilentlyContinue) {
    Write-Host "Starting Ollama daemon and pulling default local AI model ($OllamaModel)..." -ForegroundColor Cyan
    Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    ollama pull $OllamaModel
}

Write-Host "`nAll Find3r OSINT & Ollama AI pre-install packages are ready! Start with: .\\.venv\\Scripts\\find3r.exe serve" -ForegroundColor Green
"""
        return ("find3r-preinstall-windows.ps1", "text/plain; charset=utf-8", script)

    if os_norm in ("mac", "macos", "darwin", "osx"):
        script = """#!/usr/bin/env bash
# Find3r OSINT & Local AI Pre-Installer for macOS
# Run: chmod +x find3r-preinstall-macos.sh && ./find3r-preinstall-macos.sh
set -euo pipefail
OLLAMA_MODEL="${FIND3R_OLLAMA_MODEL:-llama3.1:8b}"
echo "=== Find3r OSINT & Local AI Suite Pre-Installer (macOS) ==="

if command -v brew >/dev/null 2>&1; then
  echo "[1/4] Installing Subfinder, Amass, Sherlock, theHarvester, and Ollama via Homebrew..."
  brew install subfinder amass sherlock theharvester ollama || true
else
  echo "[1/4] Homebrew not found; Subfinder & Amass will be installed via GitHub macOS binary releases."
fi

if [ ! -d ".venv" ]; then
  echo "[2/4] Creating Python virtual environment (.venv)..."
  python3 -m venv .venv
fi

.venv/bin/pip install --upgrade pip wheel setuptools
if [ -f "pyproject.toml" ]; then
  .venv/bin/pip install -e .
fi

echo "[3/4] Installing Python OSINT CLI tools (holehe, socialscan, maigret, sherlock-project, theHarvester, bbot)..."
.venv/bin/pip install --upgrade holehe socialscan maigret sherlock-project theHarvester bbot
.venv/bin/python -c "from neesha.adapters.tool_installer import install_tool; install_tool('all')" || true

if command -v ollama >/dev/null 2>&1; then
  echo "[4/4] Starting local Ollama daemon and pulling default AI model (${OLLAMA_MODEL})..."
  nohup ollama serve >/dev/null 2>&1 &
  sleep 2
  ollama pull "${OLLAMA_MODEL}" || true
fi

echo ""
echo "Find3r macOS pre-installation (OSINT tools + Ollama ${OLLAMA_MODEL}) complete! Run: .venv/bin/find3r serve"
"""
        return ("find3r-preinstall-macos.sh", "text/x-shellscript; charset=utf-8", script)

    # Default: Linux / Ubuntu / Debian / Kali
    script = """#!/usr/bin/env bash
# Find3r OSINT & Local AI Pre-Installer for Linux (Ubuntu / Debian / Kali)
# Run: chmod +x find3r-preinstall-linux.sh && ./find3r-preinstall-linux.sh
set -euo pipefail
OLLAMA_MODEL="${FIND3R_OLLAMA_MODEL:-llama3.1:8b}"
echo "=== Find3r OSINT & Local AI Suite Pre-Installer (Linux / Ubuntu) ==="

if command -v apt-get >/dev/null 2>&1; then
  echo "[1/5] Installing system dependencies via apt-get..."
  SUDO=""
  [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"
  $SUDO apt-get update -qq
  $SUDO apt-get install -y python3 python3-venv python3-pip git curl unzip ca-certificates dnsutils whois jq zstd
fi

if ! command -v ollama >/dev/null 2>&1; then
  echo "[2/5] Installing Ollama Local AI runtime..."
  curl -fsSL https://ollama.com/install.sh | sh || true
fi

if [ ! -d ".venv" ]; then
  echo "[3/5] Creating Python virtual environment (.venv)..."
  python3 -m venv .venv
fi

.venv/bin/pip install --upgrade pip wheel setuptools
if [ -f "pyproject.toml" ]; then
  .venv/bin/pip install -e .
fi

echo "[4/5] Installing Python OSINT CLI packages (holehe, socialscan, maigret, sherlock-project, theHarvester, bbot)..."
.venv/bin/pip install --upgrade holehe socialscan maigret sherlock-project theHarvester bbot
.venv/bin/python -c "from neesha.adapters.tool_installer import install_tool; install_tool('all')" || true

if command -v ollama >/dev/null 2>&1; then
  echo "[5/5] Starting local Ollama daemon and pulling default AI model (${OLLAMA_MODEL})..."
  nohup ollama serve >/dev/null 2>&1 &
  sleep 2
  ollama pull "${OLLAMA_MODEL}" || true
fi

echo ""
echo "Find3r Linux pre-installation (OSINT tools + Ollama ${OLLAMA_MODEL}) complete! Run: .venv/bin/find3r serve"
"""
    return ("find3r-preinstall-linux.sh", "text/x-shellscript; charset=utf-8", script)
