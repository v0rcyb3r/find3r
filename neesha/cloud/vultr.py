"""Vultr API v2 ephemeral Ubuntu VPS manager and remote OSINT execution bridge.

Allows analysts and teammates to spin up disposable Ubuntu 24.04 LTS instances
in randomized Vultr regions with unattributable hostnames, auto-bootstrap the
NEESHA OSINT suite via cloud-init, execute investigations from the remote
Ubuntu IP over SSH, and destroy instances on demand.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from decimal import Decimal
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
from typing import Any
import urllib.error
import urllib.request

from neesha.collectors.network import _default_context
from neesha.config import harden_path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
VULTR_API_BASE = "https://api.vultr.com/v2"

# Curated global Vultr regions for randomized ephemeral placement
VULTR_REGIONS: tuple[dict[str, str], ...] = (
    {"id": "ewr", "city": "New York / NJ", "country": "US"},
    {"id": "ord", "city": "Chicago", "country": "US"},
    {"id": "dfw", "city": "Dallas", "country": "US"},
    {"id": "sea", "city": "Seattle", "country": "US"},
    {"id": "lax", "city": "Los Angeles", "country": "US"},
    {"id": "atl", "city": "Atlanta", "country": "US"},
    {"id": "mia", "city": "Miami", "country": "US"},
    {"id": "yyz", "city": "Toronto", "country": "CA"},
    {"id": "ams", "city": "Amsterdam", "country": "NL"},
    {"id": "fra", "city": "Frankfurt", "country": "DE"},
    {"id": "lhr", "city": "London", "country": "GB"},
    {"id": "cdg", "city": "Paris", "country": "FR"},
    {"id": "mad", "city": "Madrid", "country": "ES"},
    {"id": "waw", "city": "Warsaw", "country": "PL"},
    {"id": "sto", "city": "Stockholm", "country": "SE"},
    {"id": "sgp", "city": "Singapore", "country": "SG"},
    {"id": "nrt", "city": "Tokyo", "country": "JP"},
    {"id": "icn", "city": "Seoul", "country": "KR"},
    {"id": "syd", "city": "Sydney", "country": "AU"},
    {"id": "gru", "city": "Sao Paulo", "country": "BR"},
)

REGION_LABELS = {r["id"]: f"{r['city']} ({r['country']})" for r in VULTR_REGIONS}

# Ubuntu 24.04 LTS x64 OS ID in Vultr API v2 (2284)
DEFAULT_UBUNTU_OS_ID = 2284
DEFAULT_PLAN = "vc2-1c-2gb"
ALLOWED_PLANS = frozenset({"vc2-1c-1gb", "vc2-1c-2gb", "vc2-2c-4gb", "vc2-4c-8gb"})
INSTANCE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{4,64}$")


def _valid_ip(value: Any) -> str:
    """Return canonical global/valid IP string or empty string if invalid/unassigned."""
    if not isinstance(value, str):
        return ""
    candidate = value.strip()
    if not candidate or candidate == "0.0.0.0":
        return ""
    try:
        addr = ipaddress.ip_address(candidate)
        return str(addr)
    except ValueError:
        return ""


def build_ubuntu_cloud_init() -> str:
    """Return a cloud-init bash script that provisions Ubuntu 24.04 with NEESHA & OSINT tools."""
    return """#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# 1. Neutralize hostname and system banner
RAND_HOST="node-$(head -c 4 /dev/urandom | xxd -p 2>/dev/null || echo 'ephemeral')"
hostnamectl set-hostname "$RAND_HOST" || true

# 2. Install base Ubuntu dependencies
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip git curl unzip ca-certificates dnsutils whois jq >/dev/null

# 3. Create isolated worker environment (0700)
mkdir -p /opt/osint-worker
chmod 700 /opt/osint-worker
python3 -m venv /opt/osint-worker/.venv
/opt/osint-worker/.venv/bin/pip install --upgrade pip wheel setuptools -q
/opt/osint-worker/.venv/bin/pip install -q typer rich sqlalchemy alembic pydantic cryptography holehe socialscan maigret sherlock-project theHarvester bbot

# 4. Install prebuilt Subfinder Linux binary
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
  SF_ARCH="amd64"
elif [ "$ARCH" = "aarch64" ]; then
  SF_ARCH="arm64"
else
  SF_ARCH="amd64"
fi
SF_URL=$(curl -fsSL https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | jq -r ".assets[] | select(.name | test(\"linux_${SF_ARCH}.zip$\")) | .browser_download_url" | head -n 1 || true)
if [ -n "$SF_URL" ]; then
  curl -fsSL "$SF_URL" -o /tmp/subfinder.zip && unzip -o /tmp/subfinder.zip subfinder -d /usr/local/bin/ && chmod +x /usr/local/bin/subfinder && rm -f /tmp/subfinder.zip || true
fi

# 5. Symlink CLI tools into /usr/local/bin so PATH always resolves them
for bin in holehe socialscan maigret sherlock theHarvester bbot; do
  if [ -x "/opt/osint-worker/.venv/bin/$bin" ]; then
    ln -sf "/opt/osint-worker/.venv/bin/$bin" "/usr/local/bin/$bin"
  fi
done

touch /opt/osint-worker/.bootstrap_complete
"""


class VultrError(ValueError):
    """Sanitized Vultr provisioning or API error."""


class VultrManager:
    """Manages ephemeral Vultr Ubuntu VPS workers and SSH execution."""

    def __init__(self, config_dir: Path | None = None) -> None:
        self.config_dir = config_dir or (PROJECT_ROOT / "config")
        self.state_path = self.config_dir / "vultr-nodes.json"
        self.ssh_dir = self.config_dir / "ssh"
        self.private_key_path = self.ssh_dir / "vultr_ephemeral_ed25519"
        self.public_key_path = self.ssh_dir / "vultr_ephemeral_ed25519.pub"
        self.known_hosts_path = self.ssh_dir / "known_hosts"
        self._lock = threading.RLock()

    @property
    def api_key(self) -> str:
        return os.environ.get("VULTR_API_KEY", "").strip()

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _load_state(self) -> dict[str, Any]:
        with self._lock:
            if not self.state_path.exists():
                return {"active_node_id": "local", "nodes": {}, "ssh_key_id": None}
            try:
                data = json.loads(self.state_path.read_text())
                if isinstance(data, dict):
                    data.setdefault("active_node_id", "local")
                    data.setdefault("nodes", {})
                    return data
            except Exception:
                pass
            return {"active_node_id": "local", "nodes": {}, "ssh_key_id": None}

    def _save_state(self, state: dict[str, Any]) -> None:
        with self._lock:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            harden_path(self.config_dir)
            tmp = self.state_path.with_name(f"{self.state_path.name}.{secrets.token_hex(4)}.tmp")
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(state, indent=2) + "\n")
            tmp.replace(self.state_path)
            harden_path(self.state_path)

    def ensure_local_ssh_keypair(self) -> str:
        """Generate an ephemeral local Ed25519 SSH keypair if not present."""
        with self._lock:
            self.ssh_dir.mkdir(parents=True, exist_ok=True)
            harden_path(self.ssh_dir)
            if not self.private_key_path.exists() or not self.public_key_path.exists():
                for p in (self.private_key_path, self.public_key_path):
                    if p.exists():
                        p.unlink()
                ssh_keygen = "/usr/bin/ssh-keygen" if Path("/usr/bin/ssh-keygen").is_file() else (shutil.which("ssh-keygen") or "ssh-keygen")
                subprocess.run(
                    [
                        ssh_keygen,
                        "-t",
                        "ed25519",
                        "-N",
                        "",
                        "-C",
                        "ephemeral-worker",
                        "-f",
                        str(self.private_key_path),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=True,
                    timeout=15,
                )
                harden_path(self.private_key_path)
            return self.public_key_path.read_text().strip()

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        timeout: int = 20,
    ) -> tuple[int, Any]:
        if not self.api_key:
            raise VultrError("VULTR_API_KEY is not configured. Add it in Settings & API Keys.")
        url = VULTR_API_BASE + path
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CloudProvisioner/1.0",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=_default_context()) as resp:
                raw = resp.read(1024 * 1024)
                if not raw:
                    return resp.status, {}
                return resp.status, json.loads(raw.decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            err_msg = f"Vultr API returned HTTP {exc.code}"
            try:
                err_body = json.loads(exc.read(65536).decode("utf-8", errors="replace"))
                if isinstance(err_body, dict) and isinstance(err_body.get("error"), str):
                    err_msg = f"Vultr API: {err_body['error'][:200]}"
            except Exception:
                pass
            raise VultrError(err_msg) from None
        except Exception:
            raise VultrError("Could not reach Vultr API. Verify network connectivity and VULTR_API_KEY.") from None

    def _ensure_vultr_ssh_key(self, state: dict[str, Any]) -> str:
        pub_key = self.ensure_local_ssh_keypair()
        _, data = self._request("GET", "/ssh-keys")
        for key_obj in (data.get("ssh_keys") or []) if isinstance(data, dict) else []:
            if isinstance(key_obj, dict) and key_obj.get("ssh_key", "").strip() == pub_key:
                state["ssh_key_id"] = str(key_obj["id"])
                return str(key_obj["id"])
        _, created = self._request(
            "POST",
            "/ssh-keys",
            {"name": f"ephemeral-{secrets.token_hex(3)}", "ssh_key": pub_key},
        )
        key_id = created.get("ssh_key", {}).get("id") if isinstance(created, dict) else None
        if not key_id:
            raise VultrError("Failed to register ephemeral SSH key with Vultr.")
        state["ssh_key_id"] = str(key_id)
        return str(key_id)

    def list_nodes(self, sync_remote: bool = True) -> dict[str, Any]:
        """Return current Vultr configuration, regions, active node, and ephemeral instances."""
        with self._lock:
            state = self._load_state()
            nodes_map: dict[str, dict[str, Any]] = dict(state.get("nodes") or {})

            if self.is_configured() and sync_remote:
                try:
                    _, data = self._request("GET", "/instances")
                    remote_instances = (data.get("instances") or []) if isinstance(data, dict) else []
                    remote_by_id = {
                        str(inst["id"]): inst
                        for inst in remote_instances
                        if isinstance(inst, dict) and inst.get("id") and INSTANCE_ID_RE.fullmatch(str(inst["id"]))
                    }
                    for inst_id, inst in remote_by_id.items():
                        tags = inst.get("tags") or []
                        if inst_id in nodes_map or "ephemeral-worker" in tags:
                            region_id = str(inst.get("region", ""))
                            ip = _valid_ip(inst.get("main_ip", ""))
                            nodes_map[inst_id] = {
                                "id": inst_id,
                                "label": str(inst.get("label") or f"node-{inst_id[:8]}"),
                                "region": region_id,
                                "region_name": REGION_LABELS.get(region_id, region_id.upper()),
                                "ip": ip,
                                "status": str(inst.get("status", "pending")),
                                "power_status": str(inst.get("power_status", "running")),
                                "server_status": str(inst.get("server_status", "installing")),
                                "plan": str(inst.get("plan", DEFAULT_PLAN)),
                                "os": str(inst.get("os", "Ubuntu 24.04 LTS x64")),
                                "created_at": str(inst.get("date_created") or datetime.now(timezone.utc).isoformat()),
                                "ssh_command": (
                                    f"ssh -o StrictHostKeyChecking=accept-new -i {self.private_key_path} root@{ip}"
                                    if ip
                                    else "Waiting for public IPv4 assignment…"
                                ),
                            }
                    for old_id in list(nodes_map):
                        if old_id not in remote_by_id:
                            nodes_map.pop(old_id, None)
                    state["nodes"] = nodes_map
                    if state.get("active_node_id") != "local" and state.get("active_node_id") not in nodes_map:
                        state["active_node_id"] = "local"
                    self._save_state(state)
                except VultrError:
                    pass

            nodes_list = sorted(
                nodes_map.values(),
                key=lambda x: str(x.get("created_at", "")),
                reverse=True,
            )
            return {
                "configured": self.is_configured(),
                "active_node_id": state.get("active_node_id", "local"),
                "nodes": nodes_list,
                "regions": list(VULTR_REGIONS),
                "ssh_key_path": str(self.private_key_path),
            }

    def spin_up_node(
        self,
        region: str = "random",
        plan: str = DEFAULT_PLAN,
        auto_select: bool = True,
    ) -> dict[str, Any]:
        """Spin up a new Ubuntu 24.04 VPS in a randomized (or chosen) Vultr region."""
        with self._lock:
            if not self.is_configured():
                raise VultrError("Configure VULTR_API_KEY in Settings & API Keys before spinning up a VPS.")

            valid_regions = [r["id"] for r in VULTR_REGIONS]
            chosen_region = (
                secrets.choice(valid_regions)
                if not region or region == "random" or region not in valid_regions
                else region
            )
            chosen_plan = plan if plan in ALLOWED_PLANS else DEFAULT_PLAN

            state = self._load_state()
            ssh_key_id = self._ensure_vultr_ssh_key(state)

            anon_token = secrets.token_hex(4)
            anon_hostname = f"node-{anon_token}.local"
            user_data_b64 = base64.b64encode(build_ubuntu_cloud_init().encode("utf-8")).decode("ascii")

            create_payload = {
                "region": chosen_region,
                "plan": chosen_plan,
                "os_id": DEFAULT_UBUNTU_OS_ID,
                "label": f"worker-{anon_token}",
                "hostname": anon_hostname,
                "sshkey_id": [ssh_key_id],
                "user_data": user_data_b64,
                "backups": "disabled",
                "ddos_protection": False,
                "enable_ipv6": False,
                "tags": ["ephemeral-worker"],
            }
            _, resp = self._request("POST", "/instances", create_payload)
            inst = resp.get("instance") if isinstance(resp, dict) else None
            if not isinstance(inst, dict) or not inst.get("id"):
                raise VultrError("Vultr did not return an instance ID.")

            inst_id = str(inst["id"])
            if not INSTANCE_ID_RE.fullmatch(inst_id):
                raise VultrError("Vultr returned an unexpected instance ID format.")
            ip = _valid_ip(inst.get("main_ip") or "")
            node_info = {
                "id": inst_id,
                "label": str(inst.get("label") or f"worker-{anon_token}"),
                "hostname": anon_hostname,
                "region": chosen_region,
                "region_name": REGION_LABELS.get(chosen_region, chosen_region.upper()),
                "ip": ip,
                "status": str(inst.get("status", "pending")),
                "power_status": str(inst.get("power_status", "running")),
                "server_status": str(inst.get("server_status", "installing")),
                "plan": chosen_plan,
                "os": "Ubuntu 24.04 LTS x64",
                "created_at": str(inst.get("date_created") or datetime.now(timezone.utc).isoformat()),
                "ssh_command": (
                    f"ssh -o StrictHostKeyChecking=accept-new -i {self.private_key_path} root@{ip}"
                    if ip
                    else "Waiting for public IPv4 assignment…"
                ),
            }
            state.setdefault("nodes", {})[inst_id] = node_info
            if auto_select:
                state["active_node_id"] = inst_id
            self._save_state(state)
            return {
                "created": node_info,
                "cloud": self.list_nodes(sync_remote=False),
            }

    def destroy_node(self, instance_id: str) -> dict[str, Any]:
        """Destroy a single tracked Vultr instance or 'all' tracked ephemeral instances."""
        with self._lock:
            if not self.is_configured():
                raise VultrError("VULTR_API_KEY is not configured.")
            state = self._load_state()
            nodes_map = dict(state.get("nodes") or {})

            if instance_id == "all":
                target_ids = list(nodes_map.keys())
            else:
                if not INSTANCE_ID_RE.fullmatch(str(instance_id or "")) or instance_id not in nodes_map:
                    raise VultrError("Instance ID is not a tracked ephemeral Vultr node.")
                target_ids = [instance_id]

            destroyed: list[str] = []
            for tid in target_ids:
                if not tid or tid == "local" or not INSTANCE_ID_RE.fullmatch(tid):
                    continue
                try:
                    self._request("DELETE", f"/instances/{tid}")
                except VultrError:
                    pass
                nodes_map.pop(tid, None)
                destroyed.append(tid)
                if state.get("active_node_id") == tid:
                    state["active_node_id"] = "local"

            state["nodes"] = nodes_map
            self._save_state(state)
            return {
                "destroyed": destroyed,
                "cloud": self.list_nodes(sync_remote=False),
            }

    def select_node(self, node_id: str) -> dict[str, Any]:
        """Select 'local' or an active Vultr node ID as the active investigation runner."""
        with self._lock:
            state = self._load_state()
            if node_id != "local" and node_id not in (state.get("nodes") or {}):
                raise VultrError("Selected cloud node was not found.")
            state["active_node_id"] = node_id
            self._save_state(state)
            return self.list_nodes(sync_remote=False)

    def rotate_node(self, region: str = "random") -> dict[str, Any]:
        """Spin up a fresh Ubuntu VPS in a random region and destroy previous ephemeral nodes."""
        with self._lock:
            state = self._load_state()
            old_ids = list((state.get("nodes") or {}).keys())
            spun = self.spin_up_node(region=region, auto_select=True)
            for old_id in old_ids:
                if old_id != spun["created"]["id"]:
                    try:
                        self.destroy_node(old_id)
                    except Exception:
                        pass
            return self.list_nodes(sync_remote=True)

    def get_active_remote_node(self) -> dict[str, Any] | None:
        """Return the active remote node dict if execution is set to a remote Vultr VPS."""
        state = self._load_state()
        active_id = state.get("active_node_id", "local")
        if not active_id or active_id == "local":
            return None
        info = self.list_nodes(sync_remote=True)
        for n in info.get("nodes", []):
            if n.get("id") == active_id:
                return n
        return None

    def execute_remote_investigation(
        self,
        *,
        engine,
        node: dict[str, Any],
        target: str,
        subject_kind: str,
        engagement_id: str,
        run_id: str,
        contacts: bool = False,
        website: bool = True,
        progress_cb=None,
    ) -> dict[str, Any]:
        """Sync NEESHA code to the Ubuntu VPS, run the scan from the VPS IP, and import rows into local SQLite."""
        import sqlalchemy as sa
        from neesha.db import schema

        ip = _valid_ip(node.get("ip") or "")
        if not ip:
            raise VultrError("Selected Vultr VPS does not have a valid IPv4 address yet. Wait ~30s and click Sync.")
        if not self.private_key_path.exists():
            raise VultrError("Local ephemeral SSH key is missing.")

        self.ssh_dir.mkdir(parents=True, exist_ok=True)
        harden_path(self.ssh_dir)

        ssh_exe = "/usr/bin/ssh" if Path("/usr/bin/ssh").is_file() else (shutil.which("ssh") or "ssh")
        ssh_base = [
            ssh_exe,
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            f"UserKnownHostsFile={self.known_hosts_path}",
            "-o",
            "ConnectTimeout=12",
            "-o",
            "BatchMode=yes",
            "-i",
            str(self.private_key_path),
            f"root@{ip}",
        ]

        if progress_cb:
            progress_cb({"current_source": f"vultr-vps ({ip} · {node.get('region_name', '')}) connecting", "completed": 0, "total": 3})

        with tempfile.TemporaryDirectory() as tmpdir:
            tar_path = Path(tmpdir) / "neesha_bundle.tar.gz"
            with tarfile.open(tar_path, "w:gz") as tf:
                for rel in ("neesha", "migrations", "alembic.ini", "pyproject.toml"):
                    p = PROJECT_ROOT / rel
                    if p.exists():
                        tf.add(p, arcname=rel, filter=lambda ti: None if "__pycache__" in ti.name or ti.name.endswith(".pyc") else ti)

            ready = False
            for _ in range(18):
                probe = subprocess.run(
                    ssh_base + ["test -x /opt/osint-worker/.venv/bin/python && echo READY || echo BOOTSTRAPPING"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=15,
                    check=False,
                )
                if "READY" in (probe.stdout or ""):
                    ready = True
                    break
                if progress_cb:
                    progress_cb({"current_source": f"vultr-vps ({ip}) finishing Ubuntu cloud-init setup…", "completed": 0, "total": 3})
                time.sleep(5)

            if not ready:
                raise VultrError(f"Vultr VPS ({ip}) is still bootstrapping Ubuntu packages. Wait 30–60 seconds and retry.")

            if progress_cb:
                progress_cb({"current_source": f"vultr-vps ({ip}) syncing runner bundle", "completed": 1, "total": 3})

            with tar_path.open("rb") as f_in:
                sync_proc = subprocess.run(
                    ssh_base + ["mkdir -p /opt/osint-worker/app && chmod 700 /opt/osint-worker && tar -xzf - -C /opt/osint-worker/app"],
                    stdin=f_in,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=45,
                    check=False,
                )
                if sync_proc.returncode != 0:
                    raise VultrError(f"Failed to sync runner bundle to VPS {ip}.")

            if progress_cb:
                progress_cb({"current_source": f"vultr-vps ({ip}) running OSINT sensors on Ubuntu VPS", "completed": 2, "total": 3})

            params_b64 = base64.b64encode(
                json.dumps(
                    {
                        "target": target,
                        "subject_kind": subject_kind,
                        "run_id": run_id,
                        "engagement_id": engagement_id,
                        "contacts": bool(contacts),
                        "website": bool(website),
                    }
                ).encode("utf-8")
            ).decode("ascii")

            remote_py = f"""
import base64, json, os, sys
sys.path.insert(0, '/opt/osint-worker/app')
import sqlalchemy as sa
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from neesha.db import schema
from neesha.ledger.ledger import Ledger
from neesha.harness.gate import EngagementView, PolicyGate, RunCaps
from neesha.harness.run import execute_run
from neesha.adapters import registry

params = json.loads(base64.b64decode({params_b64!r}).decode('utf-8'))
target = params['target']
subject_kind = params['subject_kind']
run_id = params['run_id']
eng_id = params['engagement_id']
contacts = params['contacts']
website = params['website']

db_file = f'/opt/osint-worker/run_{{run_id}}.sqlite3'
try:
    engine = sa.create_engine('sqlite:///' + db_file)
    schema.metadata.create_all(engine)
    ledger = Ledger(engine)
    ledger.set_cap(Decimal('100.00'))
    now = datetime.now(timezone.utc)
    is_personal = subject_kind in ('email', 'username')
    eng = EngagementView(
        id=eng_id,
        authority_basis='public_research' if is_personal else 'prospect_company',
        authorized_domains=() if is_personal else (target,),
        authorized_emails=(target,) if subject_kind == 'email' else (),
        authorized_usernames=(target,) if subject_kind == 'username' else (),
        permitted_techniques=frozenset({{'account_enumeration'}}) if is_personal else frozenset(),
        starts_at=now - timedelta(hours=1),
        expires_at=now + timedelta(days=1),
    )
    with engine.begin() as c:
        c.execute(schema.engagement.insert().values(
            id=eng_id,
            authority_basis=eng.authority_basis,
            authorized_domains=list(eng.authorized_domains),
            authorized_emails=list(eng.authorized_emails),
            authorized_usernames=list(eng.authorized_usernames),
            permitted_techniques=list(eng.permitted_techniques),
            authorized_by='vultr-ephemeral-worker',
            starts_at=eng.starts_at,
            expires_at=eng.expires_at,
            created_at=now,
        ))
    allowed_tiers = {{'A', 'B', 'C'}} if contacts else {{'A', 'C'}}
    sources = {{s['name'] for s in registry.catalog() if s['integrated'] and s['ready'] and s['tier'] in allowed_tiers and subject_kind in registry.get(s['name']).accepts}}
    if not website:
        sources.discard('company-web')
    pirs = (
        ('email-public-presence', 'email-account-presence') if subject_kind == 'email' else
        (('username-account-presence',) if subject_kind == 'username' else
        (('ip-infrastructure', 'whois-registration') if subject_kind == 'ip' else
        ('attack-surface', 'company-contacts', 'email-posture', 'public-history', 'web-response', 'tool-discovery', 'whois-registration', 'ip-infrastructure')))
    )
    rep = execute_run(
        engine=engine,
        ledger=ledger,
        gate=PolicyGate(engine, ledger),
        company=target,
        engagement=eng,
        analyst='vultr-vps',
        pir_templates=pirs,
        tiers=allowed_tiers,
        sources=sources,
        subject_kind=subject_kind,
        run_id=run_id,
        parallel=True,
    )
    with engine.connect() as c:
        srs = []
        for r in c.execute(sa.select(schema.source_record)).mappings():
            d = dict(r)
            d['raw_payload_b64'] = base64.b64encode(d.pop('raw_payload') or b'').decode('ascii')
            srs.append(d)
        dump = {{
            'entities': [dict(r) for r in c.execute(sa.select(schema.entity)).mappings()],
            'source_records': srs,
            'facts': [dict(r) for r in c.execute(sa.select(schema.fact)).mappings()],
            'pirs': [dict(r) for r in c.execute(sa.select(schema.pir)).mappings()],
            'query_logs': [dict(r) for r in c.execute(sa.select(schema.query_log)).mappings()],
            'run': dict(c.execute(sa.select(schema.run).where(schema.run.c.id == run_id)).mappings().one()),
            'facts_written': rep.facts_written,
            'steps_count': len(rep.steps),
            'skipped_count': len(rep.skipped),
        }}
    print('===NEESHA_REMOTE_DUMP===')
    print(json.dumps(dump, default=str))
finally:
    if os.path.exists(db_file):
        os.remove(db_file)
"""
            script_b64 = base64.b64encode(remote_py.encode("utf-8")).decode("ascii")
            safe_remote_cmd = f"/opt/osint-worker/.venv/bin/python -c {shlex.quote(f'import base64; exec(base64.b64decode({script_b64!r}).decode())')}"
            exec_proc = subprocess.run(
                ssh_base + [safe_remote_cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=240,
                check=False,
            )
            stdout = exec_proc.stdout or ""
            if "===NEESHA_REMOTE_DUMP===" not in stdout:
                raise VultrError(f"Remote VPS investigation on {ip} did not complete. Check VPS status and retry.")
            dump = json.loads(stdout.split("===NEESHA_REMOTE_DUMP===", 1)[1].strip())

        def _dt(val):
            if not val or not isinstance(val, str):
                return datetime.now(timezone.utc)
            try:
                return datetime.fromisoformat(val)
            except Exception:
                return datetime.now(timezone.utc)

        entity_id_map: dict[str, str] = {}
        with engine.begin() as conn:
            # 1. Insert/reconcile entities (root entities with company_id=None first)
            entities_sorted = sorted(dump.get("entities", []), key=lambda e: 0 if e.get("company_id") is None else 1)
            for ent in entities_sorted:
                old_id = ent["id"]
                if ent.get("company_id") in entity_id_map:
                    ent["company_id"] = entity_id_map[ent["company_id"]]
                ent["first_seen_at"] = _dt(ent.get("first_seen_at"))
                ent["last_seen_at"] = _dt(ent.get("last_seen_at"))
                existing_id = conn.execute(
                    sa.select(schema.entity.c.id).where(
                        schema.entity.c.kind == ent["kind"],
                        schema.entity.c.canonical_name == ent["canonical_name"],
                        schema.entity.c.company_id.is_(None)
                        if ent.get("company_id") is None
                        else (schema.entity.c.company_id == ent.get("company_id")),
                    )
                ).scalar()
                if existing_id:
                    entity_id_map[old_id] = existing_id
                else:
                    conn.execute(schema.entity.insert().values(**ent))
                    entity_id_map[old_id] = old_id

            # 2. Insert run row (before source_record, fact, and pir)
            r_row = dump["run"]
            r_row["company_id"] = entity_id_map.get(r_row["company_id"], r_row["company_id"])
            r_row["analyst"] = f"vultr-vps:{ip}"
            r_row["started_at"] = _dt(r_row.get("started_at"))
            r_row["ended_at"] = _dt(r_row.get("ended_at"))
            r_row["max_spend_usd"] = Decimal(str(r_row.get("max_spend_usd", "1.00")))
            conn.execute(schema.run.insert().values(**r_row))

            # 3. Insert source_record rows
            for sr in dump.get("source_records", []):
                raw_b64 = sr.pop("raw_payload_b64", "")
                sr["raw_payload"] = base64.b64decode(raw_b64) if raw_b64 else b""
                sr["collected_at"] = _dt(sr.get("collected_at"))
                sr["retention_expires_at"] = _dt(sr.get("retention_expires_at"))
                conn.execute(schema.source_record.insert().values(**sr))

            # 4. Insert fact rows
            for fct in dump.get("facts", []):
                fct["entity_id"] = entity_id_map.get(fct["entity_id"], fct["entity_id"])
                fct["observed_at"] = _dt(fct.get("observed_at"))
                fct["retention_expires_at"] = _dt(fct.get("retention_expires_at"))
                conn.execute(schema.fact.insert().values(**fct))

            # 5. Insert pir rows
            for pr in dump.get("pirs", []):
                conn.execute(schema.pir.insert().values(**pr))

            # 6. Insert query_log rows
            for ql in dump.get("query_logs", []):
                ql.pop("id", None)
                ql["occurred_at"] = _dt(ql.get("occurred_at"))
                if ql.get("estimated_usd") is not None:
                    ql["estimated_usd"] = Decimal(str(ql["estimated_usd"]))
                if ql.get("actual_usd") is not None:
                    ql["actual_usd"] = Decimal(str(ql["actual_usd"]))
                conn.execute(schema.query_log.insert().values(**ql))

        return {
            "run_id": run_id,
            "facts_written": dump.get("facts_written", 0),
            "steps_count": dump.get("steps_count", 0),
            "skipped_count": dump.get("skipped_count", 0),
            "node_ip": ip,
            "node_region": node.get("region_name", ""),
        }
