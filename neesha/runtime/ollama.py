"""Local Ollama AI runtime discovery, model selector catalog, installer/puller, and loopback JSON inference."""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any

from neesha.adapters.tool_installer import _safe_subprocess_env, ensure_tool_paths_in_env, find_tool_binary, install_tool
from neesha.runtime.providers import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, MAX_TEXT_CHARS, ProviderError, _NoRedirect

OLLAMA_HOST = "http://127.0.0.1:11434"
OLLAMA_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}\Z")
DEFAULT_OLLAMA_MODEL = "llama3.1:8b"

RECOMMENDED_OLLAMA_MODELS: tuple[dict[str, str], ...] = (
    {
        "id": "llama3.1:8b",
        "label": "Llama 3.1 8B",
        "size": "4.7 GB",
        "specialty": "Balanced OSINT & security posture synthesis (Recommended)",
    },
    {
        "id": "qwen2.5:7b",
        "label": "Qwen 2.5 7B",
        "size": "4.7 GB",
        "specialty": "Structured JSON claims & entity correlation",
    },
    {
        "id": "qwen2.5:14b",
        "label": "Qwen 2.5 14B",
        "size": "9.0 GB",
        "specialty": "High-precision deep technical & posture review",
    },
    {
        "id": "deepseek-r1:8b",
        "label": "DeepSeek R1 8B",
        "size": "4.9 GB",
        "specialty": "Chain-of-thought exposure reasoning & verification",
    },
    {
        "id": "mistral:7b",
        "label": "Mistral 7B v0.3",
        "size": "4.1 GB",
        "specialty": "Fast infrastructure & DNS/TLS triage",
    },
    {
        "id": "gemma2:9b",
        "label": "Gemma 2 9B",
        "size": "5.4 GB",
        "specialty": "Google open-weights evidence summarization",
    },
    {
        "id": "phi4:14b",
        "label": "Phi-4 14B",
        "size": "9.1 GB",
        "specialty": "Compact high-density analytical reasoning",
    },
    {
        "id": "llama3.2:3b",
        "label": "Llama 3.2 3B",
        "size": "2.0 GB",
        "specialty": "Ultra-fast low-memory local laptop synthesis",
    },
)


def valid_ollama_model(model: str) -> str:
    """Validate an Ollama model tag (e.g. 'llama3.1:8b' or 'user/custom-model:latest') against injection."""
    cleaned = (model or "").strip()
    if cleaned.lower().startswith("ollama:"):
        cleaned = cleaned.split(":", 1)[1].strip()
    if (
        not cleaned
        or "://" in cleaned
        or ".." in cleaned
        or cleaned.startswith("/")
        or cleaned.endswith("/")
        or not OLLAMA_MODEL_RE.fullmatch(cleaned)
    ):
        raise ValueError("Enter a valid Ollama model tag (for example, llama3.1:8b or custom-model:latest).")
    return cleaned


def _loopback_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def is_daemon_reachable(timeout: float = 1.0) -> bool:
    """Return True if local Ollama HTTP daemon is listening on 127.0.0.1:11434."""
    try:
        with socket.create_connection(("127.0.0.1", 11434), timeout=timeout):
            return True
    except OSError:
        return False


def ensure_ollama_running(wait_seconds: float = 4.0) -> bool:
    """Start 'ollama serve' in the background if the binary is installed and daemon is not listening."""
    if is_daemon_reachable(timeout=0.8):
        return True
    binary = find_tool_binary("ollama")
    if not binary:
        return False
    try:
        subprocess.Popen(
            [binary, "serve"],
            env=_safe_subprocess_env(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception:
        return False
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if is_daemon_reachable(timeout=0.5):
            return True
        time.sleep(0.25)
    return is_daemon_reachable(timeout=0.5)


def _scan_offline_manifests() -> list[dict[str, Any]]:
    """Discover manually installed models from ~/.ollama/models/manifests even when daemon is stopped."""
    from pathlib import Path
    manifests_root = Path(os.environ.get("OLLAMA_MODELS", str(Path.home() / ".ollama" / "models"))) / "manifests"
    if not manifests_root.is_dir() or manifests_root.is_symlink():
        return []
    found: list[dict[str, Any]] = []
    scanned = 0
    try:
        for tag_file in sorted(manifests_root.rglob("*")):
            scanned += 1
            if scanned > 200:
                break
            if tag_file.is_symlink() or not tag_file.is_file() or tag_file.name.startswith("."):
                continue
            rel = tag_file.relative_to(manifests_root).parts
            # Standard layout: registry.ollama.ai/library/<model>/<tag> or <registry>/<ns>/<model>/<tag>
            if len(rel) >= 4 and rel[0] == "registry.ollama.ai" and rel[1] == "library":
                model_id = f"{rel[2]}:{rel[3]}"
            elif len(rel) >= 4 and rel[0] == "registry.ollama.ai":
                model_id = f"{'/'.join(rel[1:-1])}:{rel[-1]}"
            elif len(rel) >= 3:
                model_id = f"{'/'.join(rel[:-1])}:{rel[-1]}"
            else:
                continue
            if OLLAMA_MODEL_RE.fullmatch(model_id):
                found.append({"id": model_id, "label": model_id, "size": "local", "modified_at": ""})
    except Exception:
        return []
    return found


def list_installed_models(timeout: float = 1.5) -> tuple[bool, list[dict[str, Any]]]:
    """Query GET http://127.0.0.1:11434/api/tags for locally pulled models, with offline manifest fallback."""
    req = urllib.request.Request(
        f"{OLLAMA_HOST}/api/tags",
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with _loopback_opener().open(req, timeout=timeout) as resp:
            if resp.status != 200:
                return False, _scan_offline_manifests()
            raw = resp.read(2 * 1024 * 1024)
            data = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return False, _scan_offline_manifests()

    models_raw = data.get("models") if isinstance(data, dict) else []
    installed: list[dict[str, Any]] = []
    for item in models_raw or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("model") or "").strip()
        if not name or not OLLAMA_MODEL_RE.fullmatch(name):
            continue
        size_bytes = item.get("size") if isinstance(item.get("size"), int) else 0
        size_gb = f"{size_bytes / (1024 ** 3):.1f} GB" if size_bytes else "local"
        installed.append({
            "id": name,
            "label": name,
            "size": size_gb,
            "modified_at": str(item.get("modified_at") or ""),
        })
    return True, installed


def ollama_status(*, start_daemon: bool = False) -> dict[str, Any]:
    """Return full status of the local Ollama installation, daemon, pulled models, and catalog."""
    ensure_tool_paths_in_env()
    binary = find_tool_binary("ollama")
    if start_daemon and binary and not is_daemon_reachable(timeout=0.5):
        ensure_ollama_running(wait_seconds=3.0)

    daemon_up, installed_models = list_installed_models(timeout=1.2)
    installed_ids = {m["id"] for m in installed_models}
    installed_base_ids = {m["id"].split(":")[0] for m in installed_models}

    selected = os.environ.get("NEESHA_OLLAMA_MODEL", "").strip() or DEFAULT_OLLAMA_MODEL
    try:
        selected = valid_ollama_model(selected)
    except ValueError:
        selected = DEFAULT_OLLAMA_MODEL

    catalog: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    rec_by_id = {r["id"]: r for r in RECOMMENDED_OLLAMA_MODELS}

    # 1. Put all locally installed/manually pulled models FIRST so custom models are immediately visible
    for m in installed_models:
        mid = m["id"]
        seen_ids.add(mid)
        rec = rec_by_id.get(mid)
        catalog.append({
            "id": mid,
            "label": rec["label"] if rec else mid,
            "size": m["size"] or (rec["size"] if rec else "local"),
            "specialty": rec["specialty"] if rec else "Manually installed local Ollama model",
            "pulled": True,
        })

    # 2. If the user selected a custom model tag not in installed_models or recommended, include it
    if selected not in seen_ids and selected not in rec_by_id:
        seen_ids.add(selected)
        catalog.append({
            "id": selected,
            "label": selected,
            "size": "custom",
            "specialty": "Custom configured Ollama model tag",
            "pulled": False,
        })

    # 3. Append remaining recommended catalog models
    for rec in RECOMMENDED_OLLAMA_MODELS:
        mid = rec["id"]
        if mid in seen_ids:
            continue
        seen_ids.add(mid)
        pulled = mid in installed_ids or (mid.endswith(":latest") and mid.split(":")[0] in installed_base_ids)
        catalog.append({
            **rec,
            "pulled": pulled,
        })

    selected_pulled = selected in installed_ids or any(
        m["id"] == f"{selected}:latest" for m in installed_models
    )
    ready = bool(binary and (daemon_up or installed_models))

    if not binary:
        reason = "Ollama CLI not installed yet. Click Install Ollama or use the Pre-Install Download Kit."
    elif not daemon_up:
        reason = "Ollama binary installed; daemon will auto-start on model pull or analysis."
    elif not installed_models:
        reason = f"Ollama daemon online. Select a model (e.g. {selected}) and click Pull Model."
    elif selected_pulled:
        reason = f"Local model {selected} pulled and ready for private $0 synthesis."
    else:
        reason = f"Ollama online ({len(installed_models)} local model(s) pulled). Click Pull Model to download {selected}."

    return {
        "installed": bool(binary),
        "binary_path": binary,
        "daemon_running": daemon_up,
        "ready": ready,
        "selected_model": selected,
        "selected_pulled": selected_pulled,
        "installed_models": installed_models,
        "catalog": catalog,
        "reason": reason,
        "endpoint": OLLAMA_HOST,
    }


def pull_ollama_model(model: str) -> dict[str, Any]:
    """Install Ollama if missing, start the daemon if needed, and pull the requested model tag."""
    target_model = valid_ollama_model(model)
    binary = find_tool_binary("ollama")
    if not binary:
        install_res = install_tool("ollama")
        if not install_res.get("installed"):
            raise RuntimeError(install_res.get("message") or "Could not install Ollama automatically.")
        binary = find_tool_binary("ollama")
    if not binary:
        raise RuntimeError("Ollama binary not found after installation.")

    ensure_ollama_running(wait_seconds=4.0)
    try:
        proc = subprocess.run(
            [binary, "pull", target_model],
            env=_safe_subprocess_env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=600,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Pulling {target_model} timed out after 10 minutes.") from None
    except Exception as exc:
        raise RuntimeError(f"Could not run ollama pull: {exc}") from None

    if proc.returncode != 0:
        out = (proc.stdout or "").strip()
        tail = "\n".join(out.splitlines()[-4:]) if out else "ollama pull returned non-zero status."
        raise RuntimeError(f"Ollama pull failed for {target_model}: {tail}")

    os.environ["NEESHA_OLLAMA_MODEL"] = target_model
    status = ollama_status()
    status["pulled_model"] = target_model
    status["message"] = f"Pulled local model {target_model} and set it as active."
    return status


def create_custom_ollama_model(name: str, source: str) -> dict[str, Any]:
    """Import or build a custom local model from a .gguf file, Modelfile path, or base model tag via 'ollama create'."""
    from pathlib import Path
    import tempfile

    raw_name = (name or "").strip()
    if ":" not in raw_name and raw_name:
        raw_name = f"{raw_name}:latest"
    target_name = valid_ollama_model(raw_name)

    raw_source = (source or "").strip()
    if (
        not raw_source
        or len(raw_source) > 512
        or any(ord(c) < 32 or c in ('"', "'", "\x7f") for c in raw_source)
    ):
        raise ValueError("Enter a valid local .gguf path, Modelfile path, or base Ollama model tag.")

    binary = find_tool_binary("ollama")
    if not binary:
        install_res = install_tool("ollama")
        if not install_res.get("installed"):
            raise ValueError(install_res.get("message") or "Install Ollama first before importing a custom model.")
        binary = find_tool_binary("ollama")
    if not binary:
        raise ValueError("Ollama binary not found after installation.")

    ensure_ollama_running(wait_seconds=4.0)

    is_path_like = (
        raw_source.startswith(("/", "~/", "./", "../"))
        or bool(re.match(r"^[A-Za-z]:[\\/]", raw_source))
        or raw_source.lower().endswith((".gguf", ".bin", ".safetensors", "modelfile", ".modelfile"))
    )
    temp_dir = None
    try:
        if is_path_like:
            candidate = Path(raw_source).expanduser()
            lower_name = candidate.name.lower()
            is_modelfile = lower_name == "modelfile" or lower_name.endswith(".modelfile")
            is_weights = candidate.suffix.lower() in (".gguf", ".bin", ".safetensors")
            if not (is_modelfile or is_weights):
                raise ValueError("Local file must be a .gguf/.safetensors weights file or a Modelfile.")
            if candidate.is_symlink():
                raise ValueError("Symbolic links are not permitted for local model imports.")
            resolved = candidate.resolve()
            if any(c in str(resolved) for c in ('"', "'", "\n", "\r")) or not resolved.is_file():
                raise ValueError("Specified local model file or Modelfile was not found.")
            if is_modelfile:
                if resolved.stat().st_size > 65536:
                    raise ValueError("Modelfile exceeds the 64 KiB size limit.")
                mf_text = resolved.read_text(encoding="utf-8", errors="replace")
                for line in mf_text.splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    upper = stripped.upper()
                    if upper.startswith("ADAPTER "):
                        raise ValueError("ADAPTER directives are not permitted in imported Modelfiles.")
                modelfile_path = str(resolved)
            else:
                temp_dir = tempfile.mkdtemp(prefix="find3r-ollama-")
                os.chmod(temp_dir, 0o700)
                mf = Path(temp_dir) / "Modelfile"
                mf.write_text(f'FROM "{resolved}"\nPARAMETER temperature 0.1\n', encoding="utf-8")
                modelfile_path = str(mf)
        else:
            base_model = valid_ollama_model(raw_source)
            temp_dir = tempfile.mkdtemp(prefix="find3r-ollama-")
            os.chmod(temp_dir, 0o700)
            mf = Path(temp_dir) / "Modelfile"
            mf.write_text(f"FROM {base_model}\nPARAMETER temperature 0.1\n", encoding="utf-8")
            modelfile_path = str(mf)

        proc = subprocess.run(
            [binary, "create", target_name, "-f", modelfile_path],
            env=_safe_subprocess_env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise ValueError(f"Creating {target_name} timed out after 5 minutes.") from None
    finally:
        if temp_dir:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    if proc.returncode != 0:
        raise ValueError(f"Ollama create failed for {target_name}. Verify the base model tag or weights file format.")

    os.environ["NEESHA_OLLAMA_MODEL"] = target_name
    status = ollama_status()
    status["created_model"] = target_name
    status["message"] = f"Imported and registered local model {target_name}."
    return status



def _strip_reasoning_wrappers(text: str) -> str:
    """Strip <think>...</think> blocks or markdown fences emitted by local reasoning models."""
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned).strip()
    return cleaned


def generate_ollama(model: str, system: str, payload: Any, timeout: int = 90) -> str:
    """Execute a bounded, text-only JSON synthesis request against local Ollama on 127.0.0.1:11434."""
    target_model = valid_ollama_model(model)
    if not isinstance(system, str) or not system.strip():
        raise ProviderError("A runtime system instruction is required.")
    try:
        user_text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, allow_nan=False)
    except (ValueError, TypeError):
        raise ProviderError("Runtime payload must be JSON serializable.") from None

    ensure_ollama_running(wait_seconds=3.0)
    body = {
        "model": target_model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_text},
        ],
        "format": "json",
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 2048,
        },
    }
    encoded = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(encoded) > MAX_REQUEST_BYTES:
        raise ProviderError("Runtime request exceeded the size limit.")

    request = urllib.request.Request(
        f"{OLLAMA_HOST}/api/chat",
        data=encoded,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    deadline = time.monotonic() + timeout
    response_received = False
    try:
        with _loopback_opener().open(request, timeout=timeout) as response:
            response_received = True
            if response.status != 200:
                raise ProviderError("Local Ollama returned an unsuccessful response.")
            chunks, size = [], 0
            while True:
                if time.monotonic() >= deadline:
                    raise ProviderError("Local Ollama request timed out.")
                chunk = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise ProviderError("Local Ollama response exceeded the size limit.")
                chunks.append(chunk)
            data = json.loads(b"".join(chunks).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        exc.close()
        raise ProviderError(
            f"Local Ollama HTTP request failed (status {status_code}). Ensure model {target_model} is pulled.",
            response_received=False,
            cost_uncertain=False,
        ) from None
    except ProviderError:
        raise
    except Exception:
        raise ProviderError(
            "Local Ollama daemon is unreachable on 127.0.0.1:11434 or returned invalid JSON.",
            response_received=response_received,
            cost_uncertain=False,
        ) from None

    if not isinstance(data, dict) or data.get("error"):
        raise ProviderError("Local Ollama returned an error response.", response_received=False)
    msg = data.get("message")
    content = msg.get("content") if isinstance(msg, dict) else data.get("response")
    if not isinstance(content, str):
        raise ProviderError("Local Ollama returned non-text content.", response_received=False)
    cleaned = _strip_reasoning_wrappers(content)
    if not cleaned or len(cleaned) > MAX_TEXT_CHARS:
        raise ProviderError("Local Ollama returned empty or oversized text.", response_received=False)
    return cleaned
