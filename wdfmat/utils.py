from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
from pathlib import Path
from typing import Any, Iterable


EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"}


def run_powershell(script: str, timeout: int = 60) -> tuple[bool, str]:
    command = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, (result.stdout or result.stderr).strip()
    except Exception as exc:
        return False, str(exc)


def ps_json(script: str, timeout: int = 60) -> list[dict[str, Any]]:
    ok, output = run_powershell(f"{script} | ConvertTo-Json -Depth 6", timeout=timeout)
    if not ok or not output:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return []


def hash_file(path: str | Path, max_bytes: int | None = None) -> dict[str, str]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    read = 0
    with Path(path).open("rb") as handle:
        while True:
            if max_bytes is not None and read >= max_bytes:
                break
            size = 1024 * 1024
            if max_bytes is not None:
                size = min(size, max_bytes - read)
            chunk = handle.read(size)
            if not chunk:
                break
            read += len(chunk)
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def file_metadata(path: str | Path, hash_content: bool = True) -> dict[str, Any]:
    p = Path(path)
    info: dict[str, Any] = {"path": str(p)}
    try:
        stat = p.stat()
        info.update(
            {
                "name": p.name,
                "suffix": p.suffix.lower(),
                "size": stat.st_size,
                "created": stat.st_ctime,
                "modified": stat.st_mtime,
                "accessed": stat.st_atime,
            }
        )
        if hash_content and p.is_file():
            info.update(hash_file(p))
    except Exception as exc:
        info["error"] = str(exc)
    return info


def safe_glob(paths: Iterable[Path], patterns: Iterable[str], limit: int = 5000) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for base in paths:
        if not base.exists():
            continue
        for pattern in patterns:
            try:
                for item in base.rglob(pattern):
                    if len(results) >= limit:
                        return results
                    if item.is_file():
                        results.append(file_metadata(item, hash_content=item.suffix.lower() in EXECUTABLE_EXTENSIONS))
            except Exception:
                continue
    return results


def hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return platform.node() or "unknown-host"


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str), encoding="utf-8")


def csv_dicts(text: str) -> list[dict[str, str]]:
    reader = csv.DictReader(text.splitlines())
    return [dict(row) for row in reader]


def normalize_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().lower()


def is_windows() -> bool:
    return os.name == "nt"
