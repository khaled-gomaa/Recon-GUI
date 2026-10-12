"""Explicit, bounded wrappers for optional command-line recon tools.

The GUI never runs these automatically. Active tools are explicitly selected by the user,
use conservative rates, and require a target entered in the application's scope field.
Arguments are passed without a shell and process runtime is bounded.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

TOOL_NAMES = ("subfinder", "gau", "nuclei", "ffuf")
MAX_OUTPUT_LINES = 5000


def available_tools() -> dict[str, str | None]:
    return {name: shutil.which(name) for name in TOOL_NAMES}


def build_command(tool: str, target: str, wordlist_path: str | None = None) -> list[str]:
    parsed = urlparse((target or "").strip())
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("target must be a full HTTP(S) URL")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    if tool == "subfinder":
        return ["subfinder", "-d", host, "-silent"]
    if tool == "gau":
        return ["gau", "--subs", host]
    if tool == "nuclei":
        return [
            "nuclei", "-u", target, "-jsonl", "-silent",
            "-rate-limit", "2", "-concurrency", "2", "-timeout", "8", "-retries", "0",
        ]
    if tool == "ffuf":
        if not wordlist_path or not Path(wordlist_path).is_file():
            raise ValueError("ffuf requires an existing local wordlist file")
        return [
            "ffuf", "-u", target.rstrip("/") + "/FUZZ", "-w", str(Path(wordlist_path).resolve()),
            "-rate", "2", "-t", "2", "-noninteractive", "-s",
            "-mc", "200,204,301,302,307,401,403",
        ]
    raise ValueError(f"Unsupported tool: {tool}")


def run_tool(tool: str, target: str, wordlist_path: str | None = None,
             timeout: int = 300) -> dict:
    """Run one explicit tool invocation without a shell and cap the captured output."""
    executable = shutil.which(tool)
    if not executable:
        raise FileNotFoundError(f"{tool} is not installed or is not on PATH")
    args = build_command(tool, target, wordlist_path)
    args[0] = executable
    limit = max(1, min(int(timeout), 900))
    try:
        completed = subprocess.run(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", timeout=limit, shell=False,
            check=False,
        )
        code = completed.returncode
        raw_output = completed.stdout or ""
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        code = -1
        raw_output = exc.stdout or ""
        if isinstance(raw_output, bytes):
            raw_output = raw_output.decode("utf-8", errors="replace")
        raw_output += "\n[runner] Process timed out and was terminated."
        timed_out = True
    lines = str(raw_output).splitlines()
    truncated = len(lines) > MAX_OUTPUT_LINES
    if truncated:
        lines = lines[:MAX_OUTPUT_LINES]
        lines.append(f"[runner] Output truncated at {MAX_OUTPUT_LINES} lines.")
    return {
        "tool": tool, "target": target, "command": args,
        "return_code": code, "timed_out": timed_out,
        "output_truncated": truncated, "output": lines,
    }
