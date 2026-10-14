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

TOOL_NAMES = ("gau", "nuclei", "ffuf", "subfinder")
MAX_OUTPUT_LINES = 5000


def available_tools() -> dict[str, str | None]:
    return {name: shutil.which(name) for name in TOOL_NAMES}


def build_command(tool: str, target: str, wordlist_path: str | None = None) -> list[str]:
    parsed = urlparse((target or "").strip())
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("target must be a full HTTP(S) URL")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    if tool == "gau":
        return ["gau", "--subs", host]
    if tool == "subfinder":
        # Passive hostname discovery only; this does not probe discovered hosts.
        return ["subfinder", "-silent", "-d", host]
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
             timeout: int = 300, should_stop=None) -> dict:
    """Run one explicit tool without a shell; poll cancellation and bound runtime/output."""
    executable = shutil.which(tool)
    if not executable:
        raise FileNotFoundError(f"{tool} is not installed or is not on PATH")
    args = build_command(tool, target, wordlist_path)
    args[0] = executable
    limit = max(1, min(int(timeout), 900))
    stop = should_stop or (lambda: False)
    process = subprocess.Popen(
        args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", shell=False,
    )
    deadline = __import__("time").monotonic() + limit
    raw_output, timed_out, stopped = "", False, False
    output_truncated = False
    try:
        while True:
            if stop():
                stopped = True
                process.terminate()
                try:
                    raw_output, _ = process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    raw_output, _ = process.communicate()
                break
            remaining = deadline - __import__("time").monotonic()
            if remaining <= 0:
                timed_out = True
                process.kill()
                raw_output, _ = process.communicate()
                break
            try:
                raw_output, _ = process.communicate(timeout=min(1.0, remaining))
                break
            except subprocess.TimeoutExpired as exc:
                output = exc.output or ""
                if isinstance(output, bytes):
                    output = output.decode("utf-8", errors="replace")
                raw_output = output
                if len(raw_output) > 5 * 1024 * 1024:
                    output_truncated = True
                    process.kill()
                    raw_output, _ = process.communicate()
                    break
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if process.stdout:
            process.stdout.close()
    raw_output = str(raw_output or "")
    if len(raw_output.encode("utf-8", errors="replace")) > 5 * 1024 * 1024:
        raw_output = raw_output.encode("utf-8", errors="replace")[:5 * 1024 * 1024].decode("utf-8", errors="ignore")
        output_truncated = True
    lines = raw_output.splitlines()
    truncated = output_truncated or len(lines) > MAX_OUTPUT_LINES
    if len(lines) > MAX_OUTPUT_LINES:
        lines = lines[:MAX_OUTPUT_LINES]
    if timed_out:
        lines.append("[runner] Process timed out and was terminated.")
    if stopped:
        lines.append("[runner] Stopped by user.")
    if truncated:
        lines.append(f"[runner] Output capped (maximum {MAX_OUTPUT_LINES} lines / 5 MiB).")
    return {
        "tool": tool, "target": target, "command": args,
        "return_code": process.returncode if not (timed_out or stopped or truncated) else (
            -2 if stopped else -1 if timed_out else process.returncode
        ),
        "timed_out": timed_out, "stopped": stopped,
        "output_truncated": truncated, "output": lines,
    }
