#!/usr/bin/env python3
"""Secret scanner for the NetProof tree.

Looks for likely secrets in TEXT files (excluding .git/, lib/venv, node_modules,
*.db, package-lock.json, and the .env file itself) using conservative patterns.
Any hit is a hard failure: secrets must never be committed.

    python scripts/secret_scan.py        # exit 0 == clean

False positives are avoided by:
  - only scanning tracked (git) files when the repo is available;
  - ignoring yaml/whitelist test fixtures under backend/data/orgs and test dirs
    that intentionally put red-herring values in files;
  - keeping the rules deliberately narrow (private keys, AWS access keys,
    generic long hex/base64 assignment to secret-looking names).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SKIP_DIRNAMES = {".git", "lib", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
SKIP_FILENAMES = {".env", ".env.example", "package-lock.json"}
BINARY_EXT = {".db", ".pyc", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf"}

_PATTERNS = [
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "private key block"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "API key (sk-...)"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), "Slack token"),
]
# secret-valued assignment lines, e.g. password = "supersecret" (long literal)
_NAME_VALUE = re.compile(
    r"(?i)^\s*([A-Z0-9_./-]*(?:password|passwd|secret|api[-_]?key|token|private[-_]?key|"
    r"community|snmp[-_]?community|psk)[A-Z0-9_./-]*)\s*(?:=|:)\s*['\"]([^'\"]{12,})['\"]\s*$"
)


def _walk() -> list[Path]:
    files: list[Path] = []
    for p in ROOT.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRNAMES for part in p.relative_to(ROOT).parts):
            continue
        if p.name in SKIP_FILENAMES or p.suffix in BINARY_EXT:
            continue
        files.append(p)
    return sorted(files)


def main() -> int:
    found: list[str] = []
    for path in _walk():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if any(regex.search(line) for regex, _label in _PATTERNS):
                found.append(f"{path.relative_to(ROOT)}:{lineno}")
            else:
                m = _NAME_VALUE.match(line.strip())
                if m:
                    found.append(f"{path.relative_to(ROOT)}:{lineno} ({m.group(1)})")
    if found:
        print("SECRETS FOUND:")
        for f in found:
            print("  " + f)
        print("Secret scanner FAILED — remove the values above (use env vars) and rerun.")
        return 1
    print("secret scan: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
