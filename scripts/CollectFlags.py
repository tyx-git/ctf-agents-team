#!/usr/bin/env python3
"""Collect flag.found files into competition flag.log.

Usage:
    python3 CollectFlags.py <competition_dir> [--dry-run] [--json]
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

VALID_CATEGORIES = {"web", "pwn", "re", "misc", "crypto", "forensics", "mobile"}
CATEGORY_LABELS = {"web": "Web", "pwn": "Pwn", "re": "Re", "misc": "Misc", "crypto": "Crypto", "forensics": "Forensics", "mobile": "Mobile"}
CATEGORY_ALIASES = {"reverse": "re"}
FLAG_LOG_PATTERN = re.compile(r"^\[(\w+)\]\[(.+?)\]\s+(.+)$")
TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def _valid_timestamp(value: str) -> bool:
    if not TIMESTAMP_PATTERN.match(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def parse_flag_found(path: Path) -> tuple[dict[str, str] | None, str | None]:
    fields: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip()
    if not fields.get("FLAG"):
        return None, "missing FLAG"
    if fields.get("STATUS") != "solved":
        return None, "STATUS is not solved"
    if not _valid_timestamp(fields.get("TIMESTAMP", "")):
        return None, "invalid TIMESTAMP"
    return fields, None


def _existing_flag_log(flag_log: Path) -> tuple[set[str], list[str]]:
    keys = set()
    lines = []
    if not flag_log.is_file():
        return keys, lines
    for line in flag_log.read_text(encoding="utf-8", errors="ignore").splitlines():
        lines.append(line)
        match = FLAG_LOG_PATTERN.match(line.strip())
        if match:
            keys.add(f"[{match.group(1)}][{match.group(2)}]".lower())
    return keys, lines


def collect(competition_dir: Path, dry_run: bool) -> dict[str, Any]:
    flag_log = competition_dir / "flag.log"
    existing_keys, lines = _existing_flag_log(flag_log)
    found: dict[str, dict[str, Any]] = {}
    invalid = []

    for path in competition_dir.rglob("flag.found"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(competition_dir).parts
        if len(rel_parts) < 3:
            invalid.append({"path": str(path), "reason": "not under category/challenge"})
            continue
        category = CATEGORY_ALIASES.get(rel_parts[0].lower(), rel_parts[0].lower())
        if category not in VALID_CATEGORIES:
            invalid.append({"path": str(path), "reason": "invalid category"})
            continue
        challenge = rel_parts[1]
        fields, error = parse_flag_found(path)
        if error:
            invalid.append({"path": str(path), "reason": error})
            continue
        key = f"[{CATEGORY_LABELS[category]}][{challenge}]"
        current = found.get(key.lower())
        mtime = path.stat().st_mtime
        if current is None or mtime > current["mtime"]:
            found[key.lower()] = {"key": key, "flag": fields["FLAG"], "path": str(path), "mtime": mtime}

    appended = []
    skipped = []
    for item in sorted(found.values(), key=lambda x: x["key"].lower()):
        if item["key"].lower() in existing_keys:
            skipped.append({"key": item["key"], "reason": "already in flag.log", "path": item["path"]})
            continue
        line = f"{item['key']} {item['flag']}"
        appended.append({"line": line, "path": item["path"]})
        lines.append(line)

    if appended and not dry_run:
        flag_log.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

    return {
        "competition_dir": str(competition_dir),
        "flag_log": str(flag_log),
        "dry_run": dry_run,
        "summary": {"appended": len(appended), "skipped": len(skipped), "invalid": len(invalid)},
        "appended": appended,
        "skipped": skipped,
        "invalid": invalid,
    }


def print_human(result: dict[str, Any]) -> None:
    print(f"CollectFlags — {result['competition_dir']}")
    print(f"appended={result['summary']['appended']} skipped={result['summary']['skipped']} invalid={result['summary']['invalid']}")
    for item in result["appended"]:
        print(f"+ {item['line']}")
    for item in result["invalid"]:
        print(f"! {item['path']}: {item['reason']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("competition_dir")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    competition_dir = Path(args.competition_dir)
    if not competition_dir.is_dir():
        raise SystemExit(f"competition_dir not found: {competition_dir}")
    result = collect(competition_dir, args.dry_run)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_human(result)


if __name__ == "__main__":
    main()
