#!/usr/bin/env python3
"""Print competition status summary.

Usage:
    python3 status.py <competition_dir> [--json]
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

VALID_CATEGORIES = {"web", "pwn", "re", "misc", "crypto", "forensics", "mobile"}
CATEGORY_ALIASES = {"reverse": "re"}
FLAG_LABEL_TO_CATEGORY = {"web": "web", "pwn": "pwn", "re": "re", "misc": "misc", "crypto": "crypto", "forensics": "forensics", "mobile": "mobile"}
FLAG_LOG_PATTERN = re.compile(r"^\[(\w+)\]\[(.+?)\]\s+(.+)$")


def _has_final_wp(challenge_dir: Path) -> bool:
    expected = challenge_dir / f"{challenge_dir.name}.md"
    if expected.is_file():
        return True
    return any(p.is_file() and p.suffix == ".md" and not p.name.startswith("wp") for p in challenge_dir.iterdir())


def _flag_log_entries(flag_log: Path) -> set[tuple[str, str]]:
    entries: set[tuple[str, str]] = set()
    if not flag_log.is_file():
        return entries
    for line in flag_log.read_text(encoding="utf-8", errors="ignore").splitlines():
        match = FLAG_LOG_PATTERN.match(line.strip())
        if match:
            category = FLAG_LABEL_TO_CATEGORY.get(match.group(1).lower())
            if category:
                entries.add((category, match.group(2).lower()))
    return entries


def build_status(competition_dir: Path) -> dict[str, Any]:
    flag_log_entries = _flag_log_entries(competition_dir / "flag.log")
    categories: dict[str, dict[str, Any]] = {}
    totals = {"challenges": 0, "wp_process": 0, "final_wp": 0, "flag_found": 0, "flag_log": len(flag_log_entries), "exp_candidate": 0, "incomplete": 0}

    for category_dir in sorted([p for p in competition_dir.iterdir() if p.is_dir()], key=lambda p: p.name.lower()):
        raw_category = category_dir.name
        if raw_category != raw_category.lower():
            continue
        category = CATEGORY_ALIASES.get(raw_category, raw_category)
        if category not in VALID_CATEGORIES:
            continue
        cat = categories.setdefault(category, {"category": category, "path": str(category_dir), "counts": {k: 0 for k in totals if k != "flag_log"}, "challenges": []})
        for challenge_dir in sorted([p for p in category_dir.iterdir() if p.is_dir()], key=lambda p: p.name.lower()):
            has_wp_process = (challenge_dir / "wp.process").is_file()
            has_final_wp = _has_final_wp(challenge_dir)
            has_flag_found = (challenge_dir / "flag.found").is_file()
            has_exp_candidate = (challenge_dir / "exp_candidate.jsonl").is_file()
            in_flag_log = (category, challenge_dir.name.lower()) in flag_log_entries
            incomplete = not (has_wp_process and has_final_wp and (has_flag_found or in_flag_log))
            item = {
                "name": challenge_dir.name,
                "path": str(challenge_dir),
                "wp_process": has_wp_process,
                "final_wp": has_final_wp,
                "flag_found": has_flag_found,
                "flag_log": in_flag_log,
                "exp_candidate": has_exp_candidate,
                "status": "complete" if not incomplete else "incomplete",
            }
            cat["challenges"].append(item)
            for key in ("challenges", "wp_process", "final_wp", "flag_found", "exp_candidate", "incomplete"):
                if key == "challenges" or item.get(key):
                    cat["counts"][key] += 1
                    totals[key] += 1

    return {"competition_dir": str(competition_dir), "summary": totals, "categories": list(categories.values())}


def print_human(status: dict[str, Any]) -> None:
    s = status["summary"]
    print(f"Status — {status['competition_dir']}")
    print(f"challenges={s['challenges']} complete={s['challenges'] - s['incomplete']} incomplete={s['incomplete']} flag_found={s['flag_found']} flag_log={s['flag_log']}")
    for cat in status["categories"]:
        c = cat["counts"]
        print(f"{cat['category']}: {c['challenges']} challenges, {c['incomplete']} incomplete")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("competition_dir")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    competition_dir = Path(args.competition_dir)
    if not competition_dir.is_dir():
        raise SystemExit(f"competition_dir not found: {competition_dir}")
    status = build_status(competition_dir)
    if args.json:
        print(json.dumps(status, ensure_ascii=False, indent=2))
    else:
        print_human(status)


if __name__ == "__main__":
    main()
