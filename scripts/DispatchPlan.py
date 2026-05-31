#!/usr/bin/env python3
"""Generate Solo dispatch plan for CTF Agents Team.

Usage:
    python3 DispatchPlan.py <competition_dir> [--exp-dir <exp_dir>] [--json]
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

VALID_CATEGORIES = ["web", "pwn", "re", "misc", "crypto", "forensics", "mobile"]
CATEGORY_ALIASES = {"reverse": "re"}
EXP_FILES = {
    "web": "web/web.jsonl",
    "pwn": "pwn/pwn.jsonl",
    "re": "re/re.jsonl",
    "mobile": "re/re.jsonl",
    "misc": "misc/misc.jsonl",
    "crypto": "crypto/crypto.jsonl",
    "forensics": "forensics/forensics.jsonl",
}
TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def _valid_timestamp(value: str) -> bool:
    if not TIMESTAMP_PATTERN.match(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _flag_found_valid(challenge_dir: Path) -> bool:
    path = challenge_dir / "flag.found"
    if not path.is_file():
        return False
    fields = {"FLAG": False, "STATUS": False, "TIMESTAMP": False}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line.startswith("FLAG:") and line[5:].strip():
            fields["FLAG"] = True
        elif line.startswith("STATUS:") and line[7:].strip() == "solved":
            fields["STATUS"] = True
        elif line.startswith("TIMESTAMP:") and _valid_timestamp(line[10:].strip()):
            fields["TIMESTAMP"] = True
    return all(fields.values())


def _find_category_dirs(root: Path) -> tuple[dict[str, list[Path]], list[dict[str, str]]]:
    result = {cat: [] for cat in VALID_CATEGORIES}
    invalid = []
    for item in root.iterdir():
        if not item.is_dir():
            continue
        raw = item.name
        lowered = raw.lower()
        canonical = CATEGORY_ALIASES.get(lowered, lowered)
        if canonical not in result:
            continue
        # Strict lowercase: standard categories must be exact lowercase; alias "reverse" is accepted.
        if raw != lowered:
            invalid.append({"path": str(item), "reason": f"category directory must be lowercase '{canonical}/'"})
            continue
        result[canonical].append(item)
    return result, invalid


def _load_exp_names(exp_dir: Path | None, category: str) -> set[str]:
    if exp_dir is None:
        return set()
    rel = EXP_FILES.get(category)
    if not rel:
        return set()
    path = exp_dir / rel
    if not path.is_file():
        return set()
    names = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if category == "mobile" and rec.get("challenge") != "Mobile":
            continue
        name = rec.get("name")
        if isinstance(name, str):
            names.add(name.lower())
    return names


def _score_challenge(challenge_dir: Path, exp_names: set[str]) -> dict[str, Any]:
    files = [p for p in challenge_dir.rglob("*") if p.is_file()]
    size = sum(p.stat().st_size for p in files if p.exists())
    has_exp = challenge_dir.name.lower() in exp_names
    has_attachment = bool(files)
    score = (100 if has_exp else 0) + (20 if has_attachment else 0) - min(size // 1024, 50)
    return {"score": int(score), "exp_hit": has_exp, "file_count": len(files), "size_bytes": size}


def build_plan(competition_dir: Path, exp_dir: Path | None) -> dict[str, Any]:
    category_dirs, invalid_category_dirs = _find_category_dirs(competition_dir)
    categories = []
    dispatch_agents = []

    for category in VALID_CATEGORIES:
        dirs = category_dirs[category]
        exp_names = _load_exp_names(exp_dir, category)
        discovered = []
        skipped = []
        for cat_dir in dirs:
            for challenge_dir in sorted([p for p in cat_dir.iterdir() if p.is_dir()], key=lambda p: p.name.lower()):
                item = {
                    "name": challenge_dir.name,
                    "path": str(challenge_dir),
                    "category_dir": str(cat_dir),
                }
                if _flag_found_valid(challenge_dir):
                    skipped.append({**item, "reason": "valid flag.found exists"})
                    continue
                discovered.append({**item, **_score_challenge(challenge_dir, exp_names)})

        discovered.sort(key=lambda x: (-x["score"], x["name"].lower()))
        status = "dispatch" if discovered else "skip"
        reason = "has unsolved challenges" if discovered else ("category missing or empty" if not dirs else "no unsolved challenges")
        category_summary = {
            "category": category,
            "status": status,
            "reason": reason,
            "category_dirs": [str(p) for p in dirs],
            "unsolved_count": len(discovered),
            "skipped_count": len(skipped),
            "challenges": discovered,
            "skipped": skipped,
        }
        categories.append(category_summary)

        for idx in range(0, len(discovered), 5):
            batch = discovered[idx:idx + 5]
            if not batch:
                continue
            dispatch_agents.append({
                "agent_name": f"{category}-agent-{idx // 5 + 1}",
                "category": category,
                "time_budget_min": min(len(batch) * 45, 180),
                "challenge_count": len(batch),
                "challenges": batch,
            })

    return {
        "competition_dir": str(competition_dir),
        "exp_dir": str(exp_dir) if exp_dir else None,
        "summary": {
            "dispatch_agent_count": len(dispatch_agents),
            "unsolved_count": sum(c["unsolved_count"] for c in categories),
            "skipped_solved_count": sum(c["skipped_count"] for c in categories),
            "invalid_category_dir_count": len(invalid_category_dirs),
        },
        "invalid_category_dirs": invalid_category_dirs,
        "categories": categories,
        "dispatch_agents": dispatch_agents,
    }


def print_human(plan: dict[str, Any]) -> None:
    print(f"DispatchPlan — {plan['competition_dir']}")
    for cat in plan["categories"]:
        marker = "✓" if cat["status"] == "dispatch" else "-"
        print(f"{marker} {cat['category']}: {cat['unsolved_count']} unsolved, {cat['skipped_count']} skipped ({cat['reason']})")
    if plan.get("invalid_category_dirs"):
        for item in plan["invalid_category_dirs"]:
            print(f"! invalid category dir: {item['path']} ({item['reason']})")
    print(f"agents: {plan['summary']['dispatch_agent_count']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("competition_dir")
    parser.add_argument("--exp-dir")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    competition_dir = Path(args.competition_dir)
    if not competition_dir.is_dir():
        raise SystemExit(f"competition_dir not found: {competition_dir}")
    exp_dir = Path(args.exp_dir) if args.exp_dir else None
    plan = build_plan(competition_dir, exp_dir)
    if args.json:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
    else:
        print_human(plan)


if __name__ == "__main__":
    main()
