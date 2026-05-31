#!/usr/bin/env python3
"""清理所有题目目录下的 exp_candidate.jsonl 文件，并扫描凭据泄露。

Lead Agent 完成经验库合并后执行此脚本，遍历比赛目录并删除所有
exp_candidate.jsonl 中间文件，避免残留。同时扫描残留的 token 模式并告警。

用法:
    python3 ClearExp.py <比赛目录路径>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

TOKEN_PATTERNS = [
    re.compile(r"ctfd_[a-zA-Z0-9]{20,}", re.IGNORECASE),
    re.compile(r"token[\"']?\s*[:=]\s*[\"']?[^\"'\s,}]{8,}", re.IGNORECASE),
    re.compile(r"api[_-]?key[\"']?\s*[:=]\s*[\"']?[^\"'\s,}]{8,}", re.IGNORECASE),
    re.compile(r"session[\"']?\s*[:=]\s*[\"']?[^\"'\s,}]{16,}", re.IGNORECASE),
    re.compile(r"Bearer\s+[a-zA-Z0-9._-]{20,}", re.IGNORECASE),
    re.compile(r"Authorization[\"']?\s*[:=]\s*[\"']?[^\"'\s,}]{8,}", re.IGNORECASE),
]
SENSITIVE_KEYS = {"token", "api_key", "api-key", "session", "authorization", "cookie", "password"}


def iter_json_items(value: Any, path: str = ""):
    """Yield (path, key, scalar_value) for all nested JSON values."""
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from iter_json_items(child, child_path)
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            yield from iter_json_items(child, f"{path}[{idx}]")
    else:
        key = path.rsplit(".", 1)[-1].split("[", 1)[0].lower()
        yield path, key, value


def scan_file_for_tokens(filepath: Path) -> list[str]:
    """扫描普通文本文件中的凭据模式。"""
    warnings = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        for i, line in enumerate(content.splitlines(), 1):
            for pattern in TOKEN_PATTERNS:
                if pattern.search(line):
                    warnings.append(f"  {filepath}:{i} — 匹配: {pattern.pattern[:40]}...")
                    break
    except (OSError, UnicodeDecodeError):
        pass
    return warnings


def scan_jsonl_for_tokens(filepath: Path) -> list[str]:
    """递归扫描 exp_candidate.jsonl 中的敏感 key/value。"""
    warnings = []
    try:
        for i, line in enumerate(filepath.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                record = None

            if record is not None:
                for path, key, value in iter_json_items(record):
                    path_keys = [seg.split("[", 1)[0].lower() for seg in path.split(".") if seg]
                    if any(part in SENSITIVE_KEYS for part in path_keys) and value not in (None, ""):
                        warnings.append(f"  {filepath}:{i} — 敏感字段: '{path}'")
                    if isinstance(value, (str, int, float)):
                        text = str(value)
                        for pattern in TOKEN_PATTERNS:
                            if pattern.search(text):
                                warnings.append(f"  {filepath}:{i} — {path} 匹配: {pattern.pattern[:40]}...")
                                break
            else:
                for pattern in TOKEN_PATTERNS:
                    if pattern.search(line):
                        warnings.append(f"  {filepath}:{i} — 匹配: {pattern.pattern[:40]}...")
                        break
    except (OSError, UnicodeDecodeError):
        pass
    return warnings


def main() -> None:
    parser = argparse.ArgumentParser(description="清理 exp_candidate.jsonl 并扫描凭据泄露")
    parser.add_argument("competition_dir", type=Path, help="比赛目录路径")
    args = parser.parse_args()

    competition_dir = args.competition_dir
    if not competition_dir.is_dir():
        print(f"错误: 目录不存在: {competition_dir}", file=sys.stderr)
        sys.exit(1)

    all_warnings = []
    candidates = list(competition_dir.rglob("exp_candidate.jsonl"))

    for candidate_file in candidates:
        all_warnings.extend(scan_jsonl_for_tokens(candidate_file))

    for flag_file in competition_dir.rglob("flag.found"):
        all_warnings.extend(scan_file_for_tokens(flag_file))

    if all_warnings:
        print("⚠️  凭据泄露告警:")
        for warning in all_warnings:
            print(warning)
        print(f"\n共发现 {len(all_warnings)} 处潜在凭据泄露。")
        print("⚠️  已跳过删除，请手动检查并修复后重新运行。")
        sys.exit(1)

    removed = 0
    for candidate_file in candidates:
        candidate_file.unlink()
        print(f"已删除: {candidate_file}")
        removed += 1

    if removed == 0:
        print("未发现 exp_candidate.jsonl 文件，无需清理。")
    else:
        print(f"\n清理完成，共删除 {removed} 个文件。")


if __name__ == "__main__":
    main()
