#!/usr/bin/env python3
"""清理所有题目目录下的 exp_candidate.jsonl 文件，并扫描凭据泄露。

Lead Agent 完成经验库合并后执行此脚本，遍历比赛目录并删除所有
exp_candidate.jsonl 中间文件，避免残留。同时扫描残留的 token 模式并告警。

用法:
    python3 clearexp.py <比赛目录路径>

示例:
    python3 clearexp.py /mnt/d/Project/Tmp/CTF/ISCC
"""

import json
import re
import sys
from pathlib import Path

# 凭据检测模式
TOKEN_PATTERNS = [
    re.compile(r"ctfd_[a-zA-Z0-9]{20,}", re.IGNORECASE),
    re.compile(r"token[\"']?\s*[:=]\s*[\"'][^\"']{8,}", re.IGNORECASE),
    re.compile(r"api[_-]?key[\"']?\s*[:=]\s*[\"'][^\"']{8,}", re.IGNORECASE),
    re.compile(r"session[\"']?\s*[:=]\s*[\"'][^\"']{16,}", re.IGNORECASE),
    re.compile(r"Bearer\s+[a-zA-Z0-9._-]{20,}", re.IGNORECASE),
    re.compile(r"Authorization[\"']?\s*[:=]\s*[\"'][^\"']{8,}", re.IGNORECASE),
]


def scan_file_for_tokens(filepath: Path) -> list[str]:
    """扫描文件内容中的凭据模式，返回告警列表。"""
    warnings = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        for i, line in enumerate(content.splitlines(), 1):
            for pattern in TOKEN_PATTERNS:
                if pattern.search(line):
                    warnings.append(f"  {filepath}:{i} — 匹配: {pattern.pattern[:40]}...")
                    break  # 每行只报一次
    except (OSError, UnicodeDecodeError):
        pass
    return warnings


def scan_jsonl_for_tokens(filepath: Path) -> list[str]:
    """扫描 exp_candidate.jsonl 中的凭据字段。"""
    warnings = []
    sensitive_keys = {"token", "api_key", "session", "authorization", "cookie", "password"}
    try:
        for i, line in enumerate(filepath.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if isinstance(record, dict):
                    for key in record:
                        if key.lower() in sensitive_keys:
                            warnings.append(
                                f"  {filepath}:{i} — 敏感字段: '{key}'"
                            )
            except json.JSONDecodeError:
                pass
            # 也做正则扫描
            for pattern in TOKEN_PATTERNS:
                if pattern.search(line):
                    warnings.append(f"  {filepath}:{i} — 匹配: {pattern.pattern[:40]}...")
                    break
    except (OSError, UnicodeDecodeError):
        pass
    return warnings


def main():
    if len(sys.argv) < 2:
        print("用法: python3 clearexp.py <比赛目录路径>")
        sys.exit(1)

    competition_dir = Path(sys.argv[1])
    if not competition_dir.is_dir():
        print(f"错误: 目录不存在: {competition_dir}")
        sys.exit(1)

    # Phase 1: 扫描 exp_candidate.jsonl 中的凭据
    all_warnings = []
    candidates = list(competition_dir.rglob("exp_candidate.jsonl"))

    for candidate_file in candidates:
        warnings = scan_jsonl_for_tokens(candidate_file)
        all_warnings.extend(warnings)

    # Phase 2: 扫描 flag.found 文件（不应包含凭据）
    for flag_file in competition_dir.rglob("flag.found"):
        warnings = scan_file_for_tokens(flag_file)
        all_warnings.extend(warnings)

    # 报告凭据告警
    if all_warnings:
        print("⚠️  凭据泄露告警:")
        for w in all_warnings:
            print(w)
        print(f"\n共发现 {len(all_warnings)} 处潜在凭据泄露，请检查后再提交。\n")

    # Phase 3: 删除 exp_candidate.jsonl
    removed = 0
    for candidate_file in candidates:
        candidate_file.unlink()
        print(f"已删除: {candidate_file}")
        removed += 1

    if removed == 0:
        print("未发现 exp_candidate.jsonl 文件，无需清理。")
    else:
        print(f"\n清理完成，共删除 {removed} 个文件。")

    # 返回非零退出码如果有凭据告警
    if all_warnings:
        sys.exit(1)


if __name__ == "__main__":
    main()
