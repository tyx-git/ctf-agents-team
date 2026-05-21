#!/usr/bin/env python3
"""清理所有题目目录下的 exp_candidate.jsonl 文件。

Lead Agent 完成经验库合并后执行此脚本，遍历比赛目录并删除所有
exp_candidate.jsonl 中间文件，避免残留。

用法:
    python3 clearexp.py <比赛目录路径>

示例:
    python3 clearexp.py /mnt/d/Project/Tmp/CTF/ISCC
"""

import sys
from pathlib import Path


def main():
    if len(sys.argv) < 2:
        print("用法: python3 clearexp.py <比赛目录路径>")
        sys.exit(1)

    competition_dir = Path(sys.argv[1])
    if not competition_dir.is_dir():
        print(f"错误: 目录不存在: {competition_dir}")
        sys.exit(1)

    removed = 0
    for candidate_file in competition_dir.rglob("exp_candidate.jsonl"):
        candidate_file.unlink()
        print(f"已删除: {candidate_file}")
        removed += 1

    if removed == 0:
        print("未发现 exp_candidate.jsonl 文件，无需清理。")
    else:
        print(f"\n清理完成，共删除 {removed} 个文件。")


if __name__ == "__main__":
    main()
