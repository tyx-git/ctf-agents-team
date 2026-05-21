#!/usr/bin/env python3
"""CTF Agents Team — 工程校验脚本

对比赛目录结构、文件命名、状态一致性、经验库 schema 进行自动检查，
将自然语言约束转化为机器可执行的校验。

用法:
    python3 val.py <比赛目录路径> [--exp-dir <经验库路径>]

示例:
    python3 val.py /mnt/d/Project/Tmp/CTF/ISCC
    python3 val.py /mnt/d/Project/Tmp/CTF/ISCC --exp-dir /mnt/d/Project/Tmp/CTF/.skills/ctf-agents-team/exp
"""

import json
import re
import sys
from datetime import datetime
from pathlib import Path

# 标准品类目录名（全小写）
VALID_CATEGORIES = {"web", "pwn", "re", "misc", "crypto", "forensics", "mobile"}

# 经验库必填字段
EXP_REQUIRED_FIELDS = {"challenge", "name", "technique", "status", "experience"}
EXP_VALID_CHALLENGES = {"Web", "Pwn", "Re", "Mobile", "Misc", "Crypto", "Forensics"}
EXP_VALID_STATUS = {"solved", "partial"}

# flag.log 格式
FLAG_LOG_PATTERN = re.compile(r"^\[(\w+)\]\[(.+?)\]\s+(.+)$")


class ValidationResult:
    def __init__(self):
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.passed: int = 0

    def error(self, msg: str):
        self.errors.append(msg)

    def warn(self, msg: str):
        self.warnings.append(msg)

    def ok(self):
        self.passed += 1

    def summary(self) -> str:
        lines = []
        if self.errors:
            lines.append(f"\n❌ {len(self.errors)} 错误:")
            for e in self.errors:
                lines.append(f"  - {e}")
        if self.warnings:
            lines.append(f"\n⚠️  {len(self.warnings)} 警告:")
            for w in self.warnings:
                lines.append(f"  - {w}")
        lines.append(f"\n✅ {self.passed} 项通过")
        return "\n".join(lines)


def check_directory_compliance(competition_dir: Path, result: ValidationResult):
    """验证比赛根目录下所有题型目录均为小写。"""
    for item in competition_dir.iterdir():
        if not item.is_dir():
            continue
        name = item.name
        # 跳过非品类目录（如 .git, scripts 等）
        if name.startswith(".") or name in {"scripts", "exp", "knowledge", "references"}:
            continue
        if name.lower() in VALID_CATEGORIES:
            if name != name.lower():
                result.error(f"目录名非小写: {item} (应为 {name.lower()}/)")
            else:
                result.ok()
        # 不报告非品类目录（可能是比赛特有的其他目录）


def check_key_files(competition_dir: Path, result: ValidationResult):
    """确认关键文件命名正确。"""
    # 检查 flag.log 存在性
    flag_log = competition_dir / "flag.log"
    if flag_log.exists():
        result.ok()
    else:
        result.warn(f"flag.log 不存在: {flag_log}")

    # 遍历题目目录检查文件命名
    for category_dir in competition_dir.iterdir():
        if not category_dir.is_dir():
            continue
        if category_dir.name.lower() not in VALID_CATEGORIES:
            continue
        for challenge_dir in category_dir.iterdir():
            if not challenge_dir.is_dir():
                continue
            # 检查 wp.process
            wp_process = challenge_dir / "wp.process"
            # 检查 flag.found 格式
            flag_found = challenge_dir / "flag.found"
            if flag_found.exists():
                validate_flag_found(flag_found, result)
            # 检查是否有错误命名的 WP 文件
            for f in challenge_dir.iterdir():
                if f.is_file() and f.name.startswith(("wp：", "wp:")):
                    result.error(
                        f"WP 文件名使用了禁止的前缀: {f} (应为 '题目名称.md')"
                    )


def validate_flag_found(flag_found: Path, result: ValidationResult):
    """校验 flag.found 三行格式。"""
    try:
        content = flag_found.read_text(encoding="utf-8").strip()
        lines = content.splitlines()
        has_flag = False
        has_status = False
        has_timestamp = False
        for line in lines:
            line = line.strip()
            if line.startswith("FLAG:"):
                has_flag = bool(line[5:].strip())
            elif line.startswith("STATUS:"):
                has_status = line[7:].strip() == "solved"
            elif line.startswith("TIMESTAMP:"):
                ts = line[10:].strip()
                if re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", ts):
                    try:
                        datetime.fromisoformat(ts.replace('Z', '+00:00'))
                        has_timestamp = True
                    except ValueError:
                        has_timestamp = False

        if has_flag and has_status and has_timestamp:
            result.ok()
        else:
            missing = []
            if not has_flag:
                missing.append("FLAG")
            if not has_status:
                missing.append("STATUS")
            if not has_timestamp:
                missing.append("TIMESTAMP")
            result.error(f"flag.found 格式不完整: {flag_found} (缺少: {', '.join(missing)})")
    except (OSError, UnicodeDecodeError) as e:
        result.error(f"无法读取 flag.found: {flag_found} ({e})")


def check_status_consistency(competition_dir: Path, result: ValidationResult):
    """检查 flag.found 与 flag.log 的一致性。"""
    flag_log = competition_dir / "flag.log"
    logged_challenges: set[str] = set()

    if flag_log.exists():
        for line in flag_log.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            match = FLAG_LOG_PATTERN.match(line)
            if match:
                challenge_name = match.group(2)
                logged_challenges.add(challenge_name.lower())
                result.ok()
            else:
                result.error(f"flag.log 格式错误: '{line}' (应为 [类型][题目名称] flag字符串)")

    # 检查 flag.found 存在但 flag.log 无记录
    for category_dir in competition_dir.iterdir():
        if not category_dir.is_dir() or category_dir.name.lower() not in VALID_CATEGORIES:
            continue
        for challenge_dir in category_dir.iterdir():
            if not challenge_dir.is_dir():
                continue
            flag_found = challenge_dir / "flag.found"
            if flag_found.exists():
                challenge_name = challenge_dir.name.lower()
                if challenge_name not in logged_challenges:
                    result.warn(
                        f"flag.found 存在但 flag.log 无记录: {challenge_dir.name} "
                        f"(可能 Lead Agent 尚未汇总)"
                    )

    # 检查 flag.log 唯一性
    if flag_log.exists():
        seen: dict[str, int] = {}
        for i, line in enumerate(flag_log.read_text(encoding="utf-8").splitlines(), 1):
            match = FLAG_LOG_PATTERN.match(line.strip())
            if match:
                key = f"[{match.group(1)}][{match.group(2)}]"
                if key in seen:
                    result.error(f"flag.log 重复条目: {key} (行 {seen[key]} 和 {i})")
                else:
                    seen[key] = i


def check_exp_schema(exp_dir: Path, result: ValidationResult):
    """遍历 exp/*/*.jsonl 校验每行记录合法性。"""
    if not exp_dir.exists():
        result.warn(f"经验库目录不存在: {exp_dir}")
        return

    for jsonl_file in exp_dir.rglob("*.jsonl"):
        try:
            lines = jsonl_file.read_text(encoding="utf-8").splitlines()
            for i, line in enumerate(lines, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as e:
                    result.error(f"{jsonl_file}:{i} — JSON 解析失败: {e}")
                    continue

                if not isinstance(record, dict):
                    result.error(f"{jsonl_file}:{i} — 非 JSON 对象")
                    continue

                # 必填字段检查
                missing = EXP_REQUIRED_FIELDS - set(record.keys())
                if missing:
                    result.error(f"{jsonl_file}:{i} — 缺少必填字段: {missing}")
                    continue

                # challenge 枚举检查
                if record.get("challenge") not in EXP_VALID_CHALLENGES:
                    result.error(
                        f"{jsonl_file}:{i} — challenge 值无效: '{record.get('challenge')}' "
                        f"(应为 {EXP_VALID_CHALLENGES})"
                    )

                # status 枚举检查
                if record.get("status") not in EXP_VALID_STATUS:
                    result.error(
                        f"{jsonl_file}:{i} — status 值无效: '{record.get('status')}' "
                        f"(应为 solved 或 partial)"
                    )

                # experience 数组检查
                exp = record.get("experience")
                if not isinstance(exp, list) or not (3 <= len(exp) <= 8):
                    result.error(
                        f"{jsonl_file}:{i} — experience 应为 3-8 条数组 "
                        f"(当前 {len(exp) if isinstance(exp, list) else 'non-list'})"
                    )
                elif isinstance(exp, list):
                    for j, item in enumerate(exp):
                        if not isinstance(item, str) or not (15 <= len(item) <= 150):
                            result.warn(
                                f"{jsonl_file}:{i} — experience[{j}] 长度不符 "
                                f"(应 15-150 字符, 当前 {len(item) if isinstance(item, str) else 'non-str'})"
                            )

                # name 字段长度校验 (≤60)
                name_val = record.get("name", "")
                if not isinstance(name_val, str) or not (1 <= len(name_val) <= 60):
                    result.error(
                        f"{jsonl_file}:{i} — name 长度不符 (应 1-60 字符, "
                        f"当前 {len(name_val) if isinstance(name_val, str) else 'non-str'})"
                    )

                # technique 字段长度校验 (≤120)
                tech_val = record.get("technique", "")
                if not isinstance(tech_val, str) or not (1 <= len(tech_val) <= 120):
                    result.error(
                        f"{jsonl_file}:{i} — technique 长度不符 (应 1-120 字符, "
                        f"当前 {len(tech_val) if isinstance(tech_val, str) else 'non-str'})"
                    )

                # 多余字段检查
                allowed = EXP_REQUIRED_FIELDS | {"artifacts"}
                extra = set(record.keys()) - allowed
                if extra:
                    result.error(f"{jsonl_file}:{i} — 多余字段: {extra}")

                # 凭据检查
                content_str = json.dumps(record)
                if re.search(r"ctfd_[a-zA-Z0-9]{10,}", content_str, re.IGNORECASE):
                    result.error(f"{jsonl_file}:{i} — 包含疑似 CTFd Token")

                result.ok()
        except (OSError, UnicodeDecodeError) as e:
            result.error(f"无法读取经验库文件: {jsonl_file} ({e})")


def main():
    if len(sys.argv) < 2:
        print("用法: python3 val.py <比赛目录路径> [--exp-dir <经验库路径>]")
        sys.exit(1)

    competition_dir = Path(sys.argv[1])
    if not competition_dir.is_dir():
        print(f"错误: 目录不存在: {competition_dir}")
        sys.exit(1)

    # 解析 --exp-dir 参数
    exp_dir = None
    if "--exp-dir" in sys.argv:
        idx = sys.argv.index("--exp-dir")
        if idx + 1 < len(sys.argv):
            exp_dir = Path(sys.argv[idx + 1])

    result = ValidationResult()

    print(f"🔍 校验比赛目录: {competition_dir}")
    print("=" * 60)

    print("\n[1/4] 目录合规检查...")
    check_directory_compliance(competition_dir, result)

    print("[2/4] 关键文件检查...")
    check_key_files(competition_dir, result)

    print("[3/4] 状态一致性检查...")
    check_status_consistency(competition_dir, result)

    print("[4/4] 经验库 schema 校验...")
    if exp_dir:
        check_exp_schema(exp_dir, result)
    else:
        # 尝试自动发现经验库：从比赛目录向上查找 .skills/（最多 3 层）
        auto_exp = None
        search_dir = competition_dir.parent
        for _ in range(3):
            candidate = search_dir / ".skills" / "ctf-agents-team" / "exp"
            if candidate.exists():
                auto_exp = candidate
                break
            if search_dir.parent == search_dir:
                break  # 到达文件系统根
            search_dir = search_dir.parent

        if auto_exp:
            check_exp_schema(auto_exp, result)
        else:
            result.warn("未指定经验库路径且自动发现失败，跳过 schema 校验")

    print(result.summary())

    # 有错误时返回非零退出码
    sys.exit(1 if result.errors else 0)


if __name__ == "__main__":
    main()
