#!/usr/bin/env python3
"""CTF Agents Team — 文件存在性强检查与工程校验

对比赛目录结构、必含文件、文件命名、状态一致性、经验库 schema 进行强检查，
输出结构化 JSON 结果供模型解析与展示。整合原 val.py 全部功能。

用法:
    python3 CheckFiles.py <比赛目录路径>                          # 全量检查
    python3 CheckFiles.py <比赛目录路径> --challenge <分类/题目>   # 单题检查
    python3 CheckFiles.py <比赛目录路径> --exp-dir <经验库路径>     # 含经验库校验

示例:
    python3 CheckFiles.py /mnt/d/Project/Tmp/CTF/ISCC
    python3 CheckFiles.py /mnt/d/Project/Tmp/CTF/ISCC --challenge web/its-question
    python3 CheckFiles.py /mnt/d/Project/Tmp/CTF/ISCC --exp-dir .skills/ctf-agents-team/exp

退出码: 0 = 全部通过, 1 = 有错误
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# ── 常量 ─────────────────────────────────────────────────────────────────

VALID_CATEGORIES = {"web", "pwn", "re", "misc", "crypto", "forensics", "mobile"}
CATEGORY_ALIASES = {"reverse": "re"}
EXP_REQUIRED_FIELDS = {"challenge", "name", "technique", "status", "experience"}
EXP_OPTIONAL_FIELDS = {"artifacts", "failed_attempts"}
EXP_VALID_CHALLENGES = {"Web", "Pwn", "Re", "Mobile", "Misc", "Crypto", "Forensics"}
EXP_VALID_STATUS = {"solved", "partial"}
FLAG_LOG_PATTERN = re.compile(r"^\[(\w+)\]\[(.+?)\]\s+(.+)$")
FLAG_FOUND_PATTERN = re.compile(r"\b[A-Za-z]+\{[^}]+\}")
TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")

# 可脚本化品类（必须写 exploit.py）
SCRIPTABLE_CATEGORIES = {"web", "pwn", "crypto"}

# 禁止内容模式（凭据扫描；仅当出现在 JSON 值中才触发）
FORBIDDEN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"[A-Za-z]+\{[^}]+\}"),
    re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"ctfd_[a-zA-Z0-9]{10,}", re.IGNORECASE),
    re.compile(r"token[\"']?\s*[:=]\s*[\"']?[^\"'\s,}]{8,}", re.IGNORECASE),
    re.compile(r"api[_-]?key[\"']?\s*[:=]\s*[\"']?[^\"'\s,}]{8,}", re.IGNORECASE),
    re.compile(r"session[\"']?\s*[:=]\s*[\"']?[^\"'\s,}]{8,}", re.IGNORECASE),
    re.compile(r"authorization[\"']?\s*[:=]\s*[\"']?[^\"'\s,}]{8,}", re.IGNORECASE),
    re.compile(r"password[\"']?\s*[:=]\s*[\"']?[^\"'\s,}]{3,}", re.IGNORECASE),
    re.compile(r"bearer\s+[a-zA-Z0-9._-]{20,}", re.IGNORECASE),
]
SENSITIVE_JSON_KEYS = {"token", "api_key", "api-key", "session", "authorization", "cookie", "password"}

# ── 结果收集器 ──────────────────────────────────────────────────────────

class Report:
    def __init__(self):
        self.errors: list[dict[str, Any]] = []
        self.warnings: list[dict[str, Any]] = []
        self.checks: list[dict[str, Any]] = []

    def error(self, check: str, msg: str, detail: str = "") -> None:
        self.errors.append({"check": check, "message": msg, "detail": detail})

    def warn(self, check: str, msg: str, detail: str = "") -> None:
        self.warnings.append({"check": check, "message": msg, "detail": detail})

    def ok(self, check: str, msg: str, detail: str = "") -> None:
        self.checks.append({"check": check, "status": "pass", "message": msg, "detail": detail})

    def to_dict(self, competition_dir: str) -> dict[str, Any]:
        return {
            "competition_dir": competition_dir,
            "summary": {
                "total": len(self.checks),
                "passed": len(self.checks),
                "errors": len(self.errors),
                "warnings": len(self.warnings),
            },
            "checks": self.checks,
            "errors": self.errors,
            "warnings": self.warnings,
        }

    def print_json(self, competition_dir: str) -> None:
        print(json.dumps(self.to_dict(competition_dir), ensure_ascii=False, indent=2))

    def print_human(self, competition_dir: str) -> None:
        print(f"🔍 CheckFiles — {competition_dir}")
        print("=" * 60)
        for c in self.checks:
            print(f"  ✅ {c['check']}: {c['message']}")
        for w in self.warnings:
            print(f"  ⚠️  {w['check']}: {w['message']}")
        for e in self.errors:
            print(f"  ❌ {e['check']}: {e['message']}")
        print(f"\n📊 {len(self.checks)} passed, {len(self.warnings)} warnings, {len(self.errors)} errors")


# ── 单题文件存在性检查 ────────────────────────────────────────────────

def check_single_challenge(challenge_dir: Path, report: Report) -> None:
    """强检查单道题目的必要文件是否齐全。"""
    name = challenge_dir.name
    category = challenge_dir.parent.name.lower()

    # 标准化品类目录
    category = CATEGORY_ALIASES.get(category, category)

    # ── wp.process ──
    wp_process = challenge_dir / "wp.process"
    if wp_process.is_file():
        report.ok(f"wp.process[{name}]", "wp.process 存在", str(wp_process))
    else:
        report.error(f"wp.process[{name}]", "缺少 wp.process 文件", str(wp_process))

    # ── flag.found ──
    flag_found = challenge_dir / "flag.found"
    if flag_found.is_file():
        valid, detail = _validate_flag_found(flag_found)
        if valid:
            report.ok(f"flag.found[{name}]", "flag.found 格式正确", detail)
        else:
            report.error(f"flag.found[{name}]", "flag.found 格式不完整", detail)
    else:
        report.warn(f"flag.found[{name}]", "flag.found 不存在（未解决或子 Agent 尚未产出）", str(flag_found))

    # ── 最终 WP（题目名称.md） ──
    final_wp = challenge_dir / f"{name}.md"
    if final_wp.is_file():
        report.ok(f"WP[{name}]", "最终 WP 文件存在", str(final_wp))
    else:
        # 尝试 glob 匹配其他可能的命名
        md_files = list(challenge_dir.glob("*.md"))
        valid_wps = [f for f in md_files if f.name not in ("wp.process",) and f.is_file()]
        if valid_wps:
            report.ok(f"WP[{name}]", f"最终 WP 存在（文件名不同: {valid_wps[0].name}）", str(valid_wps[0]))
        else:
            report.error(f"WP[{name}]", "缺少最终 WP 文件（应为 {name}.md）", str(final_wp))

        # 检查是否使用了禁止的前缀
        for f in challenge_dir.iterdir():
            if f.is_file() and f.name.startswith(("wp：", "wp:")):
                report.error(f"WP命名[{name}]", f"WP 文件名使用了禁止的前缀: {f.name}", str(f))

    # ── exploit.py（可脚本化品类） ──
    if category in SCRIPTABLE_CATEGORIES:
        exploit_py = challenge_dir / "exploit.py"
        if exploit_py.is_file():
            report.ok(f"exploit.py[{name}]", "exploit.py 存在", str(exploit_py))
        else:
            report.warn(f"exploit.py[{name}]", f"缺少 exploit.py（{category} 为可脚本化品类）", str(exploit_py))

    # ── exp_candidate.jsonl（应已被清理） ──
    exp_candidate = challenge_dir / "exp_candidate.jsonl"
    if exp_candidate.is_file():
        report.warn(f"exp_candidate[{name}]", "exp_candidate.jsonl 残留，Lead Agent 尚未合并清理", str(exp_candidate))
    else:
        report.ok(f"exp_candidate[{name}]", "无经验候选残留", str(exp_candidate))


def _validate_flag_found(flag_found: Path) -> tuple[bool, str]:
    """校验 flag.found 三行格式。返回 (是否合法, 详情)。"""
    try:
        content = flag_found.read_text(encoding="utf-8").strip()
        lines = content.splitlines()
        fields = {"FLAG": False, "STATUS": False, "TIMESTAMP": False}
        for line in lines:
            line = line.strip()
            if line.startswith("FLAG:") and line[5:].strip():
                fields["FLAG"] = True
            elif line.startswith("STATUS:") and line[7:].strip() == "solved":
                fields["STATUS"] = True
            elif line.startswith("TIMESTAMP:"):
                ts = line[10:].strip()
                if TIMESTAMP_PATTERN.match(ts):
                    try:
                        datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        fields["TIMESTAMP"] = True
                    except ValueError:
                        pass

        missing = [k for k, v in fields.items() if not v]
        if missing:
            return False, f"缺少字段: {', '.join(missing)}"
        return True, "FLAG/STATUS/TIMESTAMP 三行完整"
    except (OSError, UnicodeDecodeError) as e:
        return False, str(e)


# ── 比赛级目录合规检查 ───────────────────────────────────────────────

def check_directory_compliance(competition_dir: Path, report: Report) -> None:
    """验证比赛根目录下品类目录名均为小写。"""
    for item in competition_dir.iterdir():
        if not item.is_dir():
            continue
        name = item.name
        if name.startswith(".") or name in {"scripts", "exp", "knowledge", "references"}:
            continue
        canon = CATEGORY_ALIASES.get(name.lower(), name.lower())
        if canon in VALID_CATEGORIES:
            if name != canon:
                report.error("目录合规", f"品类目录名非小写: {name}/（应为 {canon}/）", str(item))
            else:
                report.ok("目录合规", f"品类目录名正确: {name}/", str(item))


def check_flag_log(competition_dir: Path, report: Report) -> None:
    """检查 flag.log 格式与一致性。"""
    flag_log = competition_dir / "flag.log"
    if not flag_log.is_file():
        report.warn("flag.log", "flag.log 不存在（比赛可能尚未产生 flag）", str(flag_log))
        return

    report.ok("flag.log", "flag.log 存在", str(flag_log))

    # 解析所有条目
    logged: dict[str, int] = {}
    for i, line in enumerate(flag_log.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        match = FLAG_LOG_PATTERN.match(line)
        if match:
            key = f"[{match.group(1)}][{match.group(2)}]"
            if key in logged:
                report.error("flag.log", f"重复条目: {key}（行 {logged[key]} 和 {i}）", line)
            else:
                logged[key] = i
                report.ok("flag.log", f"条目格式正确: {key}", line)
        else:
            report.error("flag.log", f"格式错误: '{line[:60]}'", line)

    # 交叉检查 flag.found vs flag.log
    for category_dir in competition_dir.iterdir():
        if not category_dir.is_dir() or category_dir.name.lower() not in VALID_CATEGORIES:
            continue
        for challenge_dir in category_dir.iterdir():
            if not challenge_dir.is_dir():
                continue
            flag_found = challenge_dir / "flag.found"
            if flag_found.is_file():
                name_lower = challenge_dir.name.lower()
                if not any(name_lower in k.lower() for k in logged):
                    report.warn(
                        "flag.log vs flag.found",
                        f"flag.found 存在但 flag.log 无记录: {challenge_dir.name}",
                        str(flag_found),
                    )


def check_key_file_naming(challenge_dir: Path, report: Report) -> None:
    """检查单个题目目录中的关键文件命名。"""
    name = challenge_dir.name

    # 检查错误命名的 WP 文件
    for f in challenge_dir.iterdir():
        if f.is_file() and f.name.startswith(("wp：", "wp:")):
            report.error("文件命名", f"WP 文件使用了禁止的前缀: {f.name}（应为 '{name}.md'）", str(f))

    # 检查 wp.process 命名
    wp = challenge_dir / "wp.process"
    if wp.is_file() and wp.suffix:
        pass  # wp.process 无后缀是正常的

    # 检查 exploit.py 非标准命名
    for f in challenge_dir.iterdir():
        if f.is_file() and "exploit" in f.name.lower() and f.name != "exploit.py":
            report.warn("文件命名", f"exploit 脚本名非标准: {f.name}（应为 exploit.py）", str(f))




def _iter_json_values(value: Any, path: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from _iter_json_values(child, child_path)
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            yield from _iter_json_values(child, f"{path}[{idx}]")
    else:
        yield path, value


def _find_forbidden_json_content(value: Any) -> tuple[str, str] | None:
    for path, item in _iter_json_values(value):
        key = path.rsplit(".", 1)[-1].split("[", 1)[0].lower()
        if key in SENSITIVE_JSON_KEYS and item not in (None, ""):
            return path, f"敏感字段: {key}"
        if not isinstance(item, (str, int, float)):
            continue
        text = str(item)
        for pattern in FORBIDDEN_PATTERNS:
            match = pattern.search(text)
            if match:
                return path, match.group(0)[:60]
    return None


# ── 经验库 schema 校验 ─────────────────────────────────────────────

def check_exp_schema(exp_dir: Path, report: Report) -> None:
    """遍历 exp/*/*.jsonl 校验每行记录合法性。"""
    if not exp_dir.is_dir():
        report.warn("经验库", f"经验库目录不存在: {exp_dir}", str(exp_dir))
        return

    for jsonl_file in sorted(exp_dir.rglob("*.jsonl")):
        try:
            lines = jsonl_file.read_text(encoding="utf-8").splitlines()
            line_count = 0
            for i, line in enumerate(lines, 1):
                line = line.strip()
                if not line:
                    continue
                line_count += 1
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as e:
                    report.error("经验库", f"{jsonl_file.name}:{i} JSON 解析失败: {e}", line[:80])
                    continue

                if not isinstance(record, dict):
                    report.error("经验库", f"{jsonl_file.name}:{i} 非 JSON 对象", str(type(record).__name__))
                    continue

                # 必填字段
                missing = EXP_REQUIRED_FIELDS - set(record.keys())
                if missing:
                    report.error("经验库", f"{jsonl_file.name}:{i} 缺少必填字段: {missing}", "")
                    continue

                # challenge 枚举
                ch = record.get("challenge", "")
                if ch not in EXP_VALID_CHALLENGES:
                    report.error("经验库", f"{jsonl_file.name}:{i} challenge 无效: '{ch}'", "")

                # status 枚举
                st = record.get("status", "")
                if st not in EXP_VALID_STATUS:
                    report.error("经验库", f"{jsonl_file.name}:{i} status 无效: '{st}'", "")

                # name 长度
                name = record.get("name", "")
                if not isinstance(name, str) or not (1 <= len(name) <= 60):
                    report.error("经验库", f"{jsonl_file.name}:{i} name 长度不符 ({len(name)})", name[:40])

                # technique 长度
                tech = record.get("technique", "")
                if not isinstance(tech, str) or not (1 <= len(tech) <= 120):
                    report.error("经验库", f"{jsonl_file.name}:{i} technique 长度不符 ({len(tech)})", tech[:40])

                # experience 数组
                exp_list = record.get("experience", [])
                if not isinstance(exp_list, list) or not (3 <= len(exp_list) <= 8):
                    report.error("经验库", f"{jsonl_file.name}:{i} experience 应为 3-8 条（当前 {len(exp_list) if isinstance(exp_list, list) else 'non-list'}）", "")
                elif isinstance(exp_list, list):
                    for j, item in enumerate(exp_list):
                        if not isinstance(item, str) or not (15 <= len(item) <= 150):
                            report.warn("经验库", f"{jsonl_file.name}:{i} experience[{j}] 长度不符 ({len(item)})", "")

                # failed_attempts 结构化校验
                fa = record.get("failed_attempts")
                if fa is not None:
                    if not isinstance(fa, list) or not (1 <= len(fa) <= 5):
                        report.error("经验库", f"{jsonl_file.name}:{i} failed_attempts 应为 1-5 条（当前 {len(fa) if isinstance(fa, list) else 'non-list'}）", "")
                    else:
                        fa_fields = {"approach", "why_failed", "lesson"}
                        for j, item in enumerate(fa):
                            if not isinstance(item, dict):
                                report.error("经验库", f"{jsonl_file.name}:{i} failed_attempts[{j}] 应为 object", "")
                                continue
                            missing_sub = fa_fields - set(item.keys())
                            extra_sub = set(item.keys()) - fa_fields
                            if missing_sub:
                                report.error("经验库", f"{jsonl_file.name}:{i} failed_attempts[{j}] 缺少: {missing_sub}", "")
                            if extra_sub:
                                report.error("经验库", f"{jsonl_file.name}:{i} failed_attempts[{j}] 多余: {extra_sub}", "")
                            for field in fa_fields:
                                val = item.get(field, "")
                                if not isinstance(val, str) or not (15 <= len(val) <= 150):
                                    report.error("经验库", f"{jsonl_file.name}:{i} failed_attempts[{j}].{field} 长度 {len(val)} (应 15-150)", "")

                # 多余字段
                allowed = EXP_REQUIRED_FIELDS | EXP_OPTIONAL_FIELDS
                extra = set(record.keys()) - allowed
                if extra:
                    report.error("经验库", f"{jsonl_file.name}:{i} 多余字段: {extra}", "")

                # 凭据扫描
                forbidden = _find_forbidden_json_content(record)
                if forbidden:
                    path, detail = forbidden
                    report.error("经验库", f"{jsonl_file.name}:{i} 包含禁止内容: {path}", detail)

            if line_count > 0:
                report.ok("经验库", f"{jsonl_file.name} — {line_count} 条记录，schema 通过", str(jsonl_file))
            else:
                report.warn("经验库", f"{jsonl_file.name} — 空文件", str(jsonl_file))

        except (OSError, UnicodeDecodeError) as e:
            report.error("经验库", f"无法读取: {jsonl_file.name} ({e})", "")


# ── 凭据泄露扫描 ───────────────────────────────────────────────────

def scan_credentials(competition_dir: Path, report: Report) -> None:
    """扫描比赛目录下的敏感信息泄露。"""
    TOKEN_PATTERNS = [
        re.compile(r"ctfd_[a-zA-Z0-9]{20,}", re.IGNORECASE),
        re.compile(r"token[\"']?\s*[:=]\s*[\"'][^\"']{8,}", re.IGNORECASE),
        re.compile(r"api[_-]?key[\"']?\s*[:=]\s*[\"'][^\"']{8,}", re.IGNORECASE),
        re.compile(r"session[\"']?\s*[:=]\s*[\"'][^\"']{16,}", re.IGNORECASE),
        re.compile(r"Bearer\s+[a-zA-Z0-9._-]{20,}", re.IGNORECASE),
        re.compile(r"Authorization[\"']?\s*[:=]\s*[\"'][^\"']{8,}", re.IGNORECASE),
    ]

    # 扫描 flag.found 和 exp_candidate.jsonl
    for pattern in ("flag.found", "exp_candidate.jsonl"):
        for target_file in competition_dir.rglob(pattern):
            try:
                content = target_file.read_text(encoding="utf-8", errors="ignore")
                for i, line in enumerate(content.splitlines(), 1):
                    for p in TOKEN_PATTERNS:
                        if p.search(line):
                            report.warn(
                                "凭据扫描",
                                f"{target_file.relative_to(competition_dir)}:{i} 疑似凭据泄露",
                                p.pattern[:40],
                            )
                            break
            except (OSError, UnicodeDecodeError):
                pass


# ── 单题强检查入口 ─────────────────────────────────────────────────

def run_challenge_check(challenge_rel: str, competition_dir: Path, report: Report) -> None:
    """按 `分类/题目名` 路径对单道题做强文件检查。"""
    parts = challenge_rel.strip("/").split("/", 1)
    if len(parts) != 2:
        report.error("参数", f"无效的题目路径格式: '{challenge_rel}'（应为 分类/题目名）", "")
        return

    cat_dir_name = parts[0].lower()
    challenge_name = parts[1]

    # 别名映射
    cat_dir = CATEGORY_ALIASES.get(cat_dir_name, cat_dir_name)
    if cat_dir not in VALID_CATEGORIES:
        report.error("参数", f"无效的品类: '{cat_dir}'（应为 {sorted(VALID_CATEGORIES)}）", "")
        return

    # 尝试查找目录（大小写兼容）
    challenge_dir = None
    cat_path = competition_dir / cat_dir
    if cat_path.is_dir():
        for d in cat_path.iterdir():
            if d.is_dir() and d.name.lower() == challenge_name.lower():
                challenge_dir = d
                break

    if challenge_dir is None:
        report.error("检查", f"题目目录不存在: {challenge_rel}", str(competition_dir / cat_dir / challenge_name))
        return

    report.ok("定位", f"找到题目目录: {challenge_rel}", str(challenge_dir))
    check_single_challenge(challenge_dir, report)
    check_key_file_naming(challenge_dir, report)


# ── 全局检查入口 ──────────────────────────────────────────────────

def run_full_check(competition_dir: Path, exp_dir: Path | None, report: Report) -> None:
    """全量检查：目录合规 + 遍历所有题目检查 + flag.log + 经验库 + 凭据。"""
    # 1. 目录合规
    check_directory_compliance(competition_dir, report)

    # 2. 遍历所有品类题目
    total_challenges = 0
    for category_dir in competition_dir.iterdir():
        if not category_dir.is_dir():
            continue
        cat_name = category_dir.name.lower()
        cat_name = CATEGORY_ALIASES.get(cat_name, cat_name)
        if cat_name not in VALID_CATEGORIES:
            continue

        for challenge_dir in sorted(category_dir.iterdir()):
            if not challenge_dir.is_dir():
                continue
            total_challenges += 1
            check_single_challenge(challenge_dir, report)
            check_key_file_naming(challenge_dir, report)

    if total_challenges == 0:
        report.warn("全局", "未发现任何题目目录", str(competition_dir))

    # 3. flag.log
    check_flag_log(competition_dir, report)

    # 4. 经验库
    if exp_dir:
        check_exp_schema(exp_dir, report)

    # 5. 凭据扫描
    scan_credentials(competition_dir, report)


# ── 主入口 ─────────────────────────────────────────────────────────

def _usage() -> None:
    print(__doc__)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        _usage()
        sys.exit(0)

    competition_dir = Path(sys.argv[1])
    if not competition_dir.is_dir():
        print(f"❌ 错误: 目录不存在: {competition_dir}", file=sys.stderr)
        sys.exit(1)

    # 解析参数
    challenge_rel: str | None = None
    exp_dir: Path | None = None

    if "--challenge" in sys.argv:
        idx = sys.argv.index("--challenge")
        if idx + 1 < len(sys.argv):
            challenge_rel = sys.argv[idx + 1]

    if "--exp-dir" in sys.argv:
        idx = sys.argv.index("--exp-dir")
        if idx + 1 < len(sys.argv):
            exp_dir = Path(sys.argv[idx + 1])

    report = Report()

    if challenge_rel:
        run_challenge_check(challenge_rel, competition_dir, report)
    else:
        run_full_check(competition_dir, exp_dir, report)

    # ── 输出 ──
    use_json = "--json" in sys.argv
    if use_json:
        report.print_json(str(competition_dir))
    else:
        report.print_human(str(competition_dir))

    sys.exit(1 if report.errors else 0)


if __name__ == "__main__":
    main()
