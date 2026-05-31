#!/usr/bin/env python3
"""统一经验库追加与同步工具。

用法:
    python3 AddExp.py --commit '<json_line>'
        解析校验一条经验 JSON，追加到所有已知 exp 仓库（去重）。
    python3 AddExp.py --commit '<json_line>' --json
        同上，输出精简 JSON 供模型解析。
    python3 AddExp.py --debug-syn [target_dir]
        将 ~/.claude 的 exp/ 同步到 target_dir。
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any, NoReturn

# ── 常量 ─────────────────────────────────────────────────────────────────

VALID_CHALLENGES = {"Web", "Pwn", "Re", "Mobile", "Misc", "Crypto", "Forensics"}
VALID_STATUS = {"solved", "partial"}
REQUIRED_FIELDS = {"challenge", "name", "technique", "status", "experience"}
OPTIONAL_FIELDS = {"artifacts", "failed_attempts"}
SPECULATIVE_TERMS = ("可能", "猜测", "未确认", "疑似", "也许", "maybe", "probably", "guess", "unconfirmed")
SENSITIVE_JSON_KEYS = {"token", "api_key", "api-key", "session", "authorization", "cookie", "password"}

CHALLENGE_TO_DIR: dict[str, str] = {
    "Web": "web", "Pwn": "pwn", "Re": "re", "Mobile": "re",
    "Misc": "misc", "Crypto": "crypto", "Forensics": "forensics",
}

FORBIDDEN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"[A-Za-z]+\{[^}]+\}"),
    re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"ctfd_[a-zA-Z0-9]{10,}", re.IGNORECASE),
    re.compile(r'"api[_-]?key"\s*:\s*"[^"]{3,}"', re.IGNORECASE),
    re.compile(r'"session"\s*:\s*"[^"]{8,}"', re.IGNORECASE),
    re.compile(r'"authorization"\s*:\s*"[^"]{3,}"', re.IGNORECASE),
    re.compile(r'"password"\s*:\s*"[^"]{3,}"', re.IGNORECASE),
    re.compile(r"bearer\s+[a-zA-Z0-9._-]{20,}", re.IGNORECASE),
]

OUTPUT_JSON = "--json" in sys.argv


def output(data: str | dict[str, Any]) -> None:
    if OUTPUT_JSON and isinstance(data, dict):
        print(json.dumps(data, ensure_ascii=False))
    else:
        print(data)


def error_exit(msg: str) -> NoReturn:
    payload = {"status": "error", "message": msg}
    if OUTPUT_JSON:
        output(payload)
    else:
        print(f"❌ {msg}", file=sys.stderr)
    sys.exit(1)


def warn(msg: str) -> None:
    if not OUTPUT_JSON:
        print(f"⚠️  {msg}", file=sys.stderr)


def info(msg: str) -> None:
    if not OUTPUT_JSON:
        print(f"   {msg}")


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



def _find_forbidden_json_content(entry: dict[str, Any]) -> tuple[str, str] | None:
    for path, item in _iter_json_values(entry):
        path_keys = [seg.split("[", 1)[0].lower() for seg in path.split(".") if seg]
        sensitive_key = next((key for key in path_keys if key in SENSITIVE_JSON_KEYS), None)
        if sensitive_key and item not in (None, ""):
            return path, f"敏感字段: {sensitive_key}"
        if not isinstance(item, (str, int, float)):
            continue
        text = str(item)
        for pattern in FORBIDDEN_PATTERNS:
            match = pattern.search(text)
            if match:
                return path, match.group(0)[:60]
    return None

def _contains_speculative_terms(entry: dict[str, Any]) -> tuple[str, str] | None:
    for path, item in _iter_json_values(entry):
        if path == "name" or not isinstance(item, str):
            continue
        lower = item.lower()
        for term in SPECULATIVE_TERMS:
            term_lower = term.lower()
            if term_lower.isascii():
                if re.search(rf"\b{re.escape(term_lower)}\b", lower):
                    return path, term
            elif term_lower in lower:
                return path, term
    return None


# ── 仓库发现 ─────────────────────────────────────────────────────────────

def _iter_stores() -> list[Path]:
    home = Path.home()
    result: list[Path] = []
    for p in (home / ".claude" / "skills" / "ctf-agents-team" / "exp",
              home / ".codex" / "skills" / "ctf-agents-team" / "exp"):
        if p.is_dir():
            result.append(p)
    return result


# ── 校验 ─────────────────────────────────────────────────────────────────

def _validate(entry: dict, source: str = "<stdin>") -> None:
    allowed = REQUIRED_FIELDS | OPTIONAL_FIELDS
    extra = set(entry.keys()) - allowed
    if extra:
        error_exit(f"多余字段: {extra}  ({source})")

    missing = REQUIRED_FIELDS - set(entry.keys())
    if missing:
        error_exit(f"缺少必填字段: {missing}  ({source})")

    ch = entry.get("challenge")
    if ch not in VALID_CHALLENGES:
        error_exit(f"challenge 无效: '{ch}' ({sorted(VALID_CHALLENGES)})  ({source})")

    st = entry.get("status")
    if st not in VALID_STATUS:
        error_exit(f"status 无效: '{st}' (solved/partial)  ({source})")
    if st == "solved":
        speculative = _contains_speculative_terms(entry)
        if speculative:
            path, term = speculative
            error_exit(f"solved 条目包含未验证推测: {path} 命中 '{term}'  ({source})")

    name = entry.get("name", "")
    if not isinstance(name, str) or not (1 <= len(name) <= 60):
        error_exit(f"name 长度不符 ({len(name)})  ({source})")

    tech = entry.get("technique", "")
    if not isinstance(tech, str) or not (1 <= len(tech) <= 120):
        error_exit(f"technique 长度不符 ({len(tech)})  ({source})")

    exp_list = entry.get("experience", [])
    if not isinstance(exp_list, list) or not (3 <= len(exp_list) <= 8):
        error_exit(f"experience 应为 3-8 条 ({len(exp_list)})  ({source})")
    for j, item in enumerate(exp_list):
        if not isinstance(item, str) or not (15 <= len(item) <= 150):
            error_exit(f"experience[{j}] 长度 {len(item)} (应 15-150)  ({source})")

    # failed_attempts
    fa = entry.get("failed_attempts")
    if fa is not None:
        if not isinstance(fa, list) or not (1 <= len(fa) <= 5):
            error_exit(f"failed_attempts 应为 1-5 条 ({len(fa)})  ({source})")
        fa_fields = {"approach", "why_failed", "lesson"}
        for j, item in enumerate(fa):
            if not isinstance(item, dict):
                error_exit(f"failed_attempts[{j}] 应为 object  ({source})")
            missing_sub = fa_fields - set(item.keys())
            extra_sub = set(item.keys()) - fa_fields
            if missing_sub:
                error_exit(f"failed_attempts[{j}] 缺少: {missing_sub}  ({source})")
            if extra_sub:
                error_exit(f"failed_attempts[{j}] 多余: {extra_sub}  ({source})")
            for field in fa_fields:
                val = item.get(field, "")
                if not isinstance(val, str) or not (15 <= len(val) <= 150):
                    error_exit(f"failed_attempts[{j}].{field} 长度 {len(val)} (应 15-150)  ({source})")

    # artifacts
    arts = entry.get("artifacts")
    if arts is not None:
        if not isinstance(arts, dict):
            error_exit(f"artifacts 应为 object, 实际 {type(arts).__name__}  ({source})")
        for k, v in arts.items():
            if not isinstance(v, (str, int, float)):
                error_exit(f"artifacts.{k} 值只能为 string/number  ({source})")

    forbidden = _find_forbidden_json_content(entry)
    if forbidden:
        path, detail = forbidden
        error_exit(f"含禁止内容: {path} — {detail}  ({source})")


# ── 去重 ─────────────────────────────────────────────────────────────────

def _is_dup(target_file: Path, entry: dict) -> bool:
    if not target_file.exists():
        return False
    try:
        for line in target_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("name") == entry.get("name") and rec.get("technique") == entry.get("technique"):
                return True
    except (OSError, UnicodeDecodeError) as exc:
        warn(f"无法读取 {target_file}: {exc}")
    return False


# ── 提交 ─────────────────────────────────────────────────────────────────

def _commit(entry: dict) -> None:
    _validate(entry)

    challenge = entry["challenge"]
    dir_name = CHALLENGE_TO_DIR[challenge]
    file_name = f"{dir_name}.jsonl"
    stores = _iter_stores()

    append_count = 0
    skip_count = 0
    json_line = json.dumps(entry, ensure_ascii=False) + "\n"

    for store in stores:
        target = store / dir_name / file_name
        if not target.parent.is_dir():
            continue
        if _is_dup(target, entry):
            skip_count += 1
            continue
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "a", encoding="utf-8") as fh:
                fh.write(json_line)
            append_count += 1
        except OSError as exc:
            warn(f"{store} 写入失败: {exc}")

    if not stores:
        error_exit("未找到 exp 仓库 (~/.claude 或 ~/.codex)")

    action = "appended" if append_count > 0 else "duplicate"
    if OUTPUT_JSON:
        output({"status": action, "stores": len(stores), "appended": append_count, "skipped": skip_count})
    else:
        print(f"✅ {append_count}/{skip_count} 仓库已追加/跳过")
        if skip_count > 0:
            info("部分仓库因重复跳过")


# ── 调试同步 ─────────────────────────────────────────────────────────────

def _debug_syn(target_dir: str | None = None) -> None:
    claude_exp = Path.home() / ".claude" / "skills" / "ctf-agents-team" / "exp"
    if not claude_exp.is_dir():
        error_exit(f"源目录不存在: {claude_exp}")

    target = Path(target_dir).resolve() if target_dir else Path.cwd() / "exp"
    exists = target.is_dir()
    try:
        shutil.copytree(str(claude_exp), str(target), dirs_exist_ok=exists)
        print(f"✅ 同步完成: {claude_exp} -> {target}")
    except OSError as exc:
        error_exit(f"同步失败: {exc}")


# ── 主入口 ───────────────────────────────────────────────────────────────

def main() -> None:
    global OUTPUT_JSON
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="统一经验库追加与同步工具")
    parser.add_argument("--commit", help="一条 JSON 经验记录")
    parser.add_argument("--debug-syn", nargs="?", const="", metavar="TARGET_DIR", help="将 ~/.claude 的 exp/ 同步到目标目录；不填则同步到当前目录 exp/")
    parser.add_argument("--json", action="store_true", help="输出精简 JSON")
    args = parser.parse_args()
    OUTPUT_JSON = args.json

    if args.commit is not None and args.debug_syn is not None:
        error_exit("--commit 与 --debug-syn 不能同时使用")

    if args.commit is not None:
        try:
            entry = json.loads(args.commit)
        except json.JSONDecodeError as exc:
            error_exit(f"JSON 解析失败: {exc}")
        if not isinstance(entry, dict):
            error_exit(f"经验条目必须是 JSON 对象, 不是 {type(entry).__name__}")
        _commit(entry)
        return

    if args.debug_syn is not None:
        _debug_syn(args.debug_syn or None)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
