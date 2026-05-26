# CTF Agents Team

A unified CTF challenge-solving orchestration system for [Claude Code](https://docs.anthropic.com/en/docs/claude-code). Provides reconnaissance, classification, specialist dispatch, flag verification, and detailed writeup generation — all driven by a single slash command.

## Features

- **7-Phase Workflow**: Session Recovery → Competition Intake → Challenge Triage → Environment Check → Solve → Verification → Writeup
- **7 Specialist Agents**: Pwn, Web, Reverse, Mobile, Crypto, Misc, Forensics — each with technique cheatsheets and copy-paste templates
- **12 Deep Knowledge Files**: Python/Bash jails, encodings, games/VMs, Linux privesc, CTFd API, RF/SDR, DNS exploitation (~196KB)
- **Structured Tracking**: `wp.process` with Stage numbering, `flag.log` index, competition-level planning files
- **Planning Discipline**: 2-Action Rule, 3-Strike Protocol, 5-Question Reboot Test (from planning-with-files / Manus patterns)
- **Auto-Solve Quick Check**: robots.txt, .git leak, default credentials, known CVE — fast-path before deep analysis
- **CTFd Integration**: API-based challenge listing, attachment download, flag submission

## Installation

### As a project-level skill (recommended)

```bash
cd your-ctf-workspace
mkdir -p .skills
git clone https://github.com/YOUR_USERNAME/ctf-agents-team .skills/ctf-agents-team
```

### As a global skill (available in all projects)

```bash
mkdir -p ~/.claude/skills
git clone https://github.com/YOUR_USERNAME/ctf-agents-team ~/.claude/skills/ctf-agents-team
```

## Usage

In Claude Code, invoke with the slash command. Two primary modes are supported:

### Solo Mode — Solve all challenges in parallel

```
/ctf-agents-team BugKu
/ctf-agents-team BugKu/          # trailing slash OK
```

Scans the competition directory, discovers all challenges grouped by category (Web, Pwn, Re, Misc, ...), then launches one agent per category in parallel. Each category agent works through its challenges sequentially. Ideal for competitions where you want maximum throughput.

### Single-Challenge Mode — Focus on one challenge

```
/ctf-agents-team BugKu/Web/one things
```

Jumps directly into a specific challenge and runs the full solve pipeline (triage → environment check → solve → verify → writeup).

### Other invocations

```
# New challenge from description
/ctf-agents-team ISCC 新题 Web 叫 A bridge so far，地址 http://x.x.x.x:8080

# Resume previous session (no arguments)
/ctf-agents-team
```

### What happens

**Single-Challenge Mode:**
1. **Challenge Triage** — Identifies file types, searches experience library, classifies into one of 7 categories
2. **Environment Check** — Verifies required tools are available, installs missing pip packages
3. **Solve** — Loads the relevant specialist reference, applies techniques, tracks progress in `wp.process`
4. **Verification** — Confirms flag with confidence levels (guess → evidence → verified)
5. **Writeup** — Generates detailed `题目名称.md` with reproducible steps + standalone `exploit.py`

**Solo Mode:**
1. **Competition Intake** — Scans the competition directory, creates `task_plan.md`, `findings.md`, `progress.md`
2. **Solo Dispatch** — Groups challenges by category, prioritizes, launches parallel agents
3. **Parallel Solve** — Each category agent runs the full triage→solve→writeup pipeline per challenge
4. **Collection** — Lead agent collects all flags into `flag.log`, updates progress

### Directory structure created

```
ISCC/                           ← Competition root
├── task_plan.md                ← All challenges overview + progress
├── findings.md                 ← Cross-challenge discoveries
├── progress.md                 ← Session timeline
├── flag.log                    ← Verified flags index (Lead Agent only)
├── web/
│   └── Oracle's Whisper/
│       ├── (challenge files)
│       ├── wp.process          ← Stage-by-stage solving log
│       ├── flag.found          ← Flag intermediate file
│       └── Oracle's Whisper.md ← Final detailed writeup
├── pwn/
├── re/
├── mobile/
├── misc/
├── crypto/
└── forensics/
```

## Project Structure

```
ctf-agents-team/
├── SKILL.md                    ← Main orchestrator (auto-loaded by Claude Code)
├── references/                 ← Specialist technique cheatsheets
│   ├── pwn-agent.md            ← ROP, heap, fmt string, SROP, one_gadget, pwndbg
│   ├── web-agent.md            ← SQLi, SSTI, XXE, GraphQL, race condition, file upload
│   ├── reverse-agent.md        ← r2, Ghidra headless, angr, rizin, pycdc, UPX
│   ├── mobile-agent.md         ← APK, smali, Frida, Flutter/RN, root detection
│   ├── crypto-agent.md         ← RSA, AES, ECC, DSA nonce, padding oracle, LLL
│   ├── misc-agent.md           ← Stego, encodings, jails, PDF, Office, QR
│   ├── forensics-agent.md      ← PCAP, memory, disk, USB, registry, timeline
│   ├── orchestrator-playbook.md ← Dispatch rules, auto-solve patterns, CTFd integration
│   ├── environment-baseline.md  ← Tool requirements + installation guide
│   └── wp-format.md            ← wp.process + final WP format specification
├── knowledge/                  ← Deep technical references (loaded on demand)
│   ├── pyjails.md              ← Python jail escapes (671 lines)
│   ├── bashjails.md            ← Bash jail escapes
│   ├── encodings.md            ← Encodings, QR, esoteric languages
│   ├── encodings-advanced.md   ← Verilog, Gray code, SMS PDU, MaxiCode
│   ├── games-and-vms.md        ← WASM, VM, Z3, K8s (4 parts)
│   ├── games-and-vms-2.md
│   ├── games-and-vms-3.md
│   ├── games-and-vms-4.md
│   ├── linux-privesc.md        ← sudo, cron, SUID, NFS, kernel exploits
│   ├── ctfd-navigation.md      ← CTFd API navigation
│   ├── rf-sdr.md               ← RF/SDR/IQ signal processing
│   └── dns.md                  ← DNS exploitation
└── scripts/
    ├── bootstrap-linux.sh      ← Tool installation script (pyenv + full baseline)
    ├── AddExp.py               ← Unified exp append — syncs ~/.claude and ~/.codex stores
    ├── ClearExp.py             ← Clean exp_candidate.jsonl + credential scan
    └── CheckFiles.py           ← Strong file existence check + engineering validation
```

## Prerequisites

- **Claude Code** CLI or IDE extension
- **Linux** environment (Kali / Ubuntu / Debian / WSL2)
- **Python 3.8+** with pip
- Common CTF tools (the skill will check and help install missing ones)

### Recommended tools

The bootstrap script installs the full baseline toolset defined in [references/environment-baseline.md](references/environment-baseline.md):

```bash
bash .skills/ctf-agents-team/scripts/bootstrap-linux.sh
```

Or install manually — see [references/environment-baseline.md](references/environment-baseline.md) for the full list.

## Experience Library

The skill integrates with an `exp/` directory for cross-competition knowledge reuse:

```
exp/
├── web/web.jsonl
├── pwn/pwn.jsonl
├── re/re.jsonl          ← includes Mobile (distinguished by field)
├── misc/misc.jsonl
├── crypto/crypto.jsonl
└── forensics/forensics.jsonl
```

Each line is a JSON record (schema defined in [exp/README.md](exp/README.md)):
```json
{"challenge":"Web","name":"SSTI Bypass","technique":"Jinja2 SSTI + config.__class__ chain","status":"solved","experience":["SSTI 检测先用 {{7*7}} 确认模板引擎类型","Jinja2 用 __class__.__mro__[1].__subclasses__() 遍历可用类","WAF 过滤双花括号时尝试 {% print %} 替代"]}
```

The skill searches this library during reconnaissance and appends new entries after solving.

## Customization

### Adding new knowledge

Drop `.md` files into `knowledge/`, then update the index in:
- `SKILL.md` Section 8 (参考文档索引)
- `references/orchestrator-playbook.md` (知识加载指南)

### Adding new categories

1. Create `references/new-agent.md` following the existing pattern
2. Add the category to the classification matrix in `SKILL.md`
3. Add to the specialist selection matrix in `references/orchestrator-playbook.md`

## License

MIT
