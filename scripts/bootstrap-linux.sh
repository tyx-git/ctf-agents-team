#!/usr/bin/env bash
# CTF Agents Team — Linux Bootstrap Script
# Usage: bash bootstrap-linux.sh [workspace_dir]
# Installs CTF tools on Linux (Kali/Ubuntu/Debian/WSL2)

set -euo pipefail

WORKSPACE_DIR="${1:-$PWD}"

log() {
  printf '[ctf-bootstrap] %s\n' "$*"
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

has_package() {
  dpkg -l "$1" >/dev/null 2>&1
}

# === System packages ===
install_apt_packages() {
  local packages=(
    # Build essentials
    curl git jq wget unzip zip p7zip-full file make build-essential pkg-config
    ca-certificates gnupg software-properties-common
    # Libraries for Python build
    libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev
    libffi-dev liblzma-dev xz-utils tk-dev libncursesw5-dev libgdbm-dev libnss3-dev
    # Binary analysis
    gdb gdb-multiarch patchelf binutils strace ltrace socat netcat-openbsd
    # RE & Forensics
    radare2 binwalk ffmpeg pngcheck foremost
    libimage-exiftool-perl steghide zbar-tools tshark
    # Cracking
    john hashcat
    # Web
    sqlmap gobuster ffuf
    # Java & Android
    default-jdk
  )

  local install_list=()
  local skipped=()

  for pkg in "${packages[@]}"; do
    if apt-cache show "$pkg" >/dev/null 2>&1; then
      if ! has_package "$pkg"; then
        install_list+=("$pkg")
      fi
    else
      skipped+=("$pkg")
    fi
  done

  if ((${#install_list[@]} > 0)); then
    log "Installing ${#install_list[@]} apt packages..."
    sudo apt-get update -qq
    sudo apt-get install -y --no-install-recommends "${install_list[@]}"
  else
    log "All apt packages already installed"
  fi

  if ((${#skipped[@]} > 0)); then
    log "Skipped unavailable: ${skipped[*]}"
  fi
}

# === Python packages ===
install_pip_packages() {
  local pip_cmd="pip3"

  # Use .venv if exists
  if [[ -f "$WORKSPACE_DIR/.venv/bin/pip3" ]]; then
    pip_cmd="$WORKSPACE_DIR/.venv/bin/pip3"
    log "Using .venv pip"
  elif [[ -f "$WORKSPACE_DIR/.venv/bin/pip" ]]; then
    pip_cmd="$WORKSPACE_DIR/.venv/bin/pip"
    log "Using .venv pip"
  fi

  local packages=(
    pwntools ROPGadget ropper
    z3-solver pycryptodome capstone unicorn
    requests httpx beautifulsoup4 lxml
    scapy pyshark r2pipe
    numpy sympy pillow opencv-python python-magic
  )

  log "Installing Python packages..."
  $pip_cmd install --upgrade pip setuptools wheel 2>/dev/null || true
  $pip_cmd install --upgrade "${packages[@]}" || {
    log "pip install failed, trying with tsinghua mirror..."
    $pip_cmd install -i https://pypi.tuna.tsinghua.edu.cn/simple --upgrade "${packages[@]}"
  }
}

# === Optional tools ===
install_optional() {
  # apktool
  if ! has_cmd apktool; then
    log "Installing apktool..."
    sudo apt-get install -y apktool 2>/dev/null || log "apktool not available via apt"
  fi

  # checksec (pip)
  if ! has_cmd checksec; then
    log "checksec available via pwntools (checksec --file=binary)"
  fi

  # volatility3
  if ! has_cmd vol3 && ! has_cmd volatility3; then
    log "volatility3 not installed. Install manually if needed: pip3 install volatility3"
  fi
}

# === Validation ===
validate() {
  log "=== Validation ==="
  echo -n "  python3: "; python3 --version 2>/dev/null || echo "NOT FOUND"
  echo -n "  pip3: "; pip3 --version 2>/dev/null || echo "NOT FOUND"
  echo -n "  gdb: "; gdb --version 2>/dev/null | head -1 || echo "NOT FOUND"
  echo -n "  r2: "; r2 -v 2>/dev/null | head -1 || echo "NOT FOUND"
  echo -n "  binwalk: "; binwalk --help 2>/dev/null | head -1 || echo "NOT FOUND"
  echo -n "  tshark: "; tshark --version 2>/dev/null | head -1 || echo "NOT FOUND"
  echo -n "  exiftool: "; exiftool -ver 2>/dev/null || echo "NOT FOUND"
  echo -n "  pwntools: "; python3 -c "import pwn; print(pwn.version)" 2>/dev/null || echo "NOT FOUND"
  log "=== Validation complete ==="
}

# === Main ===
main() {
  log "Bootstrap starting for: $WORKSPACE_DIR"
  log "System: $(uname -a)"

  install_apt_packages
  install_pip_packages
  install_optional
  validate

  log "Bootstrap complete"
}

main "$@"
