#!/usr/bin/env bash
# CTF Agents Team — Linux Bootstrap Script
# Usage: bash bootstrap-linux.sh [workspace_dir]
# Installs the full baseline toolset defined in references/environment-baseline.md
# Supports: Kali/Ubuntu/Debian/WSL2

set -euo pipefail

WORKSPACE_DIR="${1:-$PWD}"
RECOMMENDED_PYTHON="3.11.0"

log() {
  printf '[ctf-bootstrap] %s\n' "$*"
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

has_package() {
  dpkg -l "$1" 2>/dev/null | grep -q '^ii' 2>/dev/null
}

# === pyenv Setup ===
setup_pyenv() {
  if has_cmd pyenv; then
    log "pyenv already installed: $(pyenv --version)"
  else
    log "pyenv not found. Installing..."
    if has_cmd curl; then
      curl -fsSL https://pyenv.run | bash
    else
      log "ERROR: curl required to install pyenv. Install curl first."
      return 1
    fi
    # Add pyenv to current session
    export PYENV_ROOT="$HOME/.pyenv"
    export PATH="$PYENV_ROOT/bin:$PATH"
  fi

  # Initialize pyenv for current session
  if has_cmd pyenv; then
    eval "$(pyenv init -)" 2>/dev/null || true
  fi

  # Install recommended Python version
  if pyenv versions --bare 2>/dev/null | grep -q "^${RECOMMENDED_PYTHON}$"; then
    log "Python $RECOMMENDED_PYTHON already installed via pyenv"
  else
    log "Installing Python $RECOMMENDED_PYTHON via pyenv..."
    pyenv install -s "$RECOMMENDED_PYTHON"
  fi

  pyenv global "$RECOMMENDED_PYTHON"
  log "Active Python: $(python --version 2>&1)"
}

# === System packages ===
install_apt_packages() {
  local packages=(
    # Build essentials
    curl git jq wget unzip zip p7zip-full file make build-essential pkg-config
    ca-certificates gnupg software-properties-common
    # Libraries for Python build (pyenv needs these)
    libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev
    libffi-dev liblzma-dev xz-utils tk-dev libncursesw5-dev libgdbm-dev libnss3-dev
    python3-dev
    # Binary analysis
    gdb gdb-multiarch patchelf binutils strace ltrace socat netcat-openbsd
    # RE & Forensics
    radare2 binwalk ffmpeg pngcheck foremost
    libimage-exiftool-perl steghide zbar-tools tshark
    # Compression
    zstd upx-ucl
    # Cracking
    john hashcat
    # Web
    sqlmap gobuster ffuf
    # Java & Android
    default-jdk adb
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
  local pip_cmd

  # Determine pip command: pyenv python > .venv > system pip3
  if has_cmd pyenv && pyenv which pip >/dev/null 2>&1; then
    pip_cmd="$(pyenv which pip)"
    log "Using pyenv pip: $pip_cmd"
  elif [[ -f "$WORKSPACE_DIR/.venv/bin/pip3" ]]; then
    pip_cmd="$WORKSPACE_DIR/.venv/bin/pip3"
    log "Using .venv pip"
  elif [[ -f "$WORKSPACE_DIR/.venv/bin/pip" ]]; then
    pip_cmd="$WORKSPACE_DIR/.venv/bin/pip"
    log "Using .venv pip"
  else
    pip_cmd="pip3"
    log "Using system pip3"
  fi

  local packages=(
    # Pwn
    pwntools ROPGadget ropper
    # Crypto
    z3-solver pycryptodome gmpy2 sympy
    # RE
    capstone unicorn angr r2pipe
    # Web
    requests httpx beautifulsoup4 lxml
    # Forensics / Misc
    scapy pyshark python-magic
    # Image / Signal
    numpy pillow opencv-python
    # Misc utilities
    randcrack owiener
  )

  log "Installing ${#packages[@]} Python packages..."
  $pip_cmd install --upgrade pip setuptools wheel 2>/dev/null || true
  $pip_cmd install --upgrade "${packages[@]}" || {
    log "pip install failed, trying with tsinghua mirror..."
    $pip_cmd install -i https://pypi.tuna.tsinghua.edu.cn/simple --upgrade "${packages[@]}"
  }
}

# === Ruby tools ===
install_ruby_tools() {
  if has_cmd gem; then
    if ! has_cmd one_gadget; then
      log "Installing one_gadget (Ruby gem)..."
      gem install one_gadget || log "one_gadget install failed (may need sudo)"
    else
      log "one_gadget already installed"
    fi
  else
    log "Ruby/gem not found, skipping one_gadget. Install ruby first if needed."
  fi
}

# === Optional tools ===
install_optional() {
  # apktool
  if ! has_cmd apktool; then
    log "Installing apktool..."
    sudo apt-get install -y apktool 2>/dev/null || log "apktool not available via apt"
  fi

  # jadx
  if ! has_cmd jadx; then
    log "jadx not installed. Install manually: https://github.com/skylot/jadx/releases"
  fi

  # checksec (comes with pwntools)
  if ! has_cmd checksec; then
    log "checksec available via pwntools (checksec --file=binary)"
  fi

  # volatility3
  if ! has_cmd vol3 && ! has_cmd volatility3; then
    log "volatility3 not installed. Install if needed: pip install volatility3"
  fi

  # zsteg (Ruby gem for PNG/BMP stego)
  if has_cmd gem; then
    if ! has_cmd zsteg; then
      log "Installing zsteg (Ruby gem)..."
      gem install zsteg || log "zsteg install failed"
    fi
  fi
}

# === Validation ===
validate() {
  log "=== Validation ==="
  local python_cmd="python3"
  if has_cmd pyenv; then
    python_cmd="$(pyenv which python 2>/dev/null || echo python3)"
  fi

  local checks=(
    "python3:$python_cmd --version"
    "pip:$python_cmd -m pip --version"
    "gdb:gdb --version 2>/dev/null | head -1"
    "r2:r2 -v 2>/dev/null | head -1"
    "binwalk:binwalk --help 2>/dev/null | head -1"
    "tshark:tshark --version 2>/dev/null | head -1"
    "exiftool:exiftool -ver"
    "one_gadget:one_gadget --version 2>/dev/null | head -1"
  )

  for check in "${checks[@]}"; do
    local name="${check%%:*}"
    local cmd="${check#*:}"
    printf "  %-14s" "$name:"
    eval "$cmd" 2>/dev/null || echo "NOT FOUND"
  done

  # Python package verification (using pyenv python)
  log "--- Python packages ---"
  local py_packages=(
    "pwn:pwntools"
    "Crypto:pycryptodome"
    "z3:z3-solver"
    "angr:angr"
    "gmpy2:gmpy2"
    "capstone:capstone"
    "requests:requests"
    "scapy:scapy"
  )

  for pkg_check in "${py_packages[@]}"; do
    local module="${pkg_check%%:*}"
    local display="${pkg_check#*:}"
    printf "  %-14s" "$display:"
    $python_cmd -c "import $module; print('OK')" 2>/dev/null || echo "NOT FOUND"
  done

  log "=== Validation complete ==="
}

# === Main ===
main() {
  log "Bootstrap starting for: $WORKSPACE_DIR"
  log "System: $(uname -a)"

  install_apt_packages
  setup_pyenv
  install_pip_packages
  install_ruby_tools
  install_optional
  validate

  log "Bootstrap complete"
  log "Note: Add the following to your shell profile if not already present:"
  log '  export PYENV_ROOT="$HOME/.pyenv"'
  log '  export PATH="$PYENV_ROOT/bin:$PATH"'
  log '  eval "$(pyenv init -)"'
}

main "$@"
