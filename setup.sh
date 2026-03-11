#!/bin/bash
#
# AutoPwn v3.1.0 - One-click Setup
#
# Usage: chmod +x setup.sh && ./setup.sh
#
# Installs all dependencies on Kali Linux / Debian / Ubuntu.
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[-]${NC} $1"; }
step()  { echo -e "\n${CYAN}=== $1 ===${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---- Prerequisites ----
step "Checking prerequisites"

if [ "$(id -u)" -eq 0 ]; then
    warn "Running as root; consider using a regular user"
    SUDO=""
else
    SUDO="sudo"
fi

if ! command -v python3 &>/dev/null; then
    err "python3 not found, installing..."
    $SUDO apt update && $SUDO apt install -y python3 python3-pip python3-venv
fi

PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYMAJ=$(echo "$PYVER" | cut -d. -f1)
PYMIN=$(echo "$PYVER" | cut -d. -f2)

if [ "$PYMAJ" -lt 3 ] || { [ "$PYMAJ" -eq 3 ] && [ "$PYMIN" -lt 11 ]; }; then
    err "Python >= 3.11 required, got $PYVER"
    exit 1
fi
info "Python $PYVER OK"

# ---- System packages ----
step "Installing system dependencies"

PKGS=(
    gdb
    gcc
    g++
    binutils
    nasm
    python3-pip
    python3-dev
    libffi-dev
    libssl-dev
    ruby
    ruby-dev
)

MISSING=()
for pkg in "${PKGS[@]}"; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        MISSING+=("$pkg")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    info "Installing missing packages: ${MISSING[*]}"
    $SUDO apt update
    $SUDO apt install -y "${MISSING[@]}"
else
    info "System packages OK"
fi

# ---- radare2 ----
step "Installing radare2"

if command -v r2 &>/dev/null; then
    info "radare2 already installed"
else
    if command -v apt &>/dev/null && apt-cache show radare2 &>/dev/null 2>&1; then
        info "Installing radare2 from apt..."
        $SUDO apt install -y radare2
    else
        info "Installing radare2 from GitHub..."
        git clone --depth=1 https://github.com/radareorg/radare2.git /tmp/radare2-build && \
            /tmp/radare2-build/sys/install.sh && \
            rm -rf /tmp/radare2-build || \
            warn "radare2 install failed; some analysis features will be unavailable"
    fi
fi

# ---- Install autopwn (editable) ----
step "Installing autopwn"

PIP_ARGS="--break-system-packages"
python3 -m pip install --help 2>/dev/null | grep -q "break-system-packages" || PIP_ARGS=""

info "Installing autopwn in editable mode..."
$SUDO python3 -m pip install $PIP_ARGS -e "$SCRIPT_DIR"

# LibcSearcher for remote libc identification
if python3 -c "import LibcSearcher" &>/dev/null; then
    info "LibcSearcher already installed"
else
    info "Installing LibcSearcher..."
    $SUDO python3 -m pip install $PIP_ARGS LibcSearcher || warn "LibcSearcher install failed; remote libc identification may be limited"
fi

# ---- Optional: angr ----
step "Installing optional dependencies"

if python3 -c "import angr" &>/dev/null; then
    info "angr already installed"
else
    info "Installing angr (white-box engine, may take a few minutes)..."
    $SUDO python3 -m pip install $PIP_ARGS angr || warn "angr install failed; use --blackbox mode"
fi

# ---- Ruby gems ----
step "Installing security tools"

if command -v one_gadget &>/dev/null; then
    info "one_gadget already installed"
else
    info "Installing one_gadget..."
    $SUDO gem install one_gadget 2>/dev/null || warn "one_gadget install failed"
fi

if command -v seccomp-tools &>/dev/null; then
    info "seccomp-tools already installed"
else
    info "Installing seccomp-tools..."
    $SUDO gem install seccomp-tools 2>/dev/null || warn "seccomp-tools install failed"
fi

# ---- Verify ----
step "Verifying installation"

PASS=0
FAIL=0

check() {
    local name="$1"
    local cmd="$2"
    if eval "$cmd" &>/dev/null; then
        info "$name OK"
        PASS=$((PASS + 1))
    else
        warn "$name not ready"
        FAIL=$((FAIL + 1))
    fi
}

check "python3"        "python3 --version"
check "pwntools"       "python3 -c 'import pwn'"
check "angr"           "python3 -c 'import angr'"
check "gdb"            "command -v gdb"
check "radare2"        "command -v r2"
check "ROPgadget"      "command -v ROPgadget"
check "one_gadget"     "command -v one_gadget"
check "seccomp-tools"  "command -v seccomp-tools"
check "autopwn"        "python3 -m autopwn --version"

# ---- Done ----
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${GREEN}  AutoPwn v3.1.0 setup complete${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo -e "  Passed: ${GREEN}${PASS}${NC}  Not ready: ${YELLOW}${FAIL}${NC}"
echo ""
echo -e "  Usage:"
echo -e "    ${CYAN}autopwn ./binary${NC}                  Auto-exploit"
echo -e "    ${CYAN}autopwn ./binary -l ./libc.so${NC}     Specify libc"
echo -e "    ${CYAN}autopwn ./binary -r host:port${NC}     Remote target"
echo -e "    ${CYAN}autopwn ./binary -a${NC}               Analyze only"
echo ""

if [ $FAIL -gt 0 ]; then
    warn "Some optional components are not ready; core functionality is unaffected"
fi
