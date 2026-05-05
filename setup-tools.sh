#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# setup-tools.sh — installs everything tools.py needs on a fresh Kali
#
#   Repo:   https://github.com/1337codes/OSCP-HTTP-SMB-File-Transfer-Server
#   Usage:  chmod +x setup-tools.sh && ./setup-tools.sh
# ─────────────────────────────────────────────────────────────────────

set -e

# colours
R='\033[91m'; G='\033[92m'; Y='\033[93m'; C='\033[96m'; B='\033[1m'; N='\033[0m'

banner() { echo -e "\n${C}${B}[*]${N} ${B}$1${N}"; }
ok()     { echo -e "${G}[+]${N} $1"; }
warn()   { echo -e "${Y}[!]${N} $1"; }
fail()   { echo -e "${R}[-]${N} $1" >&2; }

# need sudo
if [[ $EUID -ne 0 ]]; then
    if ! command -v sudo &>/dev/null; then
        fail "Run as root or install sudo."
        exit 1
    fi
    SUDO="sudo"
else
    SUDO=""
fi

banner "DualServe (tools.py) installer"

# ─── apt update ──────────────────────────────────────────────────────
banner "Updating package index"
$SUDO apt-get update -qq
ok "apt index updated"

# ─── core deps ───────────────────────────────────────────────────────
banner "Installing core dependencies"
$SUDO apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-impacket
ok "python3 + impacket installed"

# ─── verify the SMB binary lands in PATH ─────────────────────────────
banner "Verifying impacket-smbserver"
if command -v impacket-smbserver &>/dev/null; then
    ok "impacket-smbserver is on PATH ($(command -v impacket-smbserver))"
else
    warn "impacket-smbserver not in PATH — trying pip fallback"
    $SUDO pip3 install --break-system-packages impacket
    if command -v impacket-smbserver &>/dev/null; then
        ok "impacket-smbserver installed via pip"
    else
        fail "impacket-smbserver still missing — SMB mode won't work"
    fi
fi

# ─── python 3.13+ shim (cgi module removed) ──────────────────────────
PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [[ "$(printf '%s\n' "3.13" "$PYVER" | sort -V | head -n1)" == "3.13" ]]; then
    banner "Python ${PYVER} detected — installing legacy-cgi shim"
    $SUDO pip3 install --break-system-packages legacy-cgi
    ok "legacy-cgi installed"
fi

# ─── done ────────────────────────────────────────────────────────────
echo
echo -e "${G}${B}[✓] tools.py ready to roll.${N}"
echo -e "    HTTP only:   ${C}sudo python3 tools.py${N}"
echo -e "    HTTP + SMB:  ${C}sudo python3 tools.py -smb${N}"
echo -e "    Alias:       ${C}tools${N}  (if your alias is set)"
