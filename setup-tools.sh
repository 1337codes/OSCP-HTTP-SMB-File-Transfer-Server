#!/usr/bin/env bash
# =============================================================================
# Pentest Tools Installer — cross-distro with interface picker
# =============================================================================
#
# Manages a personal pentest toolkit. Each tool is a github repo cloned into
# a configurable folder, with shell aliases auto-generated for bash, zsh, fish.
#
# Tool definitions live in tools.json (next to this script).
#
# CROSS-DISTRO BEHAVIOR:
#   - Detects pacman (Arch family) or apt (Debian/Kali) automatically
#   - Picks the correct package names per distro
#   - 'fix-impacket' is a no-op on Kali (symlinks already provided)
#
# INTERFACE PICKER:
#   Tools can opt into an interactive interface picker by setting
#   "prompt_interface": true in their tools.json entry. The user is shown a
#   list of available interfaces with tun0 as default. The chosen interface
#   is exported as $IFACE and $IFACE_IP, available in the command.
#
# =============================================================================

set -uo pipefail

# =============================================================================
# Paths & defaults
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
readonly SCRIPT_DIR

readonly TOOLS_JSON="${TOOLS_JSON:-$SCRIPT_DIR/tools.json}"
TOOLS_DIR="${TOOLS_DIR:-$HOME/Desktop/tools}"

readonly ALIAS_FILE_BASH="$HOME/.config/tools-aliases.sh"
readonly ALIAS_FILE_FISH="$HOME/.config/fish/conf.d/tools-aliases.fish"
readonly IFACE_HELPER_BASH="$HOME/.config/tools-iface-helper.sh"
readonly IFACE_HELPER_FISH="$HOME/.config/fish/conf.d/tools-iface-helper.fish"

readonly LOG_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/tools-installer"
LOG_FILE="$LOG_DIR/tools-setup-$(date +%Y%m%d-%H%M%S).log"

mkdir -p "$LOG_DIR"

# =============================================================================
# Distro detection
# =============================================================================

DISTRO_FAMILY=""
DISTRO_ID=""
PKG_MANAGER=""

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        local id_like="${ID_LIKE:-}"

        case "$DISTRO_ID,$id_like" in
            arch*|cachyos*|manjaro*|endeavouros*|blackarch*|garuda*|*arch*)
                DISTRO_FAMILY="arch" ;;
            kali*|debian*|ubuntu*|parrot*|pop*|linuxmint*|*debian*|*ubuntu*)
                DISTRO_FAMILY="debian" ;;
            *)
                DISTRO_FAMILY="unknown" ;;
        esac
    fi

    if command -v pacman >/dev/null 2>&1; then
        PKG_MANAGER="pacman"
        [[ -z "$DISTRO_FAMILY" || "$DISTRO_FAMILY" == "unknown" ]] && DISTRO_FAMILY="arch"
    elif command -v apt >/dev/null 2>&1; then
        PKG_MANAGER="apt"
        [[ -z "$DISTRO_FAMILY" || "$DISTRO_FAMILY" == "unknown" ]] && DISTRO_FAMILY="debian"
    fi
}

# =============================================================================
# Output helpers
# =============================================================================

readonly C_RESET=$'\033[0m'
readonly C_RED=$'\033[31m'
readonly C_GREEN=$'\033[32m'
readonly C_YELLOW=$'\033[33m'
readonly C_BLUE=$'\033[34m'
readonly C_BOLD=$'\033[1m'
readonly C_DIM=$'\033[2m'

info()    { printf "${C_BLUE}[INFO]${C_RESET}  %s\n" "$*" | tee -a "$LOG_FILE" >&2; }
ok()      { printf "${C_GREEN}[OK]${C_RESET}    %s\n" "$*" | tee -a "$LOG_FILE" >&2; }
warn()    { printf "${C_YELLOW}[WARN]${C_RESET}  %s\n" "$*" | tee -a "$LOG_FILE" >&2; }
err()     { printf "${C_RED}[ERR]${C_RESET}   %s\n" "$*" | tee -a "$LOG_FILE" >&2; }
section() { printf "\n${C_BOLD}${C_BLUE}=== %s ===${C_RESET}\n" "$*" | tee -a "$LOG_FILE" >&2; }

confirm() {
    local prompt="${1:-Proceed?}"
    [[ "${ASSUME_YES:-0}" -eq 1 ]] && return 0
    read -rp "$prompt [Y/n] " ans
    [[ -z "$ans" || "$ans" =~ ^[YyJj]$ ]]
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        err "Required command not found: $cmd"
        case "$cmd" in
            jq)
                if [[ "$PKG_MANAGER" == "pacman" ]]; then
                    info "Install with: sudo pacman -S jq"
                elif [[ "$PKG_MANAGER" == "apt" ]]; then
                    info "Install with: sudo apt install jq"
                fi ;;
            git)
                if [[ "$PKG_MANAGER" == "pacman" ]]; then
                    info "Install with: sudo pacman -S git"
                elif [[ "$PKG_MANAGER" == "apt" ]]; then
                    info "Install with: sudo apt install git"
                fi ;;
        esac
        exit 1
    fi
}

# =============================================================================
# JSON helpers
# =============================================================================

ensure_tools_json() {
    if [[ ! -f "$TOOLS_JSON" ]]; then
        info "tools.json not found, creating empty one at $TOOLS_JSON"
        cat > "$TOOLS_JSON" <<'EOF'
{
  "tools": []
}
EOF
    fi
}

validate_tools_json() {
    if ! jq -e '.tools | type == "array"' "$TOOLS_JSON" >/dev/null 2>&1; then
        err "tools.json is invalid (missing or non-array .tools)"
        return 1
    fi
    return 0
}

count_tools() {
    jq '.tools | length' "$TOOLS_JSON"
}

# Returns TSV: dir, url, alias, command, setup_hooks, prompt_interface
list_tools_tsv() {
    jq -r '.tools[] | [
        .dir,
        .url,
        .alias,
        .command,
        (.setup_hooks // [] | tojson),
        (.prompt_interface // false | tostring)
    ] | @tsv' "$TOOLS_JSON"
}

# =============================================================================
# Interface helper script generation
# =============================================================================
# Generates two helper scripts (bash and fish) that:
#   1. List all "real" network interfaces with their IPs
#   2. Default-pick tun0 (or first available)
#   3. Let user override via prompt
#   4. Export IFACE and IFACE_IP env vars

generate_iface_helper_bash() {
    cat > "$IFACE_HELPER_BASH" <<'IFACE_HELPER_EOF'
#!/usr/bin/env bash
# tools-iface-helper.sh — auto-generated, do not edit
# Source this then call: pick_iface
# Sets:  $IFACE (interface name) and $IFACE_IP (its IPv4)

pick_iface() {
    local default_iface="${TOOLS_DEFAULT_IFACE:-tun0}"
    local prefer_iface="${TOOLS_FORCE_IFACE:-}"

    # Collect interfaces with IPv4 addresses (exclude lo)
    local -a iface_names=() iface_ips=()
    while IFS= read -r line; do
        local name ip
        name=$(awk '{print $1}' <<< "$line")
        ip=$(awk '{print $2}' <<< "$line")
        iface_names+=("$name")
        iface_ips+=("$ip")
    done < <(ip -o -4 addr show 2>/dev/null \
              | awk '$2 != "lo" {split($4,a,"/"); print $2, a[1]}')

    if [[ ${#iface_names[@]} -eq 0 ]]; then
        echo "[!] No interfaces with IPv4 found" >&2
        return 1
    fi

    # If TOOLS_FORCE_IFACE is set, use it without prompting
    if [[ -n "$prefer_iface" ]]; then
        for i in "${!iface_names[@]}"; do
            if [[ "${iface_names[$i]}" == "$prefer_iface" ]]; then
                IFACE="${iface_names[$i]}"
                IFACE_IP="${iface_ips[$i]}"
                export IFACE IFACE_IP
                echo "[*] Forced interface: $IFACE ($IFACE_IP)" >&2
                return 0
            fi
        done
        echo "[!] Forced interface '$prefer_iface' not found" >&2
    fi

    # Find default index (tun0 or first)
    local default_idx=0
    for i in "${!iface_names[@]}"; do
        if [[ "${iface_names[$i]}" == "$default_iface" ]]; then
            default_idx=$i
            break
        fi
    done

    # Print menu to stderr (so command output isn't polluted)
    {
        echo
        echo "==[ Pick interface ]=="
        for i in "${!iface_names[@]}"; do
            local marker="  "
            [[ $i -eq $default_idx ]] && marker=" *"
            printf "%s %d) %-12s %s\n" "$marker" "$((i+1))" "${iface_names[$i]}" "${iface_ips[$i]}"
        done
        echo "    (* = default)"
    } >&2

    local choice
    read -rp "Choice [Enter for default]: " choice </dev/tty

    if [[ -z "$choice" ]]; then
        IFACE="${iface_names[$default_idx]}"
        IFACE_IP="${iface_ips[$default_idx]}"
    elif [[ "$choice" =~ ^[0-9]+$ ]]; then
        local idx=$((choice - 1))
        if (( idx < 0 || idx >= ${#iface_names[@]} )); then
            echo "[!] Out of range, using default" >&2
            IFACE="${iface_names[$default_idx]}"
            IFACE_IP="${iface_ips[$default_idx]}"
        else
            IFACE="${iface_names[$idx]}"
            IFACE_IP="${iface_ips[$idx]}"
        fi
    else
        # Treat as interface name
        local found=0
        for i in "${!iface_names[@]}"; do
            if [[ "${iface_names[$i]}" == "$choice" ]]; then
                IFACE="${iface_names[$i]}"
                IFACE_IP="${iface_ips[$i]}"
                found=1
                break
            fi
        done
        if [[ $found -eq 0 ]]; then
            echo "[!] Interface '$choice' not found, using default" >&2
            IFACE="${iface_names[$default_idx]}"
            IFACE_IP="${iface_ips[$default_idx]}"
        fi
    fi

    export IFACE IFACE_IP
    echo "[*] Selected: $IFACE ($IFACE_IP)" >&2
}
IFACE_HELPER_EOF
}

generate_iface_helper_fish() {
    mkdir -p "$(dirname "$IFACE_HELPER_FISH")"
    cat > "$IFACE_HELPER_FISH" <<'IFACE_HELPER_EOF'
# tools-iface-helper.fish — auto-generated, do not edit
# Defines: pick_iface (sets $IFACE and $IFACE_IP)

function pick_iface
    set -l default_iface (set -q TOOLS_DEFAULT_IFACE; and echo $TOOLS_DEFAULT_IFACE; or echo tun0)
    set -l prefer_iface (set -q TOOLS_FORCE_IFACE; and echo $TOOLS_FORCE_IFACE; or echo "")

    set -l iface_names
    set -l iface_ips

    for line in (ip -o -4 addr show ^/dev/null | awk '$2 != "lo" {split($4,a,"/"); print $2, a[1]}')
        set -l parts (string split " " $line)
        set -a iface_names $parts[1]
        set -a iface_ips $parts[2]
    end

    if test (count $iface_names) -eq 0
        echo "[!] No interfaces with IPv4 found" >&2
        return 1
    end

    # Forced interface
    if test -n "$prefer_iface"
        for i in (seq (count $iface_names))
            if test "$iface_names[$i]" = "$prefer_iface"
                set -gx IFACE $iface_names[$i]
                set -gx IFACE_IP $iface_ips[$i]
                echo "[*] Forced interface: $IFACE ($IFACE_IP)" >&2
                return 0
            end
        end
        echo "[!] Forced interface '$prefer_iface' not found" >&2
    end

    # Default index
    set -l default_idx 1
    for i in (seq (count $iface_names))
        if test "$iface_names[$i]" = "$default_iface"
            set default_idx $i
            break
        end
    end

    echo "" >&2
    echo "==[ Pick interface ]==" >&2
    for i in (seq (count $iface_names))
        set -l marker "  "
        if test $i -eq $default_idx
            set marker " *"
        end
        printf "%s %d) %-12s %s\n" $marker $i $iface_names[$i] $iface_ips[$i] >&2
    end
    echo "    (* = default)" >&2

    read -P "Choice [Enter for default]: " choice

    if test -z "$choice"
        set -gx IFACE $iface_names[$default_idx]
        set -gx IFACE_IP $iface_ips[$default_idx]
    else if string match -qr '^[0-9]+$' -- $choice
        if test $choice -lt 1 -o $choice -gt (count $iface_names)
            echo "[!] Out of range, using default" >&2
            set -gx IFACE $iface_names[$default_idx]
            set -gx IFACE_IP $iface_ips[$default_idx]
        else
            set -gx IFACE $iface_names[$choice]
            set -gx IFACE_IP $iface_ips[$choice]
        end
    else
        set -l found 0
        for i in (seq (count $iface_names))
            if test "$iface_names[$i]" = "$choice"
                set -gx IFACE $iface_names[$i]
                set -gx IFACE_IP $iface_ips[$i]
                set found 1
                break
            end
        end
        if test $found -eq 0
            echo "[!] Interface '$choice' not found, using default" >&2
            set -gx IFACE $iface_names[$default_idx]
            set -gx IFACE_IP $iface_ips[$default_idx]
        end
    end

    echo "[*] Selected: $IFACE ($IFACE_IP)" >&2
end
IFACE_HELPER_EOF
}

generate_iface_helpers() {
    section "Generating interface helpers"
    generate_iface_helper_bash
    ok "Bash/Zsh: $IFACE_HELPER_BASH"
    generate_iface_helper_fish
    ok "Fish:     $IFACE_HELPER_FISH"
}

# =============================================================================
# Subcommand: list
# =============================================================================

cmd_list() {
    ensure_tools_json
    validate_tools_json || exit 1

    section "Configured tools ($(count_tools))"
    if [[ "$(count_tools)" -eq 0 ]]; then
        warn "No tools defined yet. Run: $0 add"
        return 0
    fi

    printf "  ${C_BOLD}%-20s %-12s %-6s %s${C_RESET}\n" "FOLDER" "ALIAS" "IFACE?" "COMMAND"
    printf "  %-20s %-12s %-6s %s\n" "------" "-----" "------" "-------"
    while IFS=$'\t' read -r dir url alias cmd hooks prompt_iface; do
        local iface_marker="  "
        [[ "$prompt_iface" == "true" ]] && iface_marker="${C_GREEN}YES${C_RESET}"
        printf "  %-20s ${C_GREEN}%-12s${C_RESET} %-6s ${C_DIM}%s${C_RESET}\n" \
            "$dir" "$alias" "$iface_marker" "$cmd"
        if [[ "$hooks" != "[]" && "$hooks" != "null" ]]; then
            local hook_count
            hook_count=$(echo "$hooks" | jq 'length')
            printf "  %-20s ${C_DIM}└─ %d setup hook(s)${C_RESET}\n" "" "$hook_count"
        fi
    done < <(list_tools_tsv)
    echo
    info "Tools dir:    $TOOLS_DIR"
    info "Definitions:  $TOOLS_JSON"
    info "Distro:       $DISTRO_ID ($DISTRO_FAMILY family, $PKG_MANAGER)"
}

# =============================================================================
# Subcommand: status
# =============================================================================

cmd_status() {
    ensure_tools_json
    validate_tools_json || exit 1

    section "Install status"
    printf "  ${C_BOLD}%-20s %-12s %s${C_RESET}\n" "FOLDER" "ALIAS" "STATUS"
    printf "  %-20s %-12s %s\n" "------" "-----" "------"

    local installed=0 missing=0
    while IFS=$'\t' read -r dir url alias cmd hooks prompt_iface; do
        local target="$TOOLS_DIR/$dir"
        local status
        if [[ -d "$target/.git" ]]; then
            status="${C_GREEN}OK installed${C_RESET}"
            ((installed++))
        elif [[ -d "$target" ]]; then
            status="${C_YELLOW}exists, not git${C_RESET}"
        else
            status="${C_RED}missing${C_RESET}"
            ((missing++))
        fi
        printf "  %-20s %-12s %b\n" "$dir" "$alias" "$status"
    done < <(list_tools_tsv)
    echo
    info "$installed installed, $missing missing"
}

# =============================================================================
# Subcommand: add
# =============================================================================

cmd_add() {
    ensure_tools_json
    validate_tools_json || exit 1
    require_cmd jq

    section "Add a new tool"

    echo "We need a few things:"
    echo "  ${C_BOLD}dir${C_RESET}                - folder name under \$TOOLS_DIR (lowercase)"
    echo "  ${C_BOLD}url${C_RESET}                - git clone URL"
    echo "  ${C_BOLD}alias${C_RESET}              - shell shortcut (must be valid identifier)"
    echo "  ${C_BOLD}command${C_RESET}            - what the alias runs. Use {DIR} for path."
    echo "  ${C_BOLD}prompt_interface?${C_RESET}  - should the alias ask for an interface?"
    echo "                       If yes, use \$IFACE / \$IFACE_IP in your command."
    echo
    echo "Example without interface:"
    echo "  command: bash {DIR}/run.sh"
    echo
    echo "Example with interface:"
    echo "  prompt_interface: true"
    echo "  command:          sudo python3 {DIR}/server.py -i \$IFACE"
    echo

    local dir url alias cmd prompt_iface
    read -rp "Folder name: " dir
    [[ -z "$dir" ]] && { err "Folder name required"; return 1; }
    if [[ ! "$dir" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
        err "Folder name must be lowercase letters/digits/dash/underscore only"
        return 1
    fi

    read -rp "Git URL: " url
    [[ ! "$url" =~ ^https?://|^git@ ]] && { err "URL must start with http(s):// or git@"; return 1; }

    read -rp "Alias name: " alias
    [[ -z "$alias" ]] && { err "Alias required"; return 1; }
    if [[ ! "$alias" =~ ^[a-zA-Z_][a-zA-Z0-9_-]*$ ]]; then
        err "Alias must be a valid shell identifier"
        return 1
    fi
    if jq -e --arg a "$alias" '.tools[] | select(.alias == $a)' "$TOOLS_JSON" >/dev/null; then
        err "Alias '$alias' already exists in tools.json (must be unique)"
        return 1
    fi

    read -rp "Command (use {DIR} for path): " cmd
    [[ -z "$cmd" ]] && { err "Command required"; return 1; }

    read -rp "Prompt for interface? [y/N] " prompt_iface_ans
    if [[ "$prompt_iface_ans" =~ ^[YyJj]$ ]]; then
        prompt_iface="true"
    else
        prompt_iface="false"
    fi

    echo
    info "About to add:"
    echo "  dir:               $dir"
    echo "  url:               $url"
    echo "  alias:             $alias"
    echo "  command:           $cmd"
    echo "  prompt_interface:  $prompt_iface"
    echo
    confirm "Add this tool?" || { warn "Cancelled"; return 0; }

    local tmp
    tmp=$(mktemp)
    jq --arg dir "$dir" --arg url "$url" --arg alias "$alias" --arg cmd "$cmd" \
       --argjson piface "$prompt_iface" \
        '.tools += [{
            "dir": $dir,
            "url": $url,
            "alias": $alias,
            "command": $cmd,
            "setup_hooks": [],
            "prompt_interface": $piface
        }]' \
        "$TOOLS_JSON" > "$tmp" && mv "$tmp" "$TOOLS_JSON"

    ok "Added '$alias' to tools.json"

    if confirm "Install this tool now?"; then
        clone_or_update "$dir" "$url" "[]"
        generate_aliases
        ok "Done. Run 'exec fish' or 'source ~/.bashrc' to use the alias."
    else
        info "Run '$0 install' later to clone."
    fi
}

# =============================================================================
# Subcommand: remove
# =============================================================================

cmd_remove() {
    ensure_tools_json
    validate_tools_json || exit 1
    require_cmd jq

    section "Remove a tool"
    if [[ "$(count_tools)" -eq 0 ]]; then
        warn "No tools defined."
        return 0
    fi

    local -a aliases dirs
    while IFS=$'\t' read -r dir url alias cmd hooks prompt_iface; do
        dirs+=("$dir")
        aliases+=("$alias")
    done < <(list_tools_tsv)

    echo "Available tools:"
    for i in "${!aliases[@]}"; do
        printf "  ${C_GREEN}%2d${C_RESET}) %-12s ${C_DIM}(%s)${C_RESET}\n" \
            "$((i+1))" "${aliases[$i]}" "${dirs[$i]}"
    done
    echo

    local choice
    read -rp "Number to remove (or 'q' to quit): " choice
    [[ "$choice" == "q" ]] && return 0
    [[ ! "$choice" =~ ^[0-9]+$ ]] && { err "Invalid number"; return 1; }
    if (( choice < 1 || choice > ${#aliases[@]} )); then
        err "Out of range"
        return 1
    fi

    local idx=$((choice - 1))
    local target_alias="${aliases[$idx]}"
    local target_dir="${dirs[$idx]}"

    info "Will remove from tools.json:"
    info "  alias: $target_alias"
    info "  dir:   $target_dir"
    confirm "Confirm?" || { warn "Cancelled"; return 0; }

    local tmp
    tmp=$(mktemp)
    jq --arg a "$target_alias" --arg d "$target_dir" \
       '.tools |= map(select(.alias != $a or .dir != $d))' \
       "$TOOLS_JSON" > "$tmp" && mv "$tmp" "$TOOLS_JSON"
    ok "Removed '$target_alias' from tools.json"

    local target="$TOOLS_DIR/$target_dir"
    if [[ -d "$target" ]]; then
        if ! jq -e --arg d "$target_dir" '.tools[] | select(.dir == $d)' "$TOOLS_JSON" >/dev/null; then
            if confirm "Also delete cloned folder $target?"; then
                rm -rf "$target"
                ok "Deleted $target"
            fi
        else
            info "Folder kept (still used by other aliases)"
        fi
    fi

    generate_aliases
    ok "Aliases regenerated"
}

# =============================================================================
# Subcommand: edit
# =============================================================================

cmd_edit() {
    ensure_tools_json
    "${EDITOR:-nano}" "$TOOLS_JSON"
    validate_tools_json || { err "Validation failed after edit"; exit 1; }
    ok "tools.json valid"
    if confirm "Re-install/update aliases now?"; then
        cmd_install
    fi
}

# =============================================================================
# Subcommand: fix-impacket
# =============================================================================

cmd_fix_impacket() {
    section "Impacket Kali-style symlinks"

    if command -v impacket-smbserver >/dev/null 2>&1; then
        local existing
        existing=$(command -v impacket-smbserver)
        if [[ "$DISTRO_ID" == "kali" ]] || [[ "$existing" == "/usr/bin/"* ]]; then
            ok "Already available: $existing"
            ok "Nothing to do (likely Kali, or symlinks already created)"
            return 0
        fi
    fi

    if [[ "$DISTRO_FAMILY" == "debian" ]]; then
        warn "On Debian/Kali: impacket-* commands should come from impacket-scripts"
        info "Install with: sudo apt install impacket-scripts python3-impacket"
        return 0
    fi

    if [[ "$DISTRO_FAMILY" != "arch" ]]; then
        warn "Unknown distro — proceeding with Arch-style symlink creation"
    fi

    if ! [[ -f /usr/bin/smbserver.py ]] && ! command -v smbserver.py >/dev/null 2>&1; then
        err "impacket scripts not found in /usr/bin/"
        info "Install with: sudo pacman -S impacket"
        return 1
    fi

    sudo mkdir -p /usr/local/bin

    local count=0 skipped=0
    for script in /usr/bin/*.py; do
        [[ -f "$script" ]] || continue
        if grep -q "from impacket\|import impacket" "$script" 2>/dev/null; then
            local name
            name=$(basename "$script" .py)
            local link="/usr/local/bin/impacket-$name"
            if [[ -L "$link" ]]; then
                ((skipped++))
                continue
            fi
            sudo ln -sf "$script" "$link"
            info "  $script -> $link"
            ((count++))
        fi
    done

    ok "Created $count symlinks ($skipped already existed)"

    if command -v impacket-smbserver >/dev/null 2>&1; then
        ok "impacket-smbserver is now available system-wide"
    else
        warn "impacket-smbserver still not in PATH — verify /usr/local/bin is in PATH"
    fi
}

# =============================================================================
# Install / update logic
# =============================================================================

get_pkg_list() {
    if [[ "$PKG_MANAGER" == "pacman" ]]; then
        echo "git python python-pip jq nmap smbclient impacket proxychains-ng openssh iproute2"
    elif [[ "$PKG_MANAGER" == "apt" ]]; then
        echo "git python3 python3-pip jq nmap smbclient python3-impacket impacket-scripts proxychains4 openssh-client iproute2"
    fi
}

install_dependencies() {
    section "Installing dependencies"

    if [[ -z "$PKG_MANAGER" ]]; then
        warn "No supported package manager found, skipping system deps"
        return 0
    fi

    local pkgs
    read -ra pkgs <<< "$(get_pkg_list)"

    info "$PKG_MANAGER ($DISTRO_ID): ${pkgs[*]}"
    if confirm "Install/update these packages?"; then
        if [[ "$PKG_MANAGER" == "pacman" ]]; then
            sudo pacman -S --needed --noconfirm "${pkgs[@]}" 2>&1 | tail -5 \
                || warn "Some packages failed (may already be installed)"
        elif [[ "$PKG_MANAGER" == "apt" ]]; then
            sudo apt-get update -qq 2>&1 | tail -3
            sudo apt-get install -y --no-install-recommends "${pkgs[@]}" 2>&1 | tail -5 \
                || warn "Some packages failed"
        fi
    fi

    if command -v pip >/dev/null 2>&1 || command -v pip3 >/dev/null 2>&1; then
        local pip_cmd
        pip_cmd=$(command -v pip3 || command -v pip)
        info "Installing common Python libs (user) via $pip_cmd..."
        $pip_cmd install --user --upgrade --break-system-packages \
            requests beautifulsoup4 rich colorama pyfiglet 2>&1 | tail -3 \
            || $pip_cmd install --user --upgrade \
                requests beautifulsoup4 rich colorama pyfiglet 2>&1 | tail -3 \
            || warn "Some pip libs failed"
    fi

    ok "Dependencies done"
}

run_setup_hooks() {
    local target="$1" hooks_json="$2"

    if [[ -z "$hooks_json" || "$hooks_json" == "[]" || "$hooks_json" == "null" ]]; then
        return 0
    fi

    local hook_count
    hook_count=$(echo "$hooks_json" | jq 'length')
    [[ "$hook_count" -eq 0 ]] && return 0

    info "  running $hook_count setup hook(s)..."
    while IFS= read -r hook; do
        local resolved="${hook//\{DIR\}/$target}"
        info "    $ $resolved"
        if ! bash -c "$resolved" 2>&1 | tee -a "$LOG_FILE" >&2; then
            warn "    hook failed: $resolved"
        fi
    done < <(echo "$hooks_json" | jq -r '.[]')
}

clone_or_update() {
    local dir="$1" url="$2" hooks_json="${3:-[]}"
    local target="$TOOLS_DIR/$dir"
    local was_freshly_cloned=0

    if [[ -d "$target/.git" ]]; then
        if [[ "${DO_UPDATE:-0}" -eq 1 ]]; then
            info "Updating: $dir"
            (cd "$target" && git pull --quiet) || warn "  pull failed for $dir"
        else
            info "Already cloned: $dir (use 'update' subcommand to refresh)"
        fi
    elif [[ -d "$target" ]]; then
        warn "$target exists but is not a git repo, skipping"
        return 0
    else
        info "Cloning: $url"
        info "  -> $dir/"
        if git clone --quiet "$url" "$target"; then
            was_freshly_cloned=1
        else
            err "  clone failed"
            return 1
        fi
    fi

    if [[ -f "$target/requirements.txt" ]]; then
        local pip_cmd
        pip_cmd=$(command -v pip3 || command -v pip)
        if [[ -n "$pip_cmd" ]]; then
            info "  $pip_cmd install -r $dir/requirements.txt"
            $pip_cmd install --user --break-system-packages -r "$target/requirements.txt" 2>&1 | tail -2 \
                || $pip_cmd install --user -r "$target/requirements.txt" 2>&1 | tail -2 \
                || warn "  pip install had issues"
        fi
    fi

    find "$target" -maxdepth 2 -type f \( -name "*.sh" -o -name "*.py" \) \
        -exec chmod +x {} \; 2>/dev/null

    if [[ "$was_freshly_cloned" -eq 1 || "${RERUN_HOOKS:-0}" -eq 1 ]]; then
        run_setup_hooks "$target" "$hooks_json"
    fi
}

generate_aliases() {
    section "Generating aliases"

    {
        echo "# Pentest tool aliases - auto-generated by tools-setup.sh"
        echo "# Edit tools.json and run 'tools-setup.sh install' to regenerate."
        echo "# Generated: $(date -Iseconds)"
        echo
        echo "export TOOLS_DIR=\"\${TOOLS_DIR:-$TOOLS_DIR}\""
        echo
        echo "# Source iface helper if available"
        echo "[ -f $IFACE_HELPER_BASH ] && source $IFACE_HELPER_BASH"
        echo
        while IFS=$'\t' read -r dir url alias cmd hooks prompt_iface; do
            local resolved="${cmd//\{DIR\}/\${TOOLS_DIR}/$dir}"
            if [[ "$prompt_iface" == "true" ]]; then
                # Wrap in a function that picks interface first
                cat <<ALIAS_FN
${alias}() { pick_iface || return 1; eval "${resolved}"; }
ALIAS_FN
            else
                printf "alias %s='%s'\n" "$alias" "$resolved"
            fi
        done < <(list_tools_tsv)
    } > "$ALIAS_FILE_BASH"
    ok "Bash/Zsh aliases: $ALIAS_FILE_BASH"

    mkdir -p "$(dirname "$ALIAS_FILE_FISH")"
    {
        echo "# Pentest tool aliases - auto-generated by tools-setup.sh"
        echo "# Edit tools.json and run 'tools-setup.sh install' to regenerate."
        echo "# Generated: $(date -Iseconds)"
        echo
        echo "set -gx TOOLS_DIR (set -q TOOLS_DIR; and echo \$TOOLS_DIR; or echo \"$TOOLS_DIR\")"
        echo
        # Fish auto-loads conf.d/, so iface helper is already available
        while IFS=$'\t' read -r dir url alias cmd hooks prompt_iface; do
            local resolved="${cmd//\{DIR\}/\$TOOLS_DIR/$dir}"
            if [[ "$prompt_iface" == "true" ]]; then
                cat <<ALIAS_FN
function ${alias}
    pick_iface; or return 1
    eval ${resolved}
end
ALIAS_FN
            else
                printf "alias %s '%s'\n" "$alias" "$resolved"
            fi
        done < <(list_tools_tsv)
    } > "$ALIAS_FILE_FISH"
    ok "Fish aliases: $ALIAS_FILE_FISH"
}

wire_up_shells() {
    section "Wiring shells"

    local source_line="[ -f $ALIAS_FILE_BASH ] && source $ALIAS_FILE_BASH"

    if [[ -f "$HOME/.bashrc" ]] && ! grep -q "tools-aliases.sh" "$HOME/.bashrc"; then
        printf "\n# Pentest tool aliases\n%s\n" "$source_line" >> "$HOME/.bashrc"
        ok "~/.bashrc updated"
    else
        info "bash already wired (or no ~/.bashrc)"
    fi

    if [[ -f "$HOME/.zshrc" ]] && ! grep -q "tools-aliases.sh" "$HOME/.zshrc"; then
        printf "\n# Pentest tool aliases\n%s\n" "$source_line" >> "$HOME/.zshrc"
        ok "~/.zshrc updated"
    else
        info "zsh already wired (or no ~/.zshrc)"
    fi

    info "fish auto-loads from conf.d/, no wiring needed"
}

cmd_install() {
    ensure_tools_json
    validate_tools_json || exit 1
    require_cmd git
    require_cmd jq

    section "Install / refresh tools"
    info "Detected: $DISTRO_ID ($DISTRO_FAMILY family, pkg manager: ${PKG_MANAGER:-none})"

    if [[ ! -d "$TOOLS_DIR" ]]; then
        info "Creating $TOOLS_DIR"
        mkdir -p "$TOOLS_DIR"
    else
        info "Tools dir: $TOOLS_DIR"
    fi

    install_dependencies

    if [[ "$(count_tools)" -eq 0 ]]; then
        warn "tools.json is empty. Add tools first with: $0 add"
        return 0
    fi

    section "Cloning tools"
    local -A seen
    while IFS=$'\t' read -r dir url alias cmd hooks prompt_iface; do
        local key="$dir|$url"
        if [[ -z "${seen[$key]:-}" ]]; then
            seen[$key]=1
            clone_or_update "$dir" "$url" "$hooks"
        fi
    done < <(list_tools_tsv)
    ok "All tools processed"

    generate_iface_helpers
    generate_aliases
    wire_up_shells
    show_summary
}

cmd_update() {
    DO_UPDATE=1
    cmd_install
}

show_summary() {
    section "Summary"
    echo
    echo "  Distro:       $DISTRO_ID ($DISTRO_FAMILY family)"
    echo "  Tools dir:    $TOOLS_DIR"
    echo "  Definitions:  $TOOLS_JSON"
    echo
    echo "  ${C_BOLD}Aliases:${C_RESET}"
    while IFS=$'\t' read -r dir url alias cmd hooks prompt_iface; do
        local marker=""
        [[ "$prompt_iface" == "true" ]] && marker=" ${C_DIM}[asks for iface]${C_RESET}"
        printf "    ${C_GREEN}%s${C_RESET}%b\n" "$alias" "$marker"
    done < <(list_tools_tsv)
    echo
    echo "  ${C_YELLOW}Activate now:${C_RESET}"
    echo "    fish:     exec fish"
    echo "    bash/zsh: source ~/.bashrc"
    echo

    if [[ "$DISTRO_FAMILY" == "arch" ]] && ! command -v impacket-smbserver >/dev/null 2>&1; then
        echo "  ${C_YELLOW}Tip:${C_RESET} run '$0 fix-impacket' once to enable Kali-style impacket-* commands"
        echo
    fi

    echo "  ${C_DIM}Override interface defaults via env vars:${C_RESET}"
    echo "  ${C_DIM}  TOOLS_DEFAULT_IFACE=eth0     # change default in picker${C_RESET}"
    echo "  ${C_DIM}  TOOLS_FORCE_IFACE=tun0       # skip prompt entirely${C_RESET}"
    echo
    echo "  Log: $LOG_FILE"
    echo
}

# =============================================================================
# Subcommand: menu
# =============================================================================

cmd_menu() {
    while true; do
        echo
        printf "${C_BOLD}+----------------------------------------+${C_RESET}\n"
        printf "${C_BOLD}|       Pentest Tools Installer          |${C_RESET}\n"
        printf "${C_BOLD}+----------------------------------------+${C_RESET}\n"
        printf "  ${C_DIM}Distro: %s (%s family)${C_RESET}\n" "$DISTRO_ID" "$DISTRO_FAMILY"
        echo
        echo "  ${C_GREEN}1${C_RESET}) Install / refresh all tools"
        echo "  ${C_GREEN}2${C_RESET}) Update all (git pull)"
        echo "  ${C_GREEN}3${C_RESET}) List configured tools"
        echo "  ${C_GREEN}4${C_RESET}) Show install status"
        echo "  ${C_GREEN}5${C_RESET}) Add a new tool"
        echo "  ${C_GREEN}6${C_RESET}) Remove a tool"
        echo "  ${C_GREEN}7${C_RESET}) Edit tools.json directly"
        echo "  ${C_GREEN}8${C_RESET}) Fix impacket (Kali-style symlinks)"
        echo "  ${C_GREEN}q${C_RESET}) Quit"
        echo
        read -rp "Choice: " choice
        case "$choice" in
            1) cmd_install ;;
            2) cmd_update ;;
            3) cmd_list ;;
            4) cmd_status ;;
            5) cmd_add ;;
            6) cmd_remove ;;
            7) cmd_edit ;;
            8) cmd_fix_impacket ;;
            q|Q) ok "Bye"; break ;;
            *) warn "Unknown choice: $choice" ;;
        esac
    done
}

# =============================================================================
# Help
# =============================================================================

usage() {
    cat <<EOF
Pentest Tools Installer (cross-distro: Kali, Arch, CachyOS, BlackArch, etc.)

USAGE:
  $0 [SUBCOMMAND] [OPTIONS]

SUBCOMMANDS:
  install        Install/refresh tools from tools.json
  update         Git pull all existing repos
  list           Show all defined tools
  status         Show install state per tool
  add            Interactively add a new tool
  remove         Interactively remove a tool
  edit           Open tools.json in \$EDITOR
  fix-impacket   Create Kali-style impacket-* symlinks (Arch only; no-op on Kali)
  menu           Interactive TUI menu (default if no args)
  help           Show this help

GLOBAL OPTIONS:
  -y, --yes      Non-interactive (accept defaults)
  --rerun-hooks  Re-run setup_hooks even on already-cloned tools

ENVIRONMENT VARIABLES:
  TOOLS_DIR              Where tools get cloned (default: \$HOME/Desktop/tools)
  TOOLS_JSON             Path to tools definition (default: alongside this script)
  TOOLS_DEFAULT_IFACE    Default-selected interface in picker (default: tun0)
  TOOLS_FORCE_IFACE      Skip interface picker, always use this iface
  EDITOR                 Editor for 'edit' subcommand (default: nano)

INTERFACE PICKER:
  Tools with "prompt_interface": true in tools.json will show an interface
  picker before running. tun0 is the default. The chosen interface is
  exported as \$IFACE and \$IFACE_IP — use these in the command.

  Example tools.json entry:
    {
      "dir": "myserver",
      "url": "...",
      "alias": "srv",
      "command": "python3 {DIR}/server.py --listen \$IFACE_IP",
      "prompt_interface": true
    }

  Skip the prompt:
    TOOLS_FORCE_IFACE=tun0 srv     # always tun0, no prompt
    TOOLS_DEFAULT_IFACE=eth0 srv   # picker still shows, but eth0 default

TOOLS.JSON SCHEMA:
  Each tool entry supports:
    "dir":               folder name under TOOLS_DIR (required)
    "url":               git clone URL (required)
    "alias":             shell alias name (required, must be unique)
    "command":           what the alias runs; {DIR} = tool's path (required)
    "setup_hooks":       array of shell commands run after clone (optional)
    "prompt_interface":  bool — ask user for interface before running (optional)

FILES:
  tools.json                                     Tool definitions
  ~/.config/tools-aliases.sh                     Generated bash/zsh aliases
  ~/.config/fish/conf.d/tools-aliases.fish       Generated fish aliases
  ~/.config/tools-iface-helper.sh                Bash interface picker
  ~/.config/fish/conf.d/tools-iface-helper.fish  Fish interface picker
EOF
}

# =============================================================================
# Argument parsing & dispatch
# =============================================================================

detect_distro

ASSUME_YES=0
DO_UPDATE=0
RERUN_HOOKS=0
SUBCOMMAND="menu"

ARGS=()
for arg in "$@"; do
    case "$arg" in
        -y|--yes)        ASSUME_YES=1 ;;
        --rerun-hooks)   RERUN_HOOKS=1 ;;
        -h|--help|help)  usage; exit 0 ;;
        *)               ARGS+=("$arg") ;;
    esac
done

if [[ ${#ARGS[@]} -gt 0 ]]; then
    SUBCOMMAND="${ARGS[0]}"
fi

case "$SUBCOMMAND" in
    list|status|add|remove|edit|install|update|menu)
        require_cmd jq
        ;;
esac

case "$SUBCOMMAND" in
    install)      cmd_install ;;
    update)       cmd_update ;;
    list)         cmd_list ;;
    status)       cmd_status ;;
    add)          cmd_add ;;
    remove)       cmd_remove ;;
    edit)         cmd_edit ;;
    fix-impacket) cmd_fix_impacket ;;
    menu)         cmd_menu ;;
    *)            err "Unknown subcommand: $SUBCOMMAND"; usage; exit 1 ;;
esac
