#!/usr/bin/env bash
# RouteX Installer — installs all dependencies on supported Linux distributions.
# Usage: curl -sSL https://... | sudo bash   OR   sudo bash install.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[RouteX]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── OS Detection ───────────────────────────────────────────────────────────
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    elif [ -f /etc/debian_version ]; then
        OS=debian; VER=$(cat /etc/debian_version)
    elif [ -f /etc/redhat-release ]; then
        OS=rhel; VER=$(rpm -q --qf "%{VERSION}" $(rpm -q --whatprovides redhat-release) 2>/dev/null || echo "unknown")
    elif [ -f /etc/arch-release ]; then
        OS=arch; VER=rolling
    else
        OS=unknown; VER=unknown
    fi
    log "Detected OS: $OS $VER"
}

# ── Dependency Installation ─────────────────────────────────────────────────
install_deps_debian() {
    log "Installing dependencies for Debian/Ubuntu..."
    apt-get update -qq
    apt-get install -y -qq \
        iptables \
        iproute2 \
        curl \
        ca-certificates \
        build-essential \
        git \
        sqlite3 \
        libsqlite3-dev \
        pkg-config
    log "Debian/Ubuntu dependencies installed."
}

install_deps_rhel() {
    log "Installing dependencies for RHEL/CentOS/Rocky/Alma..."
    if command -v dnf &>/dev/null; then
        dnf install -y epel-release
        dnf install -y iptables iproute curl ca-certificates gcc make git sqlite sqlite-devel pkgconfig
    else
        yum install -y epel-release
        yum install -y iptables iproute curl ca-certificates gcc make git sqlite sqlite-devel pkgconfig
    fi
    log "RHEL dependencies installed."
}

install_deps_arch() {
    log "Installing dependencies for Arch Linux..."
    pacman -Sy --noconfirm iptables iproute2 curl ca-certificates base-devel git sqlite pkg-config
    log "Arch dependencies installed."
}

install_deps_alpine() {
    log "Installing dependencies for Alpine Linux..."
    apk add --no-cache iptables iproute2 curl ca-certificates build-base git sqlite sqlite-dev pkgconfig
    log "Alpine dependencies installed."
}

# ── Go Installation ─────────────────────────────────────────────────────────
install_go() {
    GO_VERSION="1.22.2"
    GO_ARCH="linux-amd64"
    
    if command -v go &>/dev/null; then
        CURRENT=$(go version | awk '{print $3}' | sed 's/go//')
        log "Go $CURRENT already installed."
        return
    fi
    
    log "Installing Go $GO_VERSION..."
    curl -sSL "https://go.dev/dl/go${GO_VERSION}.${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    
    # Add to PATH
    if ! grep -q '/usr/local/go/bin' /etc/profile 2>/dev/null; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    export PATH=$PATH:/usr/local/go/bin
    log "Go $GO_VERSION installed."
}

# ── iptables Kernel Module Check ────────────────────────────────────────────
check_iptables_modules() {
    log "Checking iptables kernel modules..."
    local MODS=("xt_hashlimit" "xt_connlimit" "xt_recent" "xt_state" "nf_conntrack")
    local MISSING=()
    
    for mod in "${MODS[@]}"; do
        if ! grep -q "^${mod} " /proc/modules 2>/dev/null; then
            modprobe "$mod" 2>/dev/null || true
            if ! grep -q "^${mod} " /proc/modules 2>/dev/null; then
                MISSING+=("$mod")
            fi
        fi
    done
    
    if [ ${#MISSING[@]} -gt 0 ]; then
        warn "Some kernel modules may not be loaded: ${MISSING[*]}"
        warn "iptables rate limiting features may be limited."
        warn "Run: modprobe ${MISSING[*]}   or rebuild kernel with these modules."
    else
        log "All iptables kernel modules loaded."
    fi
}

# ── Build RouteX ────────────────────────────────────────────────────────────
build_routex() {
    local SRC_DIR="${1:-/opt/routex}"
    log "Building RouteX from $SRC_DIR..."
    
    if [ ! -f "$SRC_DIR/go.mod" ]; then
        err "RouteX source not found at $SRC_DIR. Clone it first: git clone <repo> $SRC_DIR"
    fi
    
    cd "$SRC_DIR"
    go mod download
    go build -ldflags "-s -w" -o /usr/local/bin/routex ./cmd/routex/
    
    log "RouteX built successfully: /usr/local/bin/routex"
}

# ── Systemd Service ─────────────────────────────────────────────────────────
install_service() {
    local SRC_DIR="${1:-/opt/routex}"
    log "Installing systemd service..."
    
    cat > /etc/systemd/system/routex.service << EOF
[Unit]
Description=RouteX Reverse Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/routex -config ${SRC_DIR}/configs/global.yaml -proxies ${SRC_DIR}/configs/proxies
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
LimitNPROC=32768
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log "Service installed. Enable with: systemctl enable --now routex"
}

# ── Config Verification ─────────────────────────────────────────────────────
verify_config() {
    local SRC_DIR="${1:-/opt/routex}"
    log "Verifying configuration..."
    
    if [ ! -f "$SRC_DIR/configs/global.yaml" ]; then
        warn "No global.yaml found at $SRC_DIR/configs/global.yaml"
        warn "Copy configs/global.yaml from the source tree."
    fi
    
    if ! /usr/local/bin/routex -config "$SRC_DIR/configs/global.yaml" -proxies "$SRC_DIR/configs/proxies" --help 2>/dev/null; then
        warn "Configuration verification skipped (binary may need valid configs)"
    fi
}

# ── Firewall Check ──────────────────────────────────────────────────────────
check_firewall() {
    log "Checking firewall status..."
    
    if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
        warn "UFW is active. You may need to allow proxy ports:"
        warn "  ufw allow 9000/tcp   # API"
        warn "  ufw allow 25565:25575/tcp  # Minecraft example"
    fi
    
    if command -v firewall-cmd &>/dev/null && firewall-cmd --state 2>/dev/null | grep -q "running"; then
        warn "firewalld is active. You may need to allow proxy ports:"
        warn "  firewall-cmd --add-port=9000/tcp --permanent"
    fi
}

# ─── Main ────────────────────────────────────────────────────────────────────
main() {
    echo ""
    log "══════════════════════════════════════════"
    log "  RouteX Reverse Proxy Installer"
    log "══════════════════════════════════════════"
    echo ""
    
    if [ "$(id -u)" -ne 0 ]; then
        err "This installer must be run as root (use sudo)."
    fi
    
    detect_os
    
    case "$OS" in
        debian|ubuntu|pop|linuxmint|elementary|kali|raspbian)
            install_deps_debian ;;
        rhel|centos|fedora|rocky|almalinux|ol|amzn)
            install_deps_rhel ;;
        arch|manjaro|endeavouros)
            install_deps_arch ;;
        alpine)
            install_deps_alpine ;;
        *)
            warn "Unsupported OS: $OS. Attempting generic install..."
            warn "You may need to install dependencies manually:"
            warn "  - iptables, iproute2, curl, git, gcc, make"
            warn "  - sqlite3, sqlite3-dev, pkg-config"
            ;;
    esac
    
    install_go
    check_iptables_modules
    
    SRC_DIR="${1:-/opt/routex}"
    
    if [ -f "$SRC_DIR/go.mod" ]; then
        build_routex "$SRC_DIR"
        install_service "$SRC_DIR"
        check_firewall
    else
        warn "RouteX source not found at $SRC_DIR"
        warn "To build from source:"
        warn "  1. Clone repository to $SRC_DIR"
        warn "  2. Run: $0 $SRC_DIR"
        log "Dependencies installed. Ready to build."
    fi
    
    echo ""
    log "══════════════════════════════════════════"
    log "  Installation Complete!"
    log "══════════════════════════════════════════"
    echo ""
    log "Next steps:"
    log "  1. Edit configs: $SRC_DIR/configs/"
    log "  2. Start service: systemctl enable --now routex"
    log "  3. Check API:     curl http://localhost:9000/api/health"
    log "  4. View metrics:  curl -H 'X-API-Key: pk_admin_xxx' http://localhost:9000/metrics?format=json"
    echo ""
}

main "$@"
