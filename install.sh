#!/bin/sh
set -eu

main() {
    version=v0.3.0
    nebula_version=v1.12.0
    asset="https://raw.githubusercontent.com/tinkerfuroc/tknet/$version/tknet.py"

    if [ "$(uname -s)" != Linux ]; then
        printf '%s\n' 'tknet currently supports Linux.' >&2
        exit 1
    fi
    if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
        printf '%s\n' 'Install Python 3.9 or newer before installing tknet.' >&2
        exit 1
    fi
    if ! python3 -c 'from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey' 2>/dev/null; then
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update
            sudo apt-get install -y python3-cryptography
        else
            printf '%s\n' 'Install the Python cryptography package, then rerun this installer.' >&2
            exit 1
        fi
    fi

    install_dir=${TKNET_INSTALL_DIR:-"$HOME/.local/bin"}
    mkdir -p -- "$install_dir"
    install_dir=$(cd -- "$install_dir" && pwd -P)
    temporary_dir=$(mktemp -d "$install_dir/.tknet-install.XXXXXX")
    trap 'rm -rf -- "$temporary_dir"' EXIT
    trap 'exit 1' HUP INT TERM

    case "$(uname -m)" in
        x86_64) arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        *) printf '%s\n' 'Supported architectures: amd64 and arm64.' >&2; exit 1 ;;
    esac
    curl --proto '=https' --proto-redir '=https' -fsSL \
        "https://github.com/slackhq/nebula/releases/download/$nebula_version/nebula-linux-$arch.tar.gz" \
        -o "$temporary_dir/nebula.tar.gz"
    tar -xzf "$temporary_dir/nebula.tar.gz" -C "$temporary_dir" nebula nebula-cert
    sudo install -d -m 755 /opt/tknet/bin
    sudo install -m 755 "$temporary_dir/nebula" "$temporary_dir/nebula-cert" /opt/tknet/bin/

    curl --proto '=https' --proto-redir '=https' -fsSL "$asset" -o "$temporary_dir/tknet"
    python3 "$temporary_dir/tknet" --help >/dev/null
    curl --proto '=https' --proto-redir '=https' -fsSL \
        "https://raw.githubusercontent.com/tinkerfuroc/tknet/$version/admin.py" \
        -o "$temporary_dir/admin.py"
    sudo install -d -m 755 /opt/tknet/lib
    sudo install -m 644 "$temporary_dir/tknet" /opt/tknet/lib/tknet.py
    sudo install -m 644 "$temporary_dir/admin.py" /opt/tknet/lib/admin.py
    chmod 755 "$temporary_dir/tknet"
    mv -fT -- "$temporary_dir/tknet" "$install_dir/tknet"

    printf 'Installed tknet %s at %s\n' "$version" "$install_dir/tknet"
    case ":$PATH:" in
        *":$install_dir:"*) printf '%s\n' 'Run tknet up to connect. No system service is installed.' ;;
        *) printf '%s\n' "Add $install_dir to PATH, or run $install_dir/tknet up." ;;
    esac
}

main "$@"
