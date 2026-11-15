#!/bin/sh
set -eu

main() {
    version=v0.1.0
    asset="https://github.com/tinkerfuroc/tknet/releases/download/$version/tknet"

    if [ "$(uname -s)" != Linux ]; then
        printf '%s\n' 'tknet currently supports Linux.' >&2
        exit 1
    fi
    if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
        printf '%s\n' 'Install Python 3.9 or newer before installing tknet.' >&2
        exit 1
    fi

    install_dir=${TKNET_INSTALL_DIR:-"$HOME/.local/bin"}
    mkdir -p -- "$install_dir"
    install_dir=$(cd -- "$install_dir" && pwd -P)
    temporary_dir=$(mktemp -d "$install_dir/.tknet-install.XXXXXX")
    trap 'rm -rf -- "$temporary_dir"' EXIT
    trap 'exit 1' HUP INT TERM

    curl --proto '=https' --proto-redir '=https' -fsSL "$asset" -o "$temporary_dir/tknet"
    python3 "$temporary_dir/tknet" --help >/dev/null
    chmod 755 "$temporary_dir/tknet"
    mv -fT -- "$temporary_dir/tknet" "$install_dir/tknet"

    printf 'Installed tknet %s at %s\n' "$version" "$install_dir/tknet"
    case ":$PATH:" in
        *":$install_dir:"*) printf '%s\n' 'Run tknet join to enter an invitation.' ;;
        *) printf '%s\n' "Add $install_dir to PATH, or run $install_dir/tknet join." ;;
    esac
    if ! command -v tailscale >/dev/null 2>&1; then
        printf '%s\n' 'Install and start Tailscale before joining.' 'https://tailscale.com/download/linux'
    fi
}

main "$@"
