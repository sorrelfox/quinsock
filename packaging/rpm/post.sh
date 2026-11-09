# $1: 1 = install, 2 = upgrade
if ! getent passwd quinsock >/dev/null; then
    if command -v systemd-sysusers >/dev/null 2>&1; then
        systemd-sysusers /usr/lib/sysusers.d/quinsock.conf || :
    fi
    getent passwd quinsock >/dev/null || \
        useradd --system --user-group --no-create-home --home-dir / \
            --shell /sbin/nologin --comment "quinsock SOCKS5 proxy" quinsock || :
fi
if [ "$1" -eq 1 ]; then
    chown root:quinsock /etc/quinsock /etc/quinsock/config.toml || :
fi
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
    if [ "$1" -eq 1 ]; then
        systemctl --no-reload preset quinsock.service >/dev/null 2>&1 || :
    fi
fi
