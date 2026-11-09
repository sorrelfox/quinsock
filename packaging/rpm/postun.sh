# $1: 0 = removal, >= 1 = upgrade
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
    if [ "$1" -ge 1 ]; then
        systemctl try-restart quinsock.service >/dev/null 2>&1 || :
    fi
fi
