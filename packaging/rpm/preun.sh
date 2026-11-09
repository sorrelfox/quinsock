# $1: 0 = removal, 1 = upgrade
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    systemctl --no-reload disable --now quinsock.service >/dev/null 2>&1 || :
fi
