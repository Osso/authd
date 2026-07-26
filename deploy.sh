#!/usr/bin/env bash
# Build authd and install binaries, service, and pacman hook, then restart the daemon
set -euo pipefail
cd "$(dirname "$0")"

cargo build --release --locked

authsudo sh -c '
    set -e
    install -m755 target/release/authd /usr/bin/authd
    install -m755 target/release/authctl /usr/bin/authctl
    install -m755 target/release/authd-polkit-agent /usr/bin/authd-polkit-agent
    install -m755 target/release/pkexec /usr/bin/authd-pkexec
    install -m4755 -o root -g root target/release/authsudo /usr/bin/authsudo
    ln -sf /usr/bin/authd-pkexec /usr/bin/pkexec
    install -m644 authd.service /usr/lib/systemd/system/authd.service
    install -m644 authd-polkit-agent.service /usr/lib/systemd/user/authd-polkit-agent.service
    install -m644 authd-pkexec.hook /usr/share/libalpm/hooks/authd-pkexec.hook
    install -dm755 /etc/authd/policies.d
    systemctl daemon-reload
    systemctl restart authd
'

user_runtime_dir="/run/user/$(id -u)"
XDG_RUNTIME_DIR="$user_runtime_dir" \
DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime_dir/bus" \
    systemctl --user daemon-reload
XDG_RUNTIME_DIR="$user_runtime_dir" \
DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime_dir/bus" \
    systemctl --user restart authd-polkit-agent.service

systemctl status authd --no-pager -n 0 | head -4
