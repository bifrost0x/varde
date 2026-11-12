#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Installs the Varde agent as a service (ADR 0031). Varde uploads this
# script with the agent binary and its configuration into a private
# temporary directory and runs it as root: sh install.sh <dir> <init>.
# It only creates what it names below; run again, it updates them.
set -eu
exec </dev/null
src=$1
init=$2
trap 'rm -rf "$src"' EXIT

user=varde-agent
home=/var/lib/varde-agent
# An agent that enrolled before keeps its identity; the new token stays
# unused. Checked before the service starts and enrolls.
enrolled=
if [ -f "$home/data/agent.json" ]; then enrolled=yes; fi

if ! id "$user" >/dev/null 2>&1; then
	if command -v useradd >/dev/null 2>&1; then
		useradd --system --user-group --home-dir "$home" --no-create-home --shell /usr/sbin/nologin "$user"
	else
		addgroup -S "$user"
		adduser -S -D -H -h "$home" -s /sbin/nologin -G "$user" "$user"
	fi
fi
group=$(id -gn "$user")
if grep -q '^VARDE_DOCKER_HOST=unix:' "$src/agent.env"; then
	# Reading the Docker API needs the docker group, which is equivalent
	# to root on this host; the user chose it in Varde.
	id -nG "$user" | grep -qw docker || usermod -aG docker "$user" 2>/dev/null || addgroup "$user" docker
fi

# The home belongs to root, so the agent cannot replace its directories
# with links that would send root's writes below elsewhere. It owns bin
# (to update itself) and data. An earlier install made the agent own the
# home; from here on it cannot change its entries, so the checks below
# hold until the end.
install -d -m 0750 -o root -g "$group" "$home"
for d in "$home/bin" "$home/data"; do
	if [ -L "$d" ] || { [ -e "$d" ] && [ ! -d "$d" ]; }; then
		echo "varde: refusing to install: $d is not a plain directory" >&2
		exit 1
	fi
done
install -d -m 0750 -o "$user" -g "$group" "$home/bin" "$home/data"
# The new binary is written where only root can, then renamed into bin: a
# rename replaces a link the agent may have put there, it does not follow it.
install -m 0750 -o "$user" -g "$group" "$src/varde" "$home/.varde.new"
mv -f "$home/.varde.new" "$home/bin/varde"
install -m 0640 -o root -g "$group" "$src/agent.env" /etc/varde-agent.env

case "$init" in
systemd)
	cat >/etc/systemd/system/varde-agent.service <<'UNIT'
[Unit]
Description=Varde agent
Wants=network-online.target
After=network-online.target

[Service]
User=varde-agent
EnvironmentFile=/etc/varde-agent.env
ExecStart=/var/lib/varde-agent/bin/varde agent
Restart=always
RestartSec=10
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/varde-agent
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT
	chmod 0644 /etc/systemd/system/varde-agent.service
	systemctl daemon-reload
	systemctl enable varde-agent >/dev/null 2>&1
	systemctl restart varde-agent
	sleep 3
	systemctl is-active --quiet varde-agent || { journalctl -u varde-agent -n 20 --no-pager >&2 || true; exit 1; }
	;;
openrc)
	cat >/etc/init.d/varde-agent <<'RC'
#!/sbin/openrc-run
description="Varde agent"
command=/var/lib/varde-agent/bin/varde
command_args=agent
command_user=varde-agent
supervisor=supervise-daemon
respawn_delay=10
respawn_max=0
set -a
. /etc/varde-agent.env
set +a
depend() {
	need net
}
RC
	chmod 0755 /etc/init.d/varde-agent
	rc-update add varde-agent default >/dev/null
	rc-service varde-agent restart >/dev/null
	sleep 3
	rc-service varde-agent status >/dev/null
	;;
*)
	echo "varde: neither systemd nor OpenRC found" >&2
	exit 1
	;;
esac
if [ -n "$enrolled" ]; then
	echo "varde: kept the existing enrollment"
else
	# A new agent must reach the server to enroll: test it now, with the
	# agent's own binary and configuration, so a firewall or a router in
	# the way shows up in Varde instead of a silent "not connected".
	(set -a; . /etc/varde-agent.env; set +a; "$home/bin/varde" check-server) || true
fi
echo "varde: agent installed"
