#!/usr/bin/env bash
set -Eeuo pipefail

# Install a rootless Podman Quadlet for one distributed go53 node.
#
# Defaults are intentionally safe for a PowerDNS migration host:
#   - DNS is published on host port 2053, not 53
#   - API is bound to loopback
#   - distributed sync is published on 53530
#   - node_id defaults to the short hostname, e.g. a-ns01
#   - /imports inside the container maps to a host import directory
#
# Override with environment variables, for example:
#   NODE_ID=a-ns01 DNS_HOST_PORT=2053 SYNC_HOST_PORT=53530 scripts/install_quadlet_distributed.sh

UNIT_NAME="${GO53_UNIT_NAME:-go53}"
NODE_ID="${NODE_ID:-$(hostname -s)}"
IMAGE="${GO53_IMAGE:-ghcr.io/tenforwardab/go53:latest}"
CONTAINER_NAME="${GO53_CONTAINER_NAME:-go53-${NODE_ID}}"
SERVICE_USER="${GO53_SERVICE_USER:-podman_go53}"
SERVICE_HOME="${GO53_SERVICE_HOME:-/var/lib/${SERVICE_USER}}"

DATA_VOLUME="${GO53_DATA_VOLUME:-go53_data}"
IMPORT_DIR="${GO53_IMPORT_DIR:-${SERVICE_HOME}/imports}"
QUADLET_DIR="${GO53_QUADLET_DIR:-${SERVICE_HOME}/.config/containers/systemd}"
CONTAINER_FILE="$QUADLET_DIR/${UNIT_NAME}.container"
VOLUME_FILE="$QUADLET_DIR/${DATA_VOLUME}.volume"

DNS_BIND="${DNS_BIND:-0.0.0.0}"
DNS_HOST_PORT="${DNS_HOST_PORT:-2053}"
API_BIND="${API_BIND:-127.0.0.1}"
API_HOST_PORT="${API_HOST_PORT:-8053}"
SYNC_BIND="${SYNC_BIND:-0.0.0.0}"
SYNC_HOST_PORT="${SYNC_HOST_PORT:-53530}"
TRANSPORT="${DISTRIBUTED_TRANSPORT:-tls}"
RESYNC_INTERVAL_S="${RESYNC_INTERVAL_S:-30}"
PUSH_TIMEOUT_MS="${PUSH_TIMEOUT_MS:-2000}"

FORCE="${FORCE:-0}"
START_SERVICE="${START_SERVICE:-1}"
CONFIGURE_DISTRIBUTED="${CONFIGURE_DISTRIBUTED:-1}"
ENABLE_AUTO_UPDATE_TIMER="${ENABLE_AUTO_UPDATE_TIMER:-1}"
ALLOW_HOST_53="${ALLOW_HOST_53:-0}"

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

info() {
	echo "== $*"
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

install_podman() {
	if command -v podman >/dev/null 2>&1; then
		return 0
	fi
	need_cmd sudo

	local id like
	if [[ -r /etc/os-release ]]; then
		# shellcheck disable=SC1091
		. /etc/os-release
		id="${ID:-}"
		like="${ID_LIKE:-}"
	else
		fail "podman is missing and /etc/os-release is not readable; install podman manually"
	fi

	info "podman is missing; installing for distro ID=${id:-unknown}"
	case " $id $like " in
		*" debian "*|*" ubuntu "*)
			need_cmd apt-get
			apt_update_for_podman
			sudo apt-get install -y podman uidmap slirp4netns fuse-overlayfs
			;;
		*" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*)
			if command -v dnf >/dev/null 2>&1; then
				sudo dnf install -y podman
			elif command -v yum >/dev/null 2>&1; then
				sudo yum install -y podman
			else
				fail "podman is missing and neither dnf nor yum is available"
			fi
			;;
		*)
			fail "podman is missing and automatic install is not implemented for distro ID=${id:-unknown} ID_LIKE=${like:-unknown}"
			;;
	esac

	command -v podman >/dev/null 2>&1 || fail "podman install completed but podman is still not in PATH"
}

install_rootless_podman_helpers() {
	if command -v newuidmap >/dev/null 2>&1 &&
		command -v newgidmap >/dev/null 2>&1 &&
		command -v slirp4netns >/dev/null 2>&1; then
		return 0
	fi
	[[ -r /etc/os-release ]] || return 0

	local id like
	# shellcheck disable=SC1091
	. /etc/os-release
	id="${ID:-}"
	like="${ID_LIKE:-}"

	case " $id $like " in
		*" debian "*|*" ubuntu "*)
			need_cmd apt-get
			info "installing rootless Podman helper packages"
			apt_update_for_podman
			sudo apt-get install -y uidmap slirp4netns fuse-overlayfs
			;;
		*" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*)
			if command -v dnf >/dev/null 2>&1; then
				sudo dnf install -y shadow-utils slirp4netns fuse-overlayfs
			elif command -v yum >/dev/null 2>&1; then
				sudo yum install -y shadow-utils slirp4netns fuse-overlayfs
			fi
			;;
	esac
}

next_subid_start() {
	local file="$1"
	awk -F: '
		BEGIN { max = 100000 }
		NF >= 3 {
			end = $2 + $3
			if (end > max) max = end
		}
		END {
			rem = max % 65536
			if (rem != 0) max += 65536 - rem
			print max
		}
	' "$file" 2>/dev/null
}

ensure_subids() {
	need_cmd usermod
	local start
	if ! grep -q "^${SERVICE_USER}:" /etc/subuid 2>/dev/null; then
		start="$(next_subid_start /etc/subuid)"
		info "adding subuid range ${start}:65536 for ${SERVICE_USER}"
		sudo usermod --add-subuids "${start}-$((start + 65535))" "$SERVICE_USER"
	fi
	if ! grep -q "^${SERVICE_USER}:" /etc/subgid 2>/dev/null; then
		start="$(next_subid_start /etc/subgid)"
		info "adding subgid range ${start}:65536 for ${SERVICE_USER}"
		sudo usermod --add-subgids "${start}-$((start + 65535))" "$SERVICE_USER"
	fi
}

apt_update_for_podman() {
	if sudo apt-get update; then
		return 0
	fi

	info "apt-get update failed; retrying with distro-owned apt sources only"
	local tmp_root tmp_sources tmp_list
	tmp_root="$(mktemp -d)"
	tmp_sources="$tmp_root/sourceparts"
	tmp_list="$tmp_root/sources.list"
	mkdir -p "$tmp_sources"
	: >"$tmp_list"

	if [[ -r /etc/apt/sources.list ]]; then
		awk '
			/^[[:space:]]*#/ { next }
			/ubuntu\.com|debian\.org|debian-security/ { print }
		' /etc/apt/sources.list >"$tmp_list"
	fi

	if [[ -d /etc/apt/sources.list.d ]]; then
		for src in /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list; do
			[[ -r "$src" ]] || continue
			if grep -Eq 'ubuntu\.com|debian\.org|debian-security' "$src"; then
				cp "$src" "$tmp_sources/$(basename "$src")"
			fi
		done
	fi

	if [[ ! -s "$tmp_list" ]] && ! compgen -G "$tmp_sources/*.sources" >/dev/null && ! compgen -G "$tmp_sources/*.list" >/dev/null; then
		rm -rf "$tmp_root"
		fail "apt-get update failed and no distro-owned apt sources were found"
	fi

	sudo apt-get \
		-o Dir::Etc::sourcelist="$tmp_list" \
		-o Dir::Etc::sourceparts="$tmp_sources" \
		-o APT::Get::List-Cleanup=0 \
		update || {
		rm -rf "$tmp_root"
		fail "apt-get update failed even with distro-owned apt sources only"
	}
	rm -rf "$tmp_root"
}

unit_service() {
	printf '%s.service' "$UNIT_NAME"
}

service_uid() {
	id -u "$SERVICE_USER"
}

as_service_user() {
	local uid
	uid="$(service_uid)"
	sudo -u "$SERVICE_USER" \
		env HOME="$SERVICE_HOME" \
		XDG_RUNTIME_DIR="/run/user/$uid" \
		DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
		sh -c 'cd "$1" && shift && exec "$@"' sh "$SERVICE_HOME" "$@"
}

systemctl_user() {
	as_service_user systemctl --user "$@"
}

journalctl_user() {
	as_service_user journalctl --user "$@"
}

podman_user() {
	as_service_user podman "$@"
}

create_service_user() {
	need_cmd sudo
	need_cmd getent

	if id "$SERVICE_USER" >/dev/null 2>&1; then
		SERVICE_HOME="$(getent passwd "$SERVICE_USER" | cut -d: -f6)"
		IMPORT_DIR="${GO53_IMPORT_DIR:-${SERVICE_HOME}/imports}"
		QUADLET_DIR="${GO53_QUADLET_DIR:-${SERVICE_HOME}/.config/containers/systemd}"
		CONTAINER_FILE="$QUADLET_DIR/${UNIT_NAME}.container"
		VOLUME_FILE="$QUADLET_DIR/${DATA_VOLUME}.volume"
		return 0
	fi

	local nologin
	for nologin in /usr/sbin/nologin /sbin/nologin /bin/false; do
		if [[ -x "$nologin" ]]; then
			break
		fi
	done

	info "creating service user ${SERVICE_USER} with shell ${nologin}"
	sudo useradd --create-home --home-dir "$SERVICE_HOME" --shell "$nologin" "$SERVICE_USER"
}

enable_linger() {
	local linger uid
	linger="$(loginctl show-user "$SERVICE_USER" -p Linger --value 2>/dev/null || true)"
	if [[ "$linger" != "yes" ]]; then
		info "enabling linger for ${SERVICE_USER}"
		sudo loginctl enable-linger "$SERVICE_USER"
	fi
	uid="$(service_uid)"
	sudo systemctl start "user@${uid}.service"
}

check_prereqs() {
	create_service_user
	install_podman
	install_rootless_podman_helpers
	need_cmd systemctl
	need_cmd loginctl
	need_cmd jq
	need_cmd ss

	enable_linger
	ensure_subids
	if ! podman_output="$(podman_user info 2>&1)"; then
		echo "$podman_output" >&2
		fail "podman is installed but not usable for ${SERVICE_USER}"
	fi
	check_image_access
	systemctl_user show-environment >/dev/null 2>&1 || fail "systemctl --user is not available for ${SERVICE_USER}"

	[[ "$NODE_ID" =~ ^[A-Za-z0-9._-]+$ ]] || fail "NODE_ID contains unsupported characters: $NODE_ID"
	if [[ "$DNS_HOST_PORT" == "53" && "$ALLOW_HOST_53" != "1" ]]; then
		fail "DNS_HOST_PORT=53 is blocked by default so PowerDNS can keep host :53; set ALLOW_HOST_53=1 to override"
	fi
	check_host_port_available "$DNS_HOST_PORT" "DNS"
	check_host_port_available "$API_HOST_PORT" "API"
	check_host_port_available "$SYNC_HOST_PORT" "distributed sync"
}

check_image_access() {
	local output
	info "checking container image access: ${IMAGE}"
	if podman_user image exists "$IMAGE" >/dev/null 2>&1; then
		return 0
	fi
	if output="$(podman_user pull "$IMAGE" 2>&1)"; then
		return 0
	fi
	echo "$output" >&2
	if grep -qi "no image found in image index for architecture" <<<"$output"; then
		cat >&2 <<EOF
ERROR: ${IMAGE} is reachable, but it does not publish an image for this host architecture.

Host architecture: $(uname -m)
Podman reported: no matching image in the manifest list.

Publish a linux/amd64 image for ${IMAGE}, or override GO53_IMAGE with a tag that contains linux/amd64.
EOF
		exit 1
	fi
	cat >&2 <<EOF
ERROR: ${SERVICE_USER} cannot pull ${IMAGE}.

If this image should be public, make the GHCR package public and confirm the tag exists.
If it is private, log in as the service user before running this installer:

  sudo -u ${SERVICE_USER} env HOME=${SERVICE_HOME} XDG_RUNTIME_DIR=/run/user/$(service_uid) sh -c 'cd "\$HOME" && podman login ghcr.io'

You can also override the image:

  GO53_IMAGE=registry.example/go53:tag ./setup_go53_podman.sh
EOF
	exit 1
}

check_host_port_available() {
	local port="$1"
	local label="$2"
	if ss -H -lntu "( sport = :$port )" 2>/dev/null | grep -q .; then
		ss -H -lntup "( sport = :$port )" 2>/dev/null || true
		fail "${label} host port ${port} is already in use; override the matching *_HOST_PORT variable"
	fi
}

write_quadlet() {
	if [[ -e "$CONTAINER_FILE" && "$FORCE" != "1" ]]; then
		fail "$CONTAINER_FILE already exists; set FORCE=1 to replace it"
	fi
	if [[ -e "$VOLUME_FILE" && "$FORCE" != "1" ]]; then
		fail "$VOLUME_FILE already exists; set FORCE=1 to replace it"
	fi

	info "creating import directory"
	sudo mkdir -p "$IMPORT_DIR" "$QUADLET_DIR"
	sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$SERVICE_HOME"
	sudo chmod 755 "$IMPORT_DIR"

	info "writing $CONTAINER_FILE"
	sudo -u "$SERVICE_USER" tee "$CONTAINER_FILE" >/dev/null <<EOF
[Unit]
Description=go53 distributed DNS node ${NODE_ID}
After=network-online.target
Wants=network-online.target

[Container]
Image=${IMAGE}
ContainerName=${CONTAINER_NAME}
PublishPort=${DNS_BIND}:${DNS_HOST_PORT}:2053/udp
PublishPort=${DNS_BIND}:${DNS_HOST_PORT}:2053/tcp
PublishPort=${API_BIND}:${API_HOST_PORT}:8053/tcp
PublishPort=${SYNC_BIND}:${SYNC_HOST_PORT}:53530/tcp
Environment=DNS_PORT=:2053
Environment=API_PORT=:8053
Environment=BIND_HOST=0.0.0.0
Environment=STORAGE_BACKEND=badger
Environment=BADGER_DIR=/var/lib/go53/badger
Environment=ADMIN_SOCKET=/var/lib/go53/admin.sock
Environment=ADMIN_SOCKET_GROUP=
Environment=GO53_ADMIN_SOCKET=/var/lib/go53/admin.sock
Volume=${DATA_VOLUME}.volume:/var/lib/go53
Volume=${IMPORT_DIR}:/imports:Z
AutoUpdate=registry
Notify=false

[Service]
Restart=always
TimeoutStartSec=30

[Install]
WantedBy=default.target
EOF

	info "writing $VOLUME_FILE"
	sudo -u "$SERVICE_USER" tee "$VOLUME_FILE" >/dev/null <<EOF
[Volume]
EOF
}

start_quadlet() {
	info "reloading user systemd for ${SERVICE_USER}"
	systemctl_user daemon-reload

	if [[ "$ENABLE_AUTO_UPDATE_TIMER" == "1" ]]; then
		systemctl_user enable --now podman-auto-update.timer >/dev/null 2>&1 || \
			echo "WARN: could not enable podman-auto-update.timer; continuing" >&2
	fi

	if [[ "$START_SERVICE" == "1" ]]; then
		enable_quadlet_autostart
		info "starting $(unit_service)"
		if ! systemctl_user start "$(unit_service)"; then
			systemctl_user status "$(unit_service)" --no-pager || true
			journalctl_user -xeu "$(unit_service)" --no-pager || true
			print_podman_start_diagnostics
			fail "failed to start $(unit_service) for ${SERVICE_USER}"
		fi
	fi
}

print_podman_start_diagnostics() {
	echo "--- podman diagnostics for ${SERVICE_USER} ---" >&2
	podman_user ps -a >&2 || true
	echo "--- image pull check ---" >&2
	podman_user pull "$IMAGE" >&2 || true
	echo "--- equivalent podman run check ---" >&2
	podman_user run --rm --name "${CONTAINER_NAME}-diagnostic" \
		--replace \
		--publish "${DNS_BIND}:${DNS_HOST_PORT}:2053/udp" \
		--publish "${DNS_BIND}:${DNS_HOST_PORT}:2053/tcp" \
		--publish "${API_BIND}:${API_HOST_PORT}:8053/tcp" \
		--publish "${SYNC_BIND}:${SYNC_HOST_PORT}:53530/tcp" \
		--volume "systemd-${DATA_VOLUME}:/var/lib/go53" \
		--volume "${IMPORT_DIR}:/imports:Z" \
		--env DNS_PORT=:2053 \
		--env API_PORT=:8053 \
		--env BIND_HOST=0.0.0.0 \
		--env STORAGE_BACKEND=badger \
		--env BADGER_DIR=/var/lib/go53/badger \
		--env ADMIN_SOCKET=/var/lib/go53/admin.sock \
		--env ADMIN_SOCKET_GROUP= \
		--env GO53_ADMIN_SOCKET=/var/lib/go53/admin.sock \
		"$IMAGE" >&2 || true
	podman_user rm -f "${CONTAINER_NAME}-diagnostic" >&2 || true
}

enable_quadlet_autostart() {
	local wants_dir link_target link_path
	wants_dir="$QUADLET_DIR/default.target.wants"
	link_target="../$(basename "$CONTAINER_FILE")"
	link_path="$wants_dir/$(basename "$CONTAINER_FILE")"

	info "enabling quadlet autostart via ${link_path}"
	sudo -u "$SERVICE_USER" mkdir -p "$wants_dir"
	if [[ -L "$link_path" || -e "$link_path" ]]; then
		if [[ "$FORCE" != "1" ]]; then
			fail "$link_path already exists; set FORCE=1 to replace it"
		fi
		sudo -u "$SERVICE_USER" rm -f "$link_path"
	fi
	sudo -u "$SERVICE_USER" ln -s "$link_target" "$link_path"
	systemctl_user daemon-reload
}

wait_for_container() {
	local deadline=$((SECONDS + 60))
	while ((SECONDS < deadline)); do
		if podman_user exec "$CONTAINER_NAME" go53ctl config get >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	systemctl_user status "$(unit_service)" --no-pager || true
	podman_user logs "$CONTAINER_NAME" 2>/dev/null || true
	fail "go53 container did not become ready"
}

configure_distributed() {
	[[ "$START_SERVICE" == "1" && "$CONFIGURE_DISTRIBUTED" == "1" ]] || return 0

	wait_for_container

	local cfg private_key patch
	cfg="$(podman_user exec "$CONTAINER_NAME" go53ctl config get)"
	private_key="$(jq -r '.distributed.private_key // ""' <<<"$cfg")"
	if [[ -z "$private_key" ]]; then
		info "generating distributed keypair inside container"
		private_key="$(podman_user exec "$CONTAINER_NAME" go53ctl distributed keypair | jq -r '.private_key')"
	fi
	[[ -n "$private_key" && "$private_key" != "null" ]] || fail "could not obtain distributed private key"

	patch="$(jq -nc \
		--arg node "$NODE_ID" \
		--arg transport "$TRANSPORT" \
		--arg private_key "$private_key" \
		--arg sync_port ":53530" \
		--argjson push_timeout "$PUSH_TIMEOUT_MS" \
		--argjson resync "$RESYNC_INTERVAL_S" \
		'{mode:"distributed", allow_axfr:true,
		  distributed:{
		    node_id:$node,
		    peers:"",
		    transport:$transport,
		    sync_bind_host:"0.0.0.0",
		    sync_port:$sync_port,
		    private_key:$private_key,
		    push_timeout_ms:$push_timeout,
		    resync_interval_s:$resync
		  }}')"

	info "configuring distributed mode with node_id=${NODE_ID}"
	podman_user exec "$CONTAINER_NAME" go53ctl config patch "$patch" >/dev/null
}

print_summary() {
	cat <<EOF

Installed go53 distributed quadlet.

Unit:          $(unit_service)
Service user:  ${SERVICE_USER} (${SERVICE_HOME})
Container:     ${CONTAINER_NAME}
Node ID:       ${NODE_ID}
Image:         ${IMAGE}
Data volume:   ${DATA_VOLUME} -> /var/lib/go53
Import dir:    ${IMPORT_DIR} -> /imports
DNS:           ${DNS_BIND}:${DNS_HOST_PORT} -> container :2053 (host :53 not used)
API:           ${API_BIND}:${API_HOST_PORT} -> container :8053
Sync:          ${SYNC_BIND}:${SYNC_HOST_PORT} -> container :53530

Useful commands:
  sudo -u ${SERVICE_USER} env HOME=${SERVICE_HOME} XDG_RUNTIME_DIR=/run/user/$(service_uid) DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(service_uid)/bus sh -c 'cd "$HOME" && exec systemctl --user status $(unit_service)'
  sudo -u ${SERVICE_USER} env HOME=${SERVICE_HOME} XDG_RUNTIME_DIR=/run/user/$(service_uid) DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(service_uid)/bus sh -c 'cd "$HOME" && exec journalctl --user -u $(unit_service) -f'
  sudo -u ${SERVICE_USER} env HOME=${SERVICE_HOME} XDG_RUNTIME_DIR=/run/user/$(service_uid) sh -c 'cd "$HOME" && exec podman exec ${CONTAINER_NAME} go53ctl distributed status'
  sudo cp example.se.zone example.se.key ${IMPORT_DIR}/
  sudo chown ${SERVICE_USER}:${SERVICE_USER} ${IMPORT_DIR}/example.se.zone ${IMPORT_DIR}/example.se.key
  sudo -u ${SERVICE_USER} env HOME=${SERVICE_HOME} XDG_RUNTIME_DIR=/run/user/$(service_uid) sh -c 'cd "$HOME" && exec podman exec ${CONTAINER_NAME} go53ctl zones import --dnssec preserve example.se. /imports/example.se.zone'
  sudo -u ${SERVICE_USER} env HOME=${SERVICE_HOME} XDG_RUNTIME_DIR=/run/user/$(service_uid) sh -c 'cd "$HOME" && exec podman exec ${CONTAINER_NAME} go53ctl dnskeys import-private --key-file /imports/example.se.key'
EOF
}

check_prereqs
write_quadlet
start_quadlet
configure_distributed
print_summary
