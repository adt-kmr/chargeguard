#!/usr/bin/env bash
# Install the ChargeGuard node on a Raspberry Pi 5 (64-bit Raspberry Pi OS Bookworm).
#
#   sudo bash deploy/pi/node/install.sh            # from the repository root, on the Pi
#
# What it does
#   1. system packages: Python venv, nftables, TPM tools, bridge networking
#   2. SPI TPM overlay in /boot/firmware/config.txt (takes effect after a reboot)
#   3. Python environment in /opt/chargeguard/venv with the node's requirements,
#      plus ExecuTorch (CPU, aarch64) for the Llama advisor and the .pte models
#   4. the eth0 + eth1 bridge (systemd-networkd), node address 10.20.0.1/24 on br0
#   5. systemd services: chargeguard-node (gateway + dashboard) and chargeguard-flows
#      (packet capture on the charger-facing port), started at boot
#
# Re-running is safe. Nothing is downloaded except Debian and PyPI packages.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
PREFIX=/opt/chargeguard
CHARGER_PORT="${CHARGER_PORT:-eth1}"   # USB Ethernet adapter, cable to the charger
UPLINK_PORT="${UPLINK_PORT:-eth0}"     # on-board Ethernet, cable to the site switch

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
[ "$(uname -m)" = "aarch64" ] || echo "warning: not aarch64 ($(uname -m)); continuing"

echo ">> 1/5 packages"
apt-get update -qq
apt-get install -y -qq python3-venv python3-dev nftables tpm2-tools libtss2-dev rsync

echo ">> 2/5 TPM overlay"
CFG=/boot/firmware/config.txt
grep -q '^dtparam=spi=on' "$CFG" || echo 'dtparam=spi=on' >> "$CFG"
grep -q '^dtoverlay=tpm-slb9670' "$CFG" || echo 'dtoverlay=tpm-slb9670' >> "$CFG"

echo ">> 3/5 application and Python environment"
mkdir -p "$PREFIX"
rsync -a --delete --exclude '.git' --exclude 'vendor' --exclude 'data/raw' --exclude 'media' \
      --exclude 'deliverables' --exclude 'models/src' "$REPO/" "$PREFIX/app/"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install -q --upgrade pip
"$PREFIX/venv/bin/pip" install -q -r "$PREFIX/app/requirements.txt"
"$PREFIX/venv/bin/pip" install -q tpm2-pytss || echo "warning: tpm2-pytss failed (node TPM signing stays software)"
"$PREFIX/venv/bin/pip" install -q --extra-index-url https://download.pytorch.org/whl/cpu executorch==1.6.0 \
  || echo "warning: no ExecuTorch wheel for this platform; build it from source (see deploy/pi/README.md). The node runs without it."
id chargeguard >/dev/null 2>&1 || useradd --system --home "$PREFIX" --shell /usr/sbin/nologin chargeguard
chown -R chargeguard:chargeguard "$PREFIX"

echo ">> 4/5 bridge ${UPLINK_PORT} + ${CHARGER_PORT} -> br0"
install -d /etc/systemd/network
sed "s/@UPLINK@/${UPLINK_PORT}/; s/@CHARGER@/${CHARGER_PORT}/" "$REPO/deploy/pi/node/network/20-members.network" \
    > /etc/systemd/network/20-chargeguard-members.network
install -m 644 "$REPO/deploy/pi/node/network/10-br0.netdev" /etc/systemd/network/10-chargeguard-br0.netdev
install -m 644 "$REPO/deploy/pi/node/network/30-br0.network" /etc/systemd/network/30-chargeguard-br0.network
systemctl enable systemd-networkd

echo ">> 5/5 services"
install -m 644 "$REPO/deploy/pi/node/chargeguard.env" /etc/default/chargeguard
sed -i "s/^CHARGEGUARD_CHARGER_PORT=.*/CHARGEGUARD_CHARGER_PORT=${CHARGER_PORT}/" /etc/default/chargeguard
install -m 644 "$REPO/deploy/pi/node/chargeguard-node.service" /etc/systemd/system/
install -m 644 "$REPO/deploy/pi/node/chargeguard-flows.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable nftables chargeguard-node chargeguard-flows

cat <<EOF

Installed. Next:
  1. copy the Llama program from your development machine (optional, 1.1 GB):
       scp models/llama3_2_1b.pte models/tokenizer.model pi@<node>:${PREFIX}/app/models/
  2. reboot (enables the TPM overlay and the bridge):   sudo reboot
  3. after the reboot, check readiness:
       sudo -u chargeguard ${PREFIX}/venv/bin/python ${PREFIX}/app/scripts/pi_preflight.py --role node
  4. validate the firewall rules once, then switch to apply in /etc/default/chargeguard:
       CHARGEGUARD_FIREWALL=check  ->  CHARGEGUARD_FIREWALL=apply
  5. enrol the charger (see deploy/pi/README.md) and open http://<node>:8000
EOF
