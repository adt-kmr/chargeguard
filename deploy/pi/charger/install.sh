#!/usr/bin/env bash
# Install the charger controller (OCPP 1.6 agent with a hardware TPM) on a second Raspberry Pi.
#
#   sudo bash deploy/pi/charger/install.sh          # from the repository root, on the charger Pi
#
# The charger gets the static address 10.20.0.15 on eth0 (cable to the node's eth1), measures
# its firmware image into PCR 23 of its TPM at every start, and connects to the node's OCPP
# endpoint at ws://10.20.0.1:9000/ocpp/CG-CHARGER-001.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
PREFIX=/opt/chargeguard-charger
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }

echo ">> packages"
apt-get update -qq
apt-get install -y -qq python3-venv python3-dev tpm2-tools libtss2-dev rsync

echo ">> TPM overlay"
CFG=/boot/firmware/config.txt
grep -q '^dtparam=spi=on' "$CFG" || echo 'dtparam=spi=on' >> "$CFG"
grep -q '^dtoverlay=tpm-slb9670' "$CFG" || echo 'dtoverlay=tpm-slb9670' >> "$CFG"

echo ">> application"
mkdir -p "$PREFIX"
rsync -a --delete --include 'charger/***' --include 'attestation/***' --include 'firmware/***' \
      --include 'scripts/' --include 'scripts/pi_preflight.py' \
      --include 'config.py' --include 'requirements.txt' --exclude '*' "$REPO/" "$PREFIX/app/"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install -q --upgrade pip
"$PREFIX/venv/bin/pip" install -q "ocpp==2.1.0" "websockets>=13.0" "cryptography>=42.0" tpm2-pytss
id chargeguard >/dev/null 2>&1 || useradd --system --home "$PREFIX" --shell /usr/sbin/nologin chargeguard
usermod -aG tss chargeguard 2>/dev/null || true          # /dev/tpmrm0 is owned by group tss
chown -R chargeguard:chargeguard "$PREFIX"

echo ">> network: eth0 10.20.0.15/24"
install -d /etc/systemd/network
cat > /etc/systemd/network/30-chargeguard-charger.network <<EOF
[Match]
Name=eth0

[Network]
Address=10.20.0.15/24
DNS=10.20.0.1
NTP=10.20.0.1
EOF
systemctl enable systemd-networkd

echo ">> service"
install -m 644 "$REPO/deploy/pi/charger/chargeguard-charger.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable chargeguard-charger

cat <<EOF

Installed. Next:
  1. sudo reboot   (enables the TPM overlay and the static address)
  2. check:   sudo -u chargeguard ${PREFIX}/venv/bin/python ${PREFIX}/app/scripts/pi_preflight.py --role charger
  3. enrol:   sudo -u chargeguard env CHARGEGUARD_TPM_TCTI=device:/dev/tpmrm0 \\
                ${PREFIX}/venv/bin/python -m charger.enroll --tpm tpm2-tss > enrol.json
     copy enrol.json to the node and run there:  python -m firmware.provision --enrol enrol.json
  4. the node signs the vendor firmware images; copy firmware/images/ and firmware/keys/CG-CHARGER-001_private.pem
     from the node so the charger boots a registered image with its enrolled device key
EOF
