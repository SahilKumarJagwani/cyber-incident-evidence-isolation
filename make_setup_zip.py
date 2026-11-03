"""
Run on WINDOWS, from the project folder (next to sandbox_receiver.py):

    venv\\Scripts\\python.exe make_setup_zip.py

Creates vm_setup.zip containing:
  vm_setup.sh          one-shot installer for the Ubuntu VM
  sandbox_receiver.py  the receiver service
  receiver.env         a freshly generated shared secret

and prints the matching Windows `setx` command. Carry the ZIP into the
offline VM with create_evidence_iso.py, then delete the ZIP/ISO afterwards.
"""

import os
import secrets
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
RECEIVER = os.path.join(HERE, "sandbox_receiver.py")
OUT_ZIP = os.path.join(HERE, "vm_setup.zip")

VM_SETUP = r'''#!/bin/bash
# One-shot installer for the evidence receiver. Run inside the Ubuntu VM:
#   bash vm_setup.sh
set -e
cd "$(dirname "$0")"

[ -f receiver.env ] && [ -f sandbox_receiver.py ] || {
    echo "receiver.env / sandbox_receiver.py not found next to this script."; exit 1; }

echo "[1/6] service user and folders"
id evidence >/dev/null 2>&1 || sudo useradd -r -s /usr/sbin/nologin evidence
sudo usermod -aG dialout evidence       # allows reading /dev/ttyS0
sudo usermod -aG evidence "$USER"       # lets you read the analysis folder
sudo mkdir -p /opt/evidence-receiver /srv/evidence
sudo chown -R evidence: /srv/evidence

echo "[2/6] receiver program and secret"
sudo install -o root -g root -m 755 sandbox_receiver.py /opt/evidence-receiver/sandbox_receiver.py
sudo install -o root -g root -m 600 receiver.env /etc/evidence-receiver.env

echo "[3/6] make sure no login prompt listens on COM1"
sudo systemctl mask serial-getty@ttyS0.service >/dev/null 2>&1 || true
sudo systemctl stop serial-getty@ttyS0.service >/dev/null 2>&1 || true

echo "[4/6] systemd service"
sudo tee /etc/systemd/system/evidence-receiver.service >/dev/null <<'UNIT'
[Unit]
Description=Evidence intake receiver (offline sandbox VM)

[Service]
User=evidence
Group=evidence
SupplementaryGroups=dialout
EnvironmentFile=/etc/evidence-receiver.env
ExecStart=/usr/bin/python3 /opt/evidence-receiver/sandbox_receiver.py
Restart=on-failure
RestartSec=5

# Hardening: no network at all, and writes only under /srv/evidence
PrivateNetwork=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/srv/evidence
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX

[Install]
WantedBy=multi-user.target
UNIT

echo "[5/6] start"
sudo systemctl daemon-reload
sudo systemctl enable evidence-receiver >/dev/null
sudo systemctl restart evidence-receiver
sleep 2

echo "[6/6] status"
systemctl is-active evidence-receiver
ls -l /dev/ttyS0 || echo "WARNING: /dev/ttyS0 not found - enable Serial Port 1 in VirtualBox."
echo
echo "Done. Log out and back in so you can read /srv/evidence/analysis."
'''


def main():
    if not os.path.isfile(RECEIVER):
        raise SystemExit("sandbox_receiver.py must be in the same folder as this script.")

    token = secrets.token_hex(32)

    with open(RECEIVER, "rb") as handle:
        receiver_bytes = handle.read().replace(b"\r\n", b"\n")

    env_text = "RECEIVER_TOKEN=%s\nRECEIVER_DEVICE=/dev/ttyS0\n" % token

    with zipfile.ZipFile(OUT_ZIP, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("vm_setup.sh", VM_SETUP.replace("\r\n", "\n"))
        archive.writestr("sandbox_receiver.py", receiver_bytes)
        archive.writestr("receiver.env", env_text)

    print("Created:", OUT_ZIP)
    print()
    print("Run this in PowerShell to give Flask the same secret,")
    print("then close and reopen your terminal / VS Code:")
    print()
    print('    setx SANDBOX_RECEIVER_TOKEN "%s"' % token)
    print()
    print("Delete vm_setup.zip and the ISO once the VM setup is finished.")


if __name__ == "__main__":
    main()