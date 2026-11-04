# Cyber Incident Reporting & Evidence Isolation System

A Flask web application for reporting and triaging cyber incidents, built around one idea:
**suspicious files submitted as evidence must never be stored on the machine that runs the web app.**

## Why this exists

When someone reports a phishing email, the file usually lands on a server or an analyst's computer.
If it is opened by mistake, the machine meant to investigate the attack becomes the victim.
This project removes that risk by never putting the evidence on the host in the first place.

## Features

**Reporting (users)**
- Register and log in, then report an incident: type, description, date, location
- Questions about clicking a link or entering credentials set the case priority (HIGH / MEDIUM / LOW)
- Unique case IDs, status tracking and public updates from administrators
- Optional evidence upload: PNG, JPG, JPEG, PDF, TXT, EML (2 MB limit)

**Case management (admins)**
- Dashboard of all cases, status and priority changes, assignment to an administrator
- Public updates for the reporter and private investigation notes
- Audit log of administrator actions
- "Prepare for Sandbox" releases evidence for analysis inside the VM

**Evidence isolation**
- Uploads stay in RAM; nothing is written to the host's disk
- Evidence travels over a virtual serial port to an offline VM
- SHA-256 verified on arrival and again before release
- Fail-closed: if the VM is unavailable the report is rejected, never saved on the host
- Quarantine vault in the VM, then a read-only analysis folder after release

## Architecture

 ![Architecture diagram](architecture.png)


## Security design

| Measure | Purpose |
|---|---|
| In-memory upload stream (`InMemoryUploadRequest`) | Werkzeug normally spools uploads over 500 KB to a temp file; this keeps them in RAM |
| HMAC-SHA256 on every message, per-request nonce | Authenticates both ends, detects corruption or a stray process on the link |
| SHA-256 at intake and at release | Proves the file in the VM is exactly what was submitted |
| Fail-closed behaviour | No fallback storage on the host when the VM is down |
| Vault files mode 0600, released files 0444 | Quarantine before release, read-only after |
| Receiver runs as an unprivileged systemd service with `PrivateNetwork=true` | Limits what a compromised receiver can do |
| ID allow-list (32 hex chars) | Uploaded filenames never become file paths |
| Password hashing, CSRF protection, login rate limiting, one-time form tokens, hardened session cookies, input validation | Standard web-app protections |

## Requirements

- Windows host (the host side uses a Windows named pipe)
- Python 3.10+ (developed on 3.14)
- VirtualBox and an Ubuntu VM (24.04 desktop was used)

## Setup

### 1. The web app

```powershell
git clone https://github.com/SahilKumarJagwani/cyber-incident-evidence-isolation.git
cd cyber-incident-evidence-isolation
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python init_db.py
python create_admin.py
```

`create_admin.py` prompts for the administrator details; no password is stored in the repository.

### 2. The sandbox VM

1. Create an Ubuntu VM in VirtualBox with **all network adapters disabled**.
2. In the VM settings go to **Serial Ports, Port 1**:
   enable it, Port Number **COM1**, Port Mode **Host Pipe**, Path `\\.\pipe\CyberEvidenceSandbox`,
   and leave **"Connect to existing pipe/socket" unticked** (VirtualBox creates the pipe).
3. Keep Shared Clipboard, Drag'n'Drop and Shared Folders **disabled**.
4. Build the installer package (it generates a shared secret):
   ```powershell
   python make_setup_zip.py
   ```
   Run the `setx SANDBOX_RECEIVER_TOKEN "..."` line it prints, then open a new terminal.
5. Turn the package into an ISO and attach it to the VM's optical drive:
   ```powershell
   python create_evidence_iso.py vm_setup.zip
   ```
   The ISO is created at `sandbox_exports\evidence_zip_transfer.iso`.
6. Inside the VM:
   ```bash
   sudo mount /dev/sr0 /mnt
   mkdir -p ~/setup && cp /mnt/evidence.zip ~/setup/ && cd ~/setup
   python3 -m zipfile -e evidence.zip .
   bash vm_setup.sh
   ```
   The script installs the receiver as a systemd service. Log out and back in afterwards.
7. Delete `vm_setup.zip` and the ISO from the host: they contain the shared secret.

### 3. Run and verify

```powershell
$env:FLASK_SECRET_KEY = "a-long-random-string"   # or set it permanently with setx
python sandbox_link.py ping          # expect: OK: {...}
python sandbox_link.py speed 1       # optional throughput test
python app.py
```

Open http://127.0.0.1:5000, submit a report with evidence, then click **Prepare for Sandbox** as an admin.
The file appears in `/srv/evidence/analysis` inside the VM, read-only.

## Demo samples

`samples/` contains **fictional** training files, all harmless:

- `phishing_samples/`: four synthetic phishing emails (reserved `.example` / `.invalid` domains)
- `fake_malware_samples/`: a decoy PDF, a fake scareware screenshot, a base64 command that only prints a message, and a fake ransom note

Nothing in them can execute or reach a real server.

## License

MIT, see [LICENSE](LICENSE).

## Author

Sahil Kumar Jagwani
