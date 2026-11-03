import os
import sys
import pycdlib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EXPORT_DIR = os.path.join(BASE_DIR, "sandbox_exports")
ISO_PATH = os.path.join(EXPORT_DIR, "evidence_zip_transfer.iso")

if len(sys.argv) != 2:
    raise SystemExit(
        "Usage: create_evidence_iso.py <path-to-verified-evidence.zip>"
    )

ZIP_PATH = os.path.abspath(sys.argv[1])

if not os.path.isfile(ZIP_PATH):
    raise FileNotFoundError(f"Evidence ZIP not found: {ZIP_PATH}")

os.makedirs(EXPORT_DIR, exist_ok=True)

iso = pycdlib.PyCdlib()
iso.new(interchange_level=1)

try:
    iso.add_file(ZIP_PATH, iso_path="/EVIDENCE.ZIP")
    iso.write(ISO_PATH)
finally:
    iso.close()

print("ISO created:", ISO_PATH)
print("ZIP size:", os.path.getsize(ZIP_PATH), "bytes")
print("ISO size:", os.path.getsize(ISO_PATH), "bytes")
