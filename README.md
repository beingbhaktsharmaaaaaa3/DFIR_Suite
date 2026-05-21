# 🔬 ForenCore — Professional Forensic Workstation v1.0
### Forensic Acquisition, Analysis & Recovery Suite

---

## Quick Start

### Windows
```
Double-click: start_windows.bat
```

### Linux / Kali
```bash
chmod +x start_linux.sh
./start_linux.sh
```

Then the browser opens automatically to `frontend/index.html`
API Docs: **http://localhost:8000/api/docs**

---

## What ForenCore Does

| Module | Capability |
|---|---|
| 🧠 RAM Capture | Live memory acquisition — WinPMEM / /proc/kcore |
| 🔍 RAM Analysis | Volatility 3 — pslist, netscan, malfind, cmdline, dlllist |
| 💿 Disk Imaging | dd / dc3dd / Python fallback — RAW/DD format |
| 🗂 Disk Analysis | Partition scan, strings, entropy, filesystem, deleted files |
| 🗑 Data Recovery | File signature carving — PhotoRec / built-in carver |
| 📦 Partition Recovery | TestDisk / manual MBR scan for lost partitions |
| 🔧 Utilities | Hash calculator, hex viewer, strings extractor, entropy |
| 📄 Reports | Professional PDF + HTML + JSON forensic reports |

---

## Optional Tools (Enhance Capabilities)

Install these to unlock full functionality:

### Volatility 3 (RAM Analysis)
```bash
pip install volatility3
# or
git clone https://github.com/volatilityfoundation/volatility3
cd volatility3 && pip install -e .
```

### TestDisk + PhotoRec (Partition/File Recovery)
```bash
# Kali/Debian/Ubuntu
sudo apt install testdisk

# Windows
# Download from https://www.cgsecurity.org/wiki/TestDisk_Download
# Place testdisk.exe in the tools/ folder
```

### pytsk3 (Full Disk Filesystem Analysis)
```bash
pip install pytsk3
# If fails: sudo apt install python3-dev libewf-dev
```

### WinPMEM (Windows RAM Capture)
```
Download winpmem_mini_x64.exe from:
https://github.com/Velocidex/WinPmem/releases
Place in: tools/winpmem.exe
```

### dc3dd (Forensic Disk Imaging)
```bash
# Kali/Debian
sudo apt install dc3dd

# Windows: Download from SourceForge, place in tools/
```

---

## Folder Structure

```
forencore/
├── backend/
│   ├── main.py                    # FastAPI app entry
│   ├── database.py                # SQLite setup
│   ├── models.py                  # DB models
│   ├── requirements.txt           # Python packages
│   ├── routers/
│   │   └── all_routers.py         # All 43 API endpoints
│   └── services/
│       ├── ram_capture.py         # WinPMEM / /proc/kcore
│       ├── ram_analysis.py        # Volatility 3 + psutil fallback
│       ├── disk_imaging.py        # dd / dc3dd / Python fallback
│       ├── forensic_analysis.py   # Disk analysis + recovery + partitions
│       └── report_service.py      # PDF + HTML + JSON reports
├── frontend/
│   └── index.html                 # Full React UI (no build step)
├── evidence/                      # Acquired images + dumps
├── reports/                       # Generated reports
├── recovered/                     # Recovered files
├── tools/                         # External forensic tools
├── start_windows.bat              # Windows launcher
├── start_linux.sh                 # Linux launcher
└── README.md
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | /api/system/info | Live system information |
| GET | /api/system/dashboard | Dashboard stats |
| POST | /api/ram/capture/start | Start RAM capture |
| GET | /api/ram/capture/progress/{id} | Capture progress |
| GET | /api/ram/capture/list | List captures |
| POST | /api/ram/analysis/full | Full Volatility analysis |
| POST | /api/ram/analysis/pslist | Process list |
| POST | /api/ram/analysis/netscan | Network connections |
| POST | /api/ram/analysis/malfind | Malicious memory regions |
| POST | /api/ram/analysis/cmdline | Command line history |
| POST | /api/ram/analysis/dlllist | DLL listing |
| GET | /api/ram/analysis/volatility/status | Volatility availability |
| GET | /api/disk/imaging/drives | Detect drives |
| POST | /api/disk/imaging/start | Start disk imaging |
| POST | /api/disk/imaging/upload | Upload image file |
| POST | /api/disk/imaging/verify | Verify image hash |
| POST | /api/disk/analysis/start | Analyze disk image |
| POST | /api/disk/analysis/partitions | Scan partitions |
| POST | /api/disk/analysis/strings | Extract strings |
| POST | /api/disk/analysis/entropy | File entropy |
| POST | /api/recovery/start | Start file recovery |
| GET | /api/recovery/progress/{id} | Recovery progress |
| POST | /api/partition/scan | Scan for lost partitions |
| POST | /api/utils/hash | Hash calculator |
| POST | /api/utils/hex | Hex viewer |
| POST | /api/utils/strings | String extractor |
| POST | /api/utils/entropy | Entropy analyzer |
| POST | /api/reports/generate | Generate report |
| GET | /api/reports/list | List reports |
| GET | /api/reports/download/{file} | Download report |

---

## Security & Legal Notice

- ForenCore is for **authorized forensic investigations only**
- **NEVER** run against systems without written authorization
- Evidence drives are opened **read-only** — source drives are never modified
- All acquisition tools use read-only flags where supported
- Run on a dedicated forensic workstation with full disk encryption
- Chain of custody is maintained via SHA256 hash verification

---

## Fallback Behavior

ForenCore works even without optional tools:

| Scenario | Fallback |
|---|---|
| Volatility 3 not installed | Shows live system processes/connections via psutil |
| WinPMEM not found | Demo memory dump written to evidence folder |
| dd/dc3dd not found | Python raw file reader (requires read access) |
| PhotoRec not found | Built-in file signature carver (jpg/png/pdf/zip/exe/mp4...) |
| TestDisk not found | Manual MBR partition table + signature scanner |
| pytsk3 not installed | Basic header/entropy/string analysis still works |

---

## Recommended Kali Setup

```bash
# Install all optional tools at once
sudo apt install testdisk dc3dd python3-venv python3-dev -y
pip install volatility3 pytsk3 --break-system-packages

# Then run ForenCore
chmod +x start_linux.sh
./start_linux.sh
```

---

Built with: FastAPI · SQLite · React · ReportLab
Inspired by: Autopsy · Volatility · FTK Imager · TestDisk · PhotoRec
