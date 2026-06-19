# Windows Digital Forensics and Malware Assessment Tool (WDFMAT)

A Windows-focused digital forensics and incident response (DFIR) tool that collects system artifacts, analyzes them for signs of compromise, and produces analyst-ready case reports (HTML, JSON, PDF).

> ⚠️ **For authorized security investigations and educational use only.**
> This tool reads registry keys, running processes, scheduled tasks, browser artifacts, and other sensitive system data. Only run it on systems you own or are explicitly authorized to investigate.

---

## ✨ Features

- 🖥️ **System Collection** — installed software, running processes, services, startup entries, scheduled tasks, user accounts, USB history, browser artifacts, event logs, network connections, recent files, and downloads
- 📧 **Email Artifact Analysis** — Outlook/Thunderbird data files, suspicious attachments, phishing indicator detection
- 🔍 **Automated Analysis**
  - Suspicious executable placement/naming detection
  - Unsigned or invalid Authenticode signature checks
  - Persistence mechanism detection (Run keys, services, scheduled tasks)
  - IOC matching (hashes, filenames, IPs, domains)
  - Optional YARA rule scanning
  - Optional VirusTotal reputation lookups
  - Suspicious network connection flagging
- 📊 **Forensic Timeline** — chronological view of file activity, event logs, and findings
- 📄 **Reporting** — generates polished HTML, JSON, and PDF case reports
- 🖱️ **GUI Dashboard** — Tkinter-based interface for running scans without the command line
- ⌨️ **CLI** — scriptable command-line interface for automated or remote use

---

## 📦 Requirements

- Windows OS (uses `winreg`, PowerShell, and Windows-specific APIs)
- Python 3.10+
- Optional dependencies for full functionality:
  ```bash
  pip install psutil requests yara-python
  ```
- **Run as Administrator** for complete registry, event log, service, and USB artifact coverage

---

## 🚀 Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/vminkook028/windows-forensics-tool.git
   cd windows-forensics-tool
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run via GUI:
   ```bash
   python run_gui.py
   ```

   Or via CLI:
   ```bash
   python run_scan.py --case-name "IR-Case-001" --output outputs --analyst "YourName"
   ```

4. Review the generated reports in the `outputs/` folder (HTML, JSON, PDF).

---

## ⚙️ CLI Options

| Flag | Description |
|---|---|
| `--case-name` | Case name used in reports |
| `--output` | Output directory (default: `outputs`) |
| `--iocs` | Path to IOC JSON file (default: `data/iocs.json`) |
| `--rules` | Path to YARA rules directory (default: `rules`) |
| `--virustotal` | Enable VirusTotal hash lookups |
| `--vt-api-key` | VirusTotal API key (or set `VT_API_KEY` env variable) |
| `--analyst` | Analyst name for report metadata |
| `--notes` | Case notes for report metadata |



---

## 🛡️ Disclaimer

This tool is intended for **authorized digital forensics, incident response, and educational purposes only**. It collects sensitive system and user data (registry contents, browser history, network connections, etc.). The author is not responsible for any misuse. Always:

- Obtain proper authorization before scanning any system
- Follow your organization's evidence handling and chain-of-custody procedures
- Treat all generated reports as sensitive/confidential, since they may contain personal or proprietary information
