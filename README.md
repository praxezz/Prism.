# PRISM — SIEM Rule Generator from Raw Logs

**PRISM** turns raw log files into ready-to-use SIEM detection rules. Point it at a Linux auth log, an Apache access log, a Windows Security event export, or a generic CSV/JSON/XML log, and it will flag suspicious activity — brute-force logins, privilege escalation, sensitive cloud API calls, cleared audit logs, and more — map each finding to **MITRE ATT&CK**, and emit ready-to-import **Sigma** and/or **Splunk** detection rules.

```
██████╗ ██████╗ ██╗███████╗███╗   ███╗
██╔══██╗██╔══██╗██║██╔════╝████╗ ████║
██████╔╝██████╔╝██║███████╗██╔████╔██║
██╔═══╝ ██╔══██╗██║╚════██║██║╚██╔╝██║
██║     ██║  ██║██║███████║██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝     ╚═╝
```

> **Status:** actively developed personal security tool. See [Disclaimer](#️-disclaimer).

---

## ✨ Features

- **Multi-format log parsing** — Linux `auth.log`, Apache combined log format, Windows Security event XML, and generic CSV/JSON/XML, all auto-normalized onto canonical fields (`src_ip`, `username`, `status`, `event_id`, etc.) so the same detection logic runs regardless of source.
- **Built-in detection engine** — brute-force/failed-login bursts, privileged logons, account/group creation, password-spraying and scanning patterns, sensitive AWS-style API calls (`CreateAccessKey`, `PutBucketPolicy`, `StopLogging`, ...), Kerberoasting indicators, cleared audit logs, and more.
- **MITRE ATT&CK mapping** — every finding is tagged with the relevant technique ID (e.g. `T1110.001 — Brute Force: Password Guessing`), not just a generic description.
- **Dual rule generation** — outputs [Sigma](https://github.com/SigmaHQ/sigma) YAML rules, Splunk searches (with alert metadata and risk scoring), or both.
- **Severity filtering** — only generate rules at or above a chosen severity (`low` / `medium` / `high` / `critical`).
- **Interactive mode** — run with no arguments to get a guided menu instead of memorizing flags.
- **Bundled demo data** — try it instantly on six sample log types with no files of your own.
- **Single file, two dependencies** — no project scaffolding, no package to install.

---

## 🚀 Getting Started

### Requirements

- Python 3.8+
- Windows, macOS, or Linux

### Installation

```bash
git clone https://github.com/<your-username>/prism.git
cd prism
pip install -r requirements.txt
```

Or use the launcher scripts, which install dependencies automatically on first run:

```bash
./run_prism.sh      # macOS / Linux
run_prism.bat        # Windows
```

### Run it

```bash
python prism.py
```

You'll land on an interactive menu — no CLI flags to remember. Direct CLI usage also works exactly as before:

```bash
python prism.py analyze auth.log
python prism.py analyze windows_security.evtx --format sigma --output ./rules/
python prism.py analyze access.log --format splunk --severity high
python prism.py demo --type auth
```

---

## 🧰 Menu Options

| Option | What it does |
|---|---|
| **1. Analyze Log File** | Prompts for a log path, runs the full detection pipeline, and generates rules — the interactive equivalent of `PRISM analyze <logfile>`. |
| **2. Run Demo** | Runs the pipeline against a bundled sample log (`auth`, `apache`, `windows`, `csv`, `json`, or `xml`) — no files of your own needed. |
| **h. Help** | In-app summary of all menu options and the equivalent CLI commands. |
| **q. Quit** | Exits PRISM. |

### CLI options (`analyze` command)

| Flag | Description |
|---|---|
| `--format {sigma,splunk,both}` | Output rule format (default: `sigma`) |
| `--output`, `-o` | Output directory for generated rules (default: `./output/rules`) |
| `--severity {low,medium,high,critical,all}` | Minimum severity threshold (default: `all`) |
| `--verbose`, `-v` | Show detailed analysis output |
| `--no-banner` | Suppress the ASCII banner |

### CLI options (`demo` command)

| Flag | Description |
|---|---|
| `--type {auth,apache,windows,csv,json,xml}` | Sample log type to demo (default: `auth`) |

---

## 📊 How detection works

1. **Parsing & normalization** — each log format has a dedicated parser (`AuthLogParser`, `ApacheLogParser`, `WindowsLogParser`, `CSVLogParser`, `JSONLogParser`, `XMLLogParser`), or PRISM auto-detects the format for you. Structured formats (CSV/JSON/XML) are flattened and field names are mapped onto a shared set of canonical fields regardless of the original vendor's naming.
2. **Detection** — the `DetectorEngine` runs a library of rules over the normalized records: known-bad Windows Security Event IDs, sensitive cloud API calls, failed-login bursts, scanning/spraying patterns, and more.
3. **MITRE mapping & severity** — each finding carries a severity (`low`/`medium`/`high`/`critical`) and a MITRE ATT&CK technique ID, and can be filtered by minimum severity before rule generation.
4. **Rule generation** — `SigmaGenerator` and `SplunkGenerator` turn each surviving finding into an importable Sigma YAML rule and/or a Splunk search with alert metadata and a risk score.

---

## ⚙️ Dependencies

| Package | Required? | Purpose |
|---|---|---|
| `rich` | ✅ Required | Powers the entire terminal UI (banner, menus, panels, tables, progress bars) |
| `pyyaml` | ✅ Required | Serializes generated Sigma rules to YAML |

Install both with:

```bash
pip install -r requirements.txt
```

---

## 📁 Output

Generated rules are written to the output directory (`./output/rules` by default) as Sigma YAML and/or Splunk search files, named after each finding, ready to import into your detection stack. Generated output is **not** committed to this repo — see `.gitignore`.

---

## 🗺️ Roadmap ideas

- [ ] Additional parsers (Nginx, Cisco ASA, cloud-native audit log formats beyond the generic CSV/JSON/XML path)
- [ ] Config file for custom detection thresholds and sensitive-action lists
- [ ] Additional rule output formats (Elastic detection rules, KQL)
- [ ] Non-interactive batch mode for scanning multiple log files in one run

Have another idea? Open an issue!

---

## 🤝 Contributing

Contributions are welcome! Please read **[CONTRIBUTING.md](CONTRIBUTING.md)** for setup instructions and guidelines before opening a PR.

## 🔒 Security

Found a security issue in PRISM itself? See **[SECURITY.md](SECURITY.md)**.

## ⚠️ Disclaimer

PRISM is an educational/personal security tool. Its detection rules are generated heuristically from patterns in the sample data provided — they are a starting point for tuning in your own environment, not a guarantee of detection coverage or an exhaustive threat model. Always review generated Sigma/Splunk rules before deploying them to production detection pipelines, and never run PRISM against logs containing data you aren't authorized to analyze.

## 📄 License

Released under the [MIT License](LICENSE).
