# Contributing to PRISM

Thanks for your interest in improving PRISM! Contributions are welcome — new log parsers, detection rules, MITRE mappings, rule-generator improvements, and documentation fixes all help.

## Getting started

1. Fork the repo and clone your fork.
2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Create a branch for your change: `git checkout -b feature/my-improvement`.

## Running it

```bash
python prism.py
```

Try both the interactive menu and the direct CLI commands to confirm your change didn't break either path:

```bash
python prism.py demo --type auth
python prism.py analyze <some-log-file> --format both --verbose
```

Run through all six bundled demo types (`auth`, `apache`, `windows`, `csv`, `json`, `xml`) if you touch a parser or the detection engine, to make sure nothing regressed across formats.

## Guidelines

- Keep PRISM **fully offline** — it never makes network calls. Don't introduce any dependency that reaches out to the internet.
- New log formats get their own parser class (following the existing `AuthLogParser` / `ApacheLogParser` / `WindowsLogParser` / `CSVLogParser` / `JSONLogParser` / `XMLLogParser` pattern) and should normalize onto the canonical fields in `FIELD_ALIASES` rather than inventing new field names.
- New detection rules go in `DetectorEngine`; each finding must include a `severity` (`low`/`medium`/`high`/`critical`) and a `mitre_technique` (ID + name, e.g. `"T1110.001 — Brute Force: Password Guessing"`) — no finding without an ATT&CK mapping.
- Keep detection rules cheap per record — batch-style log files can be large, so avoid heavy per-line computation.
- If you add a new output format, follow the `SigmaGenerator` / `SplunkGenerator` pattern: take a finding dict in, return a ready-to-write rule/search string out.
- Match the existing Rich-based UI style (`console.print`, `Panel`, `Table`, `Progress`) rather than raw `print()`.
- Don't commit anything under `output/` or `sample_logs/` — both are generated at runtime and covered by `.gitignore`.

## Reporting bugs / suggesting features

Open a GitHub Issue with your OS/Python version, the command or menu option you used, the log format involved, and what happened vs. what you expected. Redact or truncate any real log data before pasting it into an issue.

## Security issues

See [SECURITY.md](SECURITY.md).
