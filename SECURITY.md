# Security

PRISM parses log files that can contain sensitive data — IP addresses, usernames, hostnames, and sometimes more, depending on what you feed it. If you spot a way it could leak, mishandle, or unintentionally exfiltrate that data, I'd like to know.

## Found a problem?

- Open an issue on this repo, or
- Reach out to the maintainer directly (see profile) if it's something sensitive you'd rather not put in a public issue.

When you do, please include:
- PRISM version / commit hash
- OS and Python version
- The command or menu option you used, and the log format involved
- Steps to reproduce
- What actually happened vs. what you expected

Please **redact or truncate** any real log data (IPs, usernames, hostnames) before including it in a report.

## Scope notes

- PRISM is fully offline — it never sends parsed log data, findings, or generated rules anywhere over the network. If you find a code path that does, that's a valid finding regardless of severity.
- Generated Sigma/Splunk rules should never embed raw log content beyond what's needed to describe the detection logic (field names, matched values used as detection criteria) — if you find a rule template leaking more of the source log than that, flag it.
- Sample/demo logs bundled in the script are synthetic — if you find anything in them that looks like it could be mistaken for real credentials or infrastructure, let me know so it can be scrubbed further.
