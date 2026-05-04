"""
Multi-scanner support: Semgrep, Bandit, Trivy, OWASP Dependency-Check.

All parsers emit the same normalized finding dict so the rest of the
pipeline (false_positive_filter, decision_engine, llm_recommender) is
completely unaware of which scanner produced the input.
"""

from __future__ import annotations
import re
from abc import ABC, abstractmethod
from typing import Any


# ---------------------------------------------------------------------------
# Normalized finding schema (matches existing semgrep_parser.py output)
# ---------------------------------------------------------------------------
# {
#   "rule_id": str,
#   "path": str,
#   "start_line": int,
#   "end_line": int,
#   "code": str | None,
#   "message": str,
#   "severity": str,       # "ERROR" | "WARNING" | "INFO" | "UNKNOWN"
#   "metadata": dict,
#   "description": str,
#   "references": list[str],
#   "cwe": list[str],
#   "owasp": list[str],
#   "scanner": str,        # "semgrep" | "bandit" | "trivy" | "dependency-check"
# }

_SEVERITY_MAP = {
    # Bandit / generic
    "critical": "ERROR",
    "high":     "ERROR",
    "medium":   "WARNING",
    "low":      "INFO",
    "info":     "INFO",
    # Semgrep
    "error":    "ERROR",
    "warning":  "WARNING",
    # Trivy
    "critical": "ERROR",
    "high":     "ERROR",
    "medium":   "WARNING",
    "low":      "INFO",
    "unknown":  "UNKNOWN",
}


def _normalize_severity(raw: str) -> str:
    return _SEVERITY_MAP.get(raw.lower(), "UNKNOWN")


def _make_finding(**kwargs) -> dict:
    defaults = {
        "rule_id": "unknown",
        "path": "unknown",
        "start_line": 0,
        "end_line": 0,
        "code": None,
        "message": "",
        "severity": "UNKNOWN",
        "metadata": {},
        "description": "",
        "references": [],
        "cwe": [],
        "owasp": [],
        "scanner": "unknown",
    }
    defaults.update(kwargs)
    return defaults


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class ScannerParser(ABC):
    name: str = "unknown"

    @classmethod
    @abstractmethod
    def detect(cls, data: dict) -> bool:
        """Return True if this parser recognises the JSON structure."""

    @classmethod
    @abstractmethod
    def parse(cls, data: dict) -> list[dict]:
        """Return a list of normalized finding dicts."""


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------

class SemgrepParser(ScannerParser):
    name = "semgrep"

    @classmethod
    def detect(cls, data: dict) -> bool:
        return "results" in data and isinstance(data.get("results"), list) and (
            not data.get("SchemaVersion")          # not Trivy
            and "dependencies" not in data          # not OWASP DC
        )

    @classmethod
    def parse(cls, data: dict, include_code_context: bool = True) -> list[dict]:
        from .semgrep_parser import parse_semgrep_json
        findings = parse_semgrep_json(data, include_code_context=include_code_context)
        for f in findings:
            f["scanner"] = cls.name
        return findings


# ---------------------------------------------------------------------------
# Bandit
# ---------------------------------------------------------------------------

class BanditParser(ScannerParser):
    name = "bandit"

    @classmethod
    def detect(cls, data: dict) -> bool:
        # Bandit JSON has a top-level "results" list whose items have "test_id"
        results = data.get("results", [])
        return bool(results) and "test_id" in results[0]

    @classmethod
    def parse(cls, data: dict) -> list[dict]:
        findings = []
        for item in data.get("results", []):
            cwe_raw = item.get("issue_cwe", {})
            cwe_id = cwe_raw.get("id")
            cwe = [f"CWE-{cwe_id}"] if cwe_id else []

            findings.append(_make_finding(
                scanner=cls.name,
                rule_id=f"bandit.{item.get('test_id', 'unknown')}",
                path=item.get("filename", "unknown"),
                start_line=item.get("line_number", 0),
                end_line=max(item.get("line_range", [item.get("line_number", 0)])),
                code=item.get("code"),
                message=item.get("issue_text", ""),
                severity=_normalize_severity(item.get("severity", "unknown")),
                description=item.get("issue_text", ""),
                cwe=cwe,
                metadata={
                    "confidence": item.get("confidence", ""),
                    "test_name": item.get("test_name", ""),
                    "more_info": item.get("more_info", ""),
                },
            ))
        return findings


# ---------------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------------

class TrivyParser(ScannerParser):
    name = "trivy"

    @classmethod
    def detect(cls, data: dict) -> bool:
        return "SchemaVersion" in data and "Results" in data

    @classmethod
    def parse(cls, data: dict) -> list[dict]:
        findings = []
        for result in data.get("Results", []):
            target = result.get("Target", "unknown")
            for vuln in result.get("Vulnerabilities") or []:
                cwe_raw = vuln.get("CweIDs") or []
                refs = [r.get("URL", r) if isinstance(r, dict) else r
                        for r in (vuln.get("References") or [])]

                pkg = vuln.get("PkgName", "")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")
                fix_note = f"Upgrade {pkg} from {installed} to {fixed}" if fixed else f"Update {pkg} ({installed})"

                findings.append(_make_finding(
                    scanner=cls.name,
                    rule_id=f"trivy.{vuln.get('VulnerabilityID', 'unknown')}",
                    path=target,
                    start_line=0,
                    end_line=0,
                    code=None,
                    message=vuln.get("Title", vuln.get("VulnerabilityID", "")),
                    severity=_normalize_severity(vuln.get("Severity", "unknown")),
                    description=vuln.get("Description", ""),
                    references=refs,
                    cwe=cwe_raw,
                    metadata={
                        "package": pkg,
                        "installed_version": installed,
                        "fixed_version": fixed,
                        "fix_note": fix_note,
                        "cvss": vuln.get("CVSS", {}),
                    },
                ))
        return findings


# ---------------------------------------------------------------------------
# OWASP Dependency-Check
# ---------------------------------------------------------------------------

class DependencyCheckParser(ScannerParser):
    name = "dependency-check"

    @classmethod
    def detect(cls, data: dict) -> bool:
        return "dependencies" in data and isinstance(data.get("dependencies"), list)

    @classmethod
    def parse(cls, data: dict) -> list[dict]:
        findings = []
        for dep in data.get("dependencies", []):
            file_name = dep.get("fileName", dep.get("filePath", "unknown"))
            for vuln in dep.get("vulnerabilities") or []:
                cwe_raw = [c if isinstance(c, str) else f"CWE-{c}" for c in (vuln.get("cwes") or [])]
                refs = [
                    r.get("url", r.get("name", str(r))) if isinstance(r, dict) else str(r)
                    for r in (vuln.get("references") or [])
                ]
                findings.append(_make_finding(
                    scanner=cls.name,
                    rule_id=f"dependency-check.{vuln.get('name', 'unknown')}",
                    path=file_name,
                    start_line=0,
                    end_line=0,
                    code=None,
                    message=vuln.get("name", ""),
                    severity=_normalize_severity(vuln.get("severity", "unknown")),
                    description=vuln.get("description", ""),
                    references=refs,
                    cwe=cwe_raw,
                    metadata={
                        "cvssScore": vuln.get("cvssScore"),
                        "source": vuln.get("source", ""),
                    },
                ))
        return findings


# ---------------------------------------------------------------------------
# Registry + auto-detect
# ---------------------------------------------------------------------------

_PARSERS: list[type[ScannerParser]] = [
    TrivyParser,           # check Trivy first (has unique SchemaVersion key)
    DependencyCheckParser, # check before Semgrep (both have "results"-like keys)
    BanditParser,
    SemgrepParser,
]


def detect_and_parse(data: dict) -> list[dict]:
    """
    Auto-detect scanner format and return normalized findings.
    Raises ValueError if format is unrecognised.
    """
    for parser_cls in _PARSERS:
        if parser_cls.detect(data):
            return parser_cls.parse(data)
    raise ValueError(
        "Unrecognised scanner output format. "
        "Supported: Semgrep, Bandit, Trivy, OWASP Dependency-Check."
    )


def detect_scanner(data: dict) -> str:
    """Return the scanner name for the given JSON data, or 'unknown'."""
    for parser_cls in _PARSERS:
        if parser_cls.detect(data):
            return parser_cls.name
    return "unknown"
