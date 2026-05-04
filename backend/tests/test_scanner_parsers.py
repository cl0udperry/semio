import pytest
from app.services.scanner_parsers import (
    detect_and_parse, detect_scanner,
    SemgrepParser, BanditParser, TrivyParser, DependencyCheckParser,
)

# ── fixtures ──────────────────────────────────────────────────────────────────

SEMGREP_DATA = {
    "results": [
        {
            "check_id": "python.lang.security.audit.weak-crypto.use-md5",
            "path": "src/utils.py",
            "start": {"line": 10, "col": 4},
            "end": {"line": 10, "col": 30},
            "extra": {
                "message": "MD5 is weak.",
                "severity": "WARNING",
                "lines": "hashlib.md5(data)",
                "metadata": {},
                "description": "MD5 is a weak algorithm.",
                "cwe": ["CWE-327"],
                "owasp": ["A2:2021"],
            },
        }
    ]
}

BANDIT_DATA = {
    "results": [
        {
            "test_id": "B324",
            "test_name": "hashlib",
            "issue_text": "Use of weak MD5 hash for security.",
            "severity": "HIGH",
            "confidence": "HIGH",
            "filename": "src/crypto.py",
            "line_number": 42,
            "line_range": [42, 43],
            "code": "hashlib.md5(secret)",
            "issue_cwe": {"id": 327, "link": "https://cwe.mitre.org/data/definitions/327.html"},
            "more_info": "https://bandit.readthedocs.io/",
        }
    ]
}

TRIVY_DATA = {
    "SchemaVersion": 2,
    "Results": [
        {
            "Target": "requirements.txt",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-1234",
                    "PkgName": "django",
                    "InstalledVersion": "3.2.0",
                    "FixedVersion": "3.2.18",
                    "Severity": "HIGH",
                    "Title": "Django SQL injection",
                    "Description": "A SQL injection vulnerability exists.",
                    "References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-1234"],
                    "CweIDs": ["CWE-89"],
                }
            ],
        }
    ],
}

DEPENDENCY_CHECK_DATA = {
    "dependencies": [
        {
            "fileName": "package-lock.json",
            "vulnerabilities": [
                {
                    "name": "CVE-2023-5678",
                    "severity": "MEDIUM",
                    "description": "Prototype pollution in lodash.",
                    "cwes": ["CWE-1321"],
                    "references": [{"name": "NVD", "url": "https://nvd.nist.gov/"}],
                    "cvssScore": 6.5,
                    "source": "NVD",
                }
            ],
        }
    ]
}

UNKNOWN_DATA = {"foo": "bar", "baz": []}


# ── detection ─────────────────────────────────────────────────────────────────

class TestDetection:
    def test_detects_semgrep(self):
        assert detect_scanner(SEMGREP_DATA) == "semgrep"

    def test_detects_bandit(self):
        assert detect_scanner(BANDIT_DATA) == "bandit"

    def test_detects_trivy(self):
        assert detect_scanner(TRIVY_DATA) == "trivy"

    def test_detects_dependency_check(self):
        assert detect_scanner(DEPENDENCY_CHECK_DATA) == "dependency-check"

    def test_unknown_returns_unknown(self):
        assert detect_scanner(UNKNOWN_DATA) == "unknown"

    def test_detect_and_parse_raises_on_unknown(self):
        with pytest.raises(ValueError, match="Unrecognised"):
            detect_and_parse(UNKNOWN_DATA)


# ── Semgrep ───────────────────────────────────────────────────────────────────

class TestSemgrepParser:
    def test_parse_returns_findings(self):
        findings = SemgrepParser.parse(SEMGREP_DATA)
        assert len(findings) == 1

    def test_scanner_field_set(self):
        f = SemgrepParser.parse(SEMGREP_DATA)[0]
        assert f["scanner"] == "semgrep"

    def test_normalized_fields_present(self):
        f = SemgrepParser.parse(SEMGREP_DATA)[0]
        assert f["rule_id"] == "python.lang.security.audit.weak-crypto.use-md5"
        assert f["path"] == "src/utils.py"
        assert f["start_line"] == 10


# ── Bandit ────────────────────────────────────────────────────────────────────

class TestBanditParser:
    def test_parse_returns_findings(self):
        findings = BanditParser.parse(BANDIT_DATA)
        assert len(findings) == 1

    def test_rule_id_format(self):
        f = BanditParser.parse(BANDIT_DATA)[0]
        assert f["rule_id"] == "bandit.B324"

    def test_severity_normalized(self):
        f = BanditParser.parse(BANDIT_DATA)[0]
        assert f["severity"] == "ERROR"  # HIGH → ERROR

    def test_cwe_extracted(self):
        f = BanditParser.parse(BANDIT_DATA)[0]
        assert "CWE-327" in f["cwe"]

    def test_code_preserved(self):
        f = BanditParser.parse(BANDIT_DATA)[0]
        assert f["code"] == "hashlib.md5(secret)"

    def test_line_number(self):
        f = BanditParser.parse(BANDIT_DATA)[0]
        assert f["start_line"] == 42
        assert f["end_line"] == 43

    def test_scanner_field(self):
        f = BanditParser.parse(BANDIT_DATA)[0]
        assert f["scanner"] == "bandit"


# ── Trivy ─────────────────────────────────────────────────────────────────────

class TestTrivyParser:
    def test_parse_returns_findings(self):
        findings = TrivyParser.parse(TRIVY_DATA)
        assert len(findings) == 1

    def test_rule_id_contains_cve(self):
        f = TrivyParser.parse(TRIVY_DATA)[0]
        assert "CVE-2023-1234" in f["rule_id"]

    def test_path_is_target(self):
        f = TrivyParser.parse(TRIVY_DATA)[0]
        assert f["path"] == "requirements.txt"

    def test_severity_high(self):
        f = TrivyParser.parse(TRIVY_DATA)[0]
        assert f["severity"] == "ERROR"

    def test_cwe_present(self):
        f = TrivyParser.parse(TRIVY_DATA)[0]
        assert "CWE-89" in f["cwe"]

    def test_fix_note_in_metadata(self):
        f = TrivyParser.parse(TRIVY_DATA)[0]
        assert "3.2.18" in f["metadata"]["fix_note"]

    def test_no_code_for_dependency_vuln(self):
        f = TrivyParser.parse(TRIVY_DATA)[0]
        assert f["code"] is None

    def test_empty_vulnerabilities_skipped(self):
        data = {"SchemaVersion": 2, "Results": [{"Target": "x", "Vulnerabilities": None}]}
        assert TrivyParser.parse(data) == []


# ── OWASP Dependency-Check ────────────────────────────────────────────────────

class TestDependencyCheckParser:
    def test_parse_returns_findings(self):
        findings = DependencyCheckParser.parse(DEPENDENCY_CHECK_DATA)
        assert len(findings) == 1

    def test_rule_id_contains_cve(self):
        f = DependencyCheckParser.parse(DEPENDENCY_CHECK_DATA)[0]
        assert "CVE-2023-5678" in f["rule_id"]

    def test_severity_medium(self):
        f = DependencyCheckParser.parse(DEPENDENCY_CHECK_DATA)[0]
        assert f["severity"] == "WARNING"

    def test_cwe_present(self):
        f = DependencyCheckParser.parse(DEPENDENCY_CHECK_DATA)[0]
        assert "CWE-1321" in f["cwe"]

    def test_reference_url_extracted(self):
        f = DependencyCheckParser.parse(DEPENDENCY_CHECK_DATA)[0]
        assert any("nvd.nist.gov" in r for r in f["references"])

    def test_scanner_field(self):
        f = DependencyCheckParser.parse(DEPENDENCY_CHECK_DATA)[0]
        assert f["scanner"] == "dependency-check"

    def test_no_vulnerabilities_skipped(self):
        data = {"dependencies": [{"fileName": "x.json", "vulnerabilities": None}]}
        assert DependencyCheckParser.parse(data) == []


# ── detect_and_parse end-to-end ───────────────────────────────────────────────

class TestDetectAndParse:
    @pytest.mark.parametrize("data,scanner,expected_count", [
        (SEMGREP_DATA, "semgrep", 1),
        (BANDIT_DATA, "bandit", 1),
        (TRIVY_DATA, "trivy", 1),
        (DEPENDENCY_CHECK_DATA, "dependency-check", 1),
    ])
    def test_all_scanners_end_to_end(self, data, scanner, expected_count):
        findings = detect_and_parse(data)
        assert len(findings) == expected_count
        assert all(f["scanner"] == scanner for f in findings)

    def test_all_findings_have_required_keys(self):
        required = {"rule_id", "path", "start_line", "end_line", "severity", "scanner"}
        for data in [SEMGREP_DATA, BANDIT_DATA, TRIVY_DATA, DEPENDENCY_CHECK_DATA]:
            for f in detect_and_parse(data):
                assert required.issubset(f.keys())
