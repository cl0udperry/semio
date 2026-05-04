import pytest
from app.services.semgrep_parser import parse_semgrep_json, validate_semgrep_output, extract_context_for_fix


SAMPLE_FINDING = {
    "check_id": "python.lang.security.audit.weak-crypto.use-md5",
    "path": "src/utils/hashing.py",
    "start": {"line": 10, "col": 4},
    "end": {"line": 10, "col": 30},
    "extra": {
        "message": "Detected MD5 hash algorithm which is considered insecure.",
        "severity": "WARNING",
        "lines": "    hash = hashlib.md5(data).hexdigest()",
        "metadata": {"cwe": ["CWE-327"], "owasp": ["A2:2021"]},
        "description": "MD5 is a weak hashing algorithm.",
        "references": ["https://owasp.org/www-community/vulnerabilities/Weak_hashing"],
        "cwe": ["CWE-327"],
        "owasp": ["A2:2021"],
    },
}

SAMPLE_SEMGREP_OUTPUT = {"results": [SAMPLE_FINDING]}


def test_parse_semgrep_json_basic():
    results = parse_semgrep_json(SAMPLE_SEMGREP_OUTPUT)
    assert len(results) == 1
    r = results[0]
    assert r["rule_id"] == "python.lang.security.audit.weak-crypto.use-md5"
    assert r["path"] == "src/utils/hashing.py"
    assert r["start_line"] == 10
    assert r["severity"] == "WARNING"


def test_parse_semgrep_json_extracts_code():
    results = parse_semgrep_json(SAMPLE_SEMGREP_OUTPUT, include_code_context=True)
    assert results[0]["code"] == "    hash = hashlib.md5(data).hexdigest()"


def test_parse_semgrep_json_no_code_context():
    results = parse_semgrep_json(SAMPLE_SEMGREP_OUTPUT, include_code_context=False)
    assert results[0]["code"] is None


def test_parse_semgrep_json_empty():
    results = parse_semgrep_json({"results": []})
    assert results == []


def test_parse_semgrep_json_missing_end_line():
    finding = {**SAMPLE_FINDING, "end": {}}
    results = parse_semgrep_json({"results": [finding]})
    # end_line should fall back to start_line
    assert results[0]["end_line"] == results[0]["start_line"]


def test_parse_semgrep_json_metadata():
    results = parse_semgrep_json(SAMPLE_SEMGREP_OUTPUT)
    r = results[0]
    assert r["cwe"] == ["CWE-327"]
    assert r["owasp"] == ["A2:2021"]
    assert "MD5 is a weak" in r["description"]


def test_validate_semgrep_output_counts():
    validation = validate_semgrep_output(SAMPLE_SEMGREP_OUTPUT)
    assert validation["total_findings"] == 1
    assert validation["findings_with_code"] + validation["findings_without_code"] == 1


def test_validate_semgrep_output_empty():
    validation = validate_semgrep_output({"results": []})
    assert validation["total_findings"] == 0
    assert validation["findings_with_code"] == 0


def test_extract_context_for_fix():
    vuln = parse_semgrep_json(SAMPLE_SEMGREP_OUTPUT)[0]
    ctx = extract_context_for_fix(vuln)
    assert ctx["vulnerability_type"] == vuln["rule_id"]
    assert ctx["file_path"] == vuln["path"]
    assert ctx["line_number"] == vuln["start_line"]
    assert ctx["severity"] == "WARNING"
