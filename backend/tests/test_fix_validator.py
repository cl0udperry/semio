import pytest
from app.services.fix_validator import FixValidator


@pytest.fixture
def validator():
    return FixValidator()


def make_finding(path="src/app.py", rule_id="python.lang.security.audit.weak-crypto", code=""):
    return {"path": path, "rule_id": rule_id, "code": code}


class TestCleanCodeBlock:
    def test_strips_markdown_fences(self, validator):
        code = "```python\nhashlib.sha256(data)\n```"
        result = validator._clean_code_block(code)
        assert result == "hashlib.sha256(data)"

    def test_strips_repl_prefix(self, validator):
        code = ">>> x = 1"
        result = validator._clean_code_block(code)
        assert result == "x = 1"

    def test_plain_code_unchanged(self, validator):
        code = "x = hashlib.sha256(data).hexdigest()"
        result = validator._clean_code_block(code)
        assert result == code


class TestDetectLanguage:
    def test_python(self, validator):
        assert validator._detect_language("src/utils.py") == "python"

    def test_javascript(self, validator):
        assert validator._detect_language("src/index.js") == "javascript"

    def test_typescript(self, validator):
        assert validator._detect_language("src/app.ts") == "typescript"

    def test_unknown_defaults_to_python(self, validator):
        assert validator._detect_language("src/script.rb") == "python"


class TestValidatePythonSyntax:
    def test_valid_python(self, validator):
        assert validator._validate_python_syntax("x = hashlib.sha256(data).hexdigest()") is True

    def test_invalid_python(self, validator):
        assert validator._validate_python_syntax("def broken(") is False

    def test_multiline_valid(self, validator):
        code = "import hashlib\nhash_val = hashlib.sha256(b'data').hexdigest()"
        assert validator._validate_python_syntax(code) is True


class TestValidateSemantics:
    def test_empty_fix_is_invalid(self, validator):
        finding = make_finding()
        assert validator._validate_generic_semantics("", "   ", "") is False

    def test_identical_to_original_is_invalid(self, validator):
        original = "hashlib.md5(data)"
        assert validator._validate_generic_semantics("", original, original) is False

    def test_weak_crypto_replaced_with_strong(self, validator):
        original = "hashlib.md5(data)"
        fix = "hashlib.sha256(data)"
        result = validator._validate_python_semantics(
            "python.lang.security.audit.weak-crypto", original, fix
        )
        assert result is True

    def test_insecure_deserialization_replaced(self, validator):
        original = "pickle.loads(data)"
        fix = "json.loads(data)"
        result = validator._validate_python_semantics(
            "python.lang.security.audit.insecure-deserialization", original, fix
        )
        assert result is True


class TestValidateSecurityPatterns:
    def test_sql_injection_pattern_detected(self, validator):
        bad_fix = "cursor.execute('SELECT * FROM users WHERE id=' + user_id)"
        assert validator._validate_security_patterns(bad_fix, "python") is False

    def test_clean_fix_passes(self, validator):
        good_fix = "cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))"
        assert validator._validate_security_patterns(good_fix, "python") is True


class TestCalculateConfidence:
    def test_all_passing_gives_full_score(self, validator):
        assert validator._calculate_confidence(True, True, True, True) == pytest.approx(1.0)

    def test_all_failing_gives_zero(self, validator):
        assert validator._calculate_confidence(False, False, False, False) == 0.0

    def test_partial_score(self, validator):
        # syntax(0.3) + semantic(0.4) = 0.7
        score = validator._calculate_confidence(True, True, False, False)
        assert abs(score - 0.7) < 0.001


class TestValidateFix:
    def test_valid_python_fix(self, validator):
        finding = make_finding(code="hashlib.md5(data)")
        result = validator.validate_fix(finding, "hashlib.sha256(data).hexdigest()")
        assert result.is_valid is True
        assert result.confidence > 0.0

    def test_invalid_syntax_fix(self, validator):
        finding = make_finding()
        result = validator.validate_fix(finding, "def broken(")
        assert result.syntax_valid is False
        assert result.confidence < 1.0
