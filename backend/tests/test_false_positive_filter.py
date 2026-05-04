import pytest
from unittest.mock import patch, MagicMock
from app.services.false_positive_filter import FalsePositiveFilter


@pytest.fixture
def fp_filter():
    return FalsePositiveFilter()


def make_finding(path="src/app.py", rule_id="python.lang.security.audit.weak-crypto", code="", message=""):
    return {"path": path, "rule_id": rule_id, "code": code, "message": message}


class TestRuleBasedAnalysis:
    def test_test_file_gets_high_fp_score(self, fp_filter):
        finding = make_finding(path="tests/test_utils.py")
        score, matches = fp_filter._rule_based_analysis(finding)
        assert score > 0.3
        assert any("test_files" in m for m in matches)

    def test_mock_file_gets_elevated_fp_score(self, fp_filter):
        finding = make_finding(path="src/mock_service.py")
        score, matches = fp_filter._rule_based_analysis(finding)
        assert score > 0.0

    def test_production_file_gets_low_score(self, fp_filter):
        finding = make_finding(path="src/auth/login.py")
        score, _ = fp_filter._rule_based_analysis(finding)
        assert score < 0.5

    def test_score_capped_at_1(self, fp_filter):
        # Multiple matching patterns — score must never exceed 1.0
        finding = make_finding(path="tests/test_mock_fixture.py", code="# nosec mock.patch(")
        score, _ = fp_filter._rule_based_analysis(finding)
        assert score <= 1.0

    def test_high_confidence_rule_applied(self, fp_filter):
        finding = make_finding(
            path="src/crypto.py",
            rule_id="python.lang.security.audit.weak-crypto",
            code="hashlib.md5(data)",
        )
        score, matches = fp_filter._rule_based_analysis(finding)
        assert any("high_confidence_rule" in m for m in matches)


class TestContextDetection:
    def test_is_test_context_with_assert(self, fp_filter):
        assert fp_filter._is_test_context("assert result == expected", "") is True

    def test_is_test_context_with_mock(self, fp_filter):
        assert fp_filter._is_test_context("mock.patch('module.func')", "") is True

    def test_is_test_context_negative(self, fp_filter):
        assert fp_filter._is_test_context("user = User(name='alice')", "") is False

    def test_is_debug_context_with_print(self, fp_filter):
        assert fp_filter._is_debug_context("print(secret_key)", "") is True

    def test_is_debug_context_with_logger(self, fp_filter):
        assert fp_filter._is_debug_context("logger.debug(payload)", "") is True

    def test_is_debug_context_negative(self, fp_filter):
        assert fp_filter._is_debug_context("cursor.execute(query)", "") is False


class TestAnalyzeFinding:
    def test_returns_tuple_of_score_and_details(self, fp_filter):
        finding = make_finding()
        with patch.object(fp_filter, '_llm_based_analysis', return_value=(0.5, None)):
            score, details = fp_filter.analyze_finding(finding)
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0
        assert "final_score" in details

    def test_error_returns_neutral_score(self, fp_filter):
        # Simulate internal error
        with patch.object(fp_filter, '_rule_based_analysis', side_effect=RuntimeError("boom")):
            score, details = fp_filter.analyze_finding(make_finding())
        assert score == 0.5
        assert "error" in details

    def test_high_rule_score_skips_llm(self, fp_filter):
        finding = make_finding(path="tests/test_auth.py")
        with patch.object(fp_filter, '_llm_based_analysis') as mock_llm:
            fp_filter.analyze_finding(finding)
        # Rule score > 0.7, so LLM should NOT be called
        mock_llm.assert_not_called()
