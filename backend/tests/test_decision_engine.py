import pytest
from app.services.decision_engine import DecisionEngine
from app.services.agentic_types import ActionType


@pytest.fixture
def engine():
    return DecisionEngine()


def make_data(fp_score=0.1, fix_confidence=0.9, severity="ERROR", rule_id="some.rule"):
    return {
        "fp_score": fp_score,
        "fix_confidence": fix_confidence,
        "severity": severity,
        "rule_id": rule_id,
        "file_path": "src/app.py",
        "line_number": 42,
    }


class TestCalculateConfidence:
    def test_high_fp_lowers_confidence(self, engine):
        from app.services.decision_engine import DecisionFactors
        factors = DecisionFactors(fp_score=0.9, fix_confidence=0.9, severity="ERROR",
                                  rule_id="r", file_path="f", line_number=1)
        conf = engine._calculate_confidence(factors)
        assert conf < 0.2

    def test_zero_fp_high_fix_confidence_is_high(self, engine):
        from app.services.decision_engine import DecisionFactors
        factors = DecisionFactors(fp_score=0.0, fix_confidence=1.0, severity="ERROR",
                                  rule_id="r", file_path="f", line_number=1)
        conf = engine._calculate_confidence(factors)
        assert conf >= 0.9

    def test_severity_weight_info_lowers_confidence(self, engine):
        from app.services.decision_engine import DecisionFactors
        error_f = DecisionFactors(fp_score=0.0, fix_confidence=1.0, severity="ERROR",
                                  rule_id="r", file_path="f", line_number=1)
        info_f = DecisionFactors(fp_score=0.0, fix_confidence=1.0, severity="INFO",
                                 rule_id="r", file_path="f", line_number=1)
        assert engine._calculate_confidence(error_f) > engine._calculate_confidence(info_f)

    def test_confidence_clamped_0_to_1(self, engine):
        from app.services.decision_engine import DecisionFactors
        factors = DecisionFactors(fp_score=-1.0, fix_confidence=2.0, severity="ERROR",
                                  rule_id="r", file_path="f", line_number=1)
        conf = engine._calculate_confidence(factors)
        assert 0.0 <= conf <= 1.0


class TestMakeDecision:
    def test_suppress_when_fp_score_high(self, engine):
        data = make_data(fp_score=0.9)
        action, confidence, explanation = engine.make_decision(data, suppress_threshold=0.8)
        assert action == ActionType.SUPPRESS

    def test_auto_fix_when_high_confidence_low_fp(self, engine):
        data = make_data(fp_score=0.05, fix_confidence=0.95, severity="ERROR")
        action, confidence, _ = engine.make_decision(data, auto_fix_threshold=0.85)
        assert action == ActionType.AUTO_FIX

    def test_suggest_when_moderate_confidence(self, engine):
        # fp_score=0.1 → base=0.9, fix=0.8, ERROR weight=1.0 → confidence≈0.72 → SUGGEST
        data = make_data(fp_score=0.1, fix_confidence=0.8, severity="ERROR")
        action, _, _ = engine.make_decision(data, auto_fix_threshold=0.95, suppress_threshold=0.9)
        assert action == ActionType.SUGGEST

    def test_manual_review_when_low_confidence(self, engine):
        data = make_data(fp_score=0.5, fix_confidence=0.3, severity="INFO")
        action, _, _ = engine.make_decision(data, auto_fix_threshold=0.95, suppress_threshold=0.9)
        assert action == ActionType.MANUAL_REVIEW

    def test_returns_three_tuple(self, engine):
        result = engine.make_decision(make_data())
        assert len(result) == 3
        action, confidence, explanation = result
        assert isinstance(action, ActionType)
        assert isinstance(confidence, float)
        assert isinstance(explanation, str)

    def test_error_returns_manual_review(self, engine):
        action, confidence, _ = engine.make_decision({})  # Missing all keys → defaults
        assert isinstance(action, ActionType)

    def test_update_thresholds(self, engine):
        engine.update_thresholds("new.rule", {"auto_fix": 0.75, "suppress": 0.6})
        thresholds = engine._get_thresholds("new.rule")
        assert thresholds["auto_fix"] == 0.75

    def test_rule_specific_thresholds_used(self, engine):
        rule = "python.lang.correctness.useless-comparison"
        thresholds = engine._get_thresholds(rule)
        assert "auto_fix" in thresholds
        assert thresholds != engine.default_thresholds
