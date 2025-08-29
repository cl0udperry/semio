"""
Agentic AI API endpoints for Semio
"""

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Query
from fastapi.responses import JSONResponse
from typing import Dict, List, Optional
import json
import logging
import traceback

from app.services.agentic_core import SemioAgenticCore
from app.services.agentic_types import AgentDecision
from app.models.user import UserTier
from app.services.tier_service import TierService
from app.services.auth_service import get_current_user, get_current_user_by_api_key_header

logger = logging.getLogger(__name__)

router = APIRouter()

# Global variable for agentic core (will be initialized on first use)
agentic_core = None

def get_agentic_core():
    """Get or initialize the agentic core"""
    global agentic_core
    if agentic_core is None:
        try:
            agentic_core = SemioAgenticCore()
            logger.info("Agentic core initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize agentic core: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Agentic AI system initialization failed: {str(e)}"
            )
    return agentic_core

@router.post("/agentic/analyze")
async def analyze_with_agentic_ai(
    file: UploadFile = File(...),
    auto_fix_threshold: float = 0.9,
    suppress_threshold: float = 0.8,
    current_user = Depends(get_current_user)
):
    """
    Analyze Semgrep findings using the agentic AI system
    
    Args:
        file: Semgrep JSON output file
        auto_fix_threshold: Confidence threshold for automatic fixes
        suppress_threshold: Confidence threshold for suppression
        current_user: Authenticated user
        
    Returns:
        Agentic analysis results with intelligent decisions
    """
    try:
        # Check tier permissions
        if not TierService.can_use_agentic_ai(current_user.tier):
            raise HTTPException(
                status_code=403,
                detail="Agentic AI features require Pro or Enterprise tier"
            )
        
        # Read and parse Semgrep JSON
        content = await file.read()
        try:
            semgrep_data = json.loads(content.decode('utf-8'))
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON file")
        
        # Process with agentic AI
        decisions = agentic_core.process_semgrep_findings(
            semgrep_data, auto_fix_threshold, suppress_threshold
        )
        
        # Convert decisions to JSON-serializable format
        decisions_json = []
        for decision in decisions:
            decisions_json.append({
                'finding_id': decision.finding_id,
                'file_path': decision.file_path,
                'line_number': decision.line_number,
                'rule_id': decision.rule_id,
                'action': decision.action.value,
                'confidence': decision.confidence,
                'fp_likelihood': decision.fp_likelihood,
                'fix_confidence': decision.fix_confidence,
                'original_code': decision.original_code,
                'suggested_fix': decision.suggested_fix,
                'explanation': decision.explanation,
                'metadata': decision.metadata
            })
        
        # Get agent statistics
        stats = agentic_core.get_agent_stats()
        
        return {
            'success': True,
            'decisions': decisions_json,
            'total_findings': len(decisions),
            'action_summary': _summarize_actions(decisions),
            'agent_stats': stats,
            'thresholds': {
                'auto_fix_threshold': auto_fix_threshold,
                'suppress_threshold': suppress_threshold
            }
        }
        
    except Exception as e:
        logger.error(f"Agentic analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@router.post("/agentic/analyze-json")
async def analyze_json_with_agentic_ai(
    semgrep_data: Dict,
    auto_fix_threshold: float = 0.9,
    suppress_threshold: float = 0.8,
    current_user = Depends(get_current_user)
):
    """
    Analyze Semgrep JSON data using the agentic AI system
    
    Args:
        semgrep_data: Raw Semgrep JSON data
        auto_fix_threshold: Confidence threshold for automatic fixes
        suppress_threshold: Confidence threshold for suppression
        current_user: Authenticated user
        
    Returns:
        Agentic analysis results with intelligent decisions
    """
    try:
        # Check tier permissions
        if not TierService.can_use_agentic_ai(current_user.tier):
            raise HTTPException(
                status_code=403,
                detail="Agentic AI features require Pro or Enterprise tier"
            )
        
        # Process with agentic AI
        decisions = agentic_core.process_semgrep_findings(
            semgrep_data, auto_fix_threshold, suppress_threshold
        )
        
        # Convert decisions to JSON-serializable format
        decisions_json = []
        for decision in decisions:
            decisions_json.append({
                'finding_id': decision.finding_id,
                'file_path': decision.file_path,
                'line_number': decision.line_number,
                'rule_id': decision.rule_id,
                'action': decision.action.value,
                'confidence': decision.confidence,
                'fp_likelihood': decision.fp_likelihood,
                'fix_confidence': decision.fix_confidence,
                'original_code': decision.original_code,
                'suggested_fix': decision.suggested_fix,
                'explanation': decision.explanation,
                'metadata': decision.metadata
            })
        
        return {
            'success': True,
            'decisions': decisions_json,
            'total_findings': len(decisions),
            'action_summary': _summarize_actions(decisions),
            'thresholds': {
                'auto_fix_threshold': auto_fix_threshold,
                'suppress_threshold': suppress_threshold
            }
        }
        
    except Exception as e:
        logger.error(f"Agentic analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@router.post("/agentic/analyze-json-cli")
async def analyze_json_with_agentic_ai_cli(
    semgrep_data: Dict,
    auto_fix_threshold: float = 0.9,
    suppress_threshold: float = 0.8,
    api_key: str = Query(None, description="API key for CLI access (deprecated, use Authorization header)"),
    authorization: str = Depends(get_current_user)
):
    """
    CLI-specific endpoint for agentic AI analysis
    
    Args:
        semgrep_data: Raw Semgrep JSON data
        auto_fix_threshold: Confidence threshold for automatic fixes
        suppress_threshold: Confidence threshold for suppression
        api_key: API key for CLI access
        
    Returns:
        Agentic analysis results with intelligent decisions
    """
    try:
        # Validate API key
        from app.services.auth_service import AuthService
        user_info = AuthService.validate_api_key(api_key)
        if not user_info:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired API key. Please provide a valid API key for CLI access."
            )
        
        # Process with agentic AI
        decisions = agentic_core.process_semgrep_findings(
            semgrep_data, auto_fix_threshold, suppress_threshold
        )
        
        # Convert decisions to JSON-serializable format
        decisions_json = []
        for decision in decisions:
            decisions_json.append({
                'finding_id': decision.finding_id,
                'file_path': decision.file_path,
                'line_number': decision.line_number,
                'rule_id': decision.rule_id,
                'action': decision.action.value,
                'confidence': decision.confidence,
                'fp_likelihood': decision.fp_likelihood,
                'fix_confidence': decision.fix_confidence,
                'original_code': decision.original_code,
                'suggested_fix': decision.suggested_fix,
                'explanation': decision.explanation,
                'metadata': decision.metadata
            })
        
        return {
            'success': True,
            'decisions': decisions_json,
            'total_findings': len(decisions),
            'action_summary': _summarize_actions(decisions),
            'thresholds': {
                'auto_fix_threshold': auto_fix_threshold,
                'suppress_threshold': suppress_threshold
            }
        }
        
    except Exception as e:
        logger.error(f"Agentic analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@router.post("/agentic/analyze-json-secure")
async def analyze_json_with_agentic_ai_secure(
    semgrep_data: Dict,
    auto_fix_threshold: float = 0.9,
    suppress_threshold: float = 0.8,
    current_user = Depends(get_current_user_by_api_key_header)
):
    """
    Secure endpoint for agentic AI analysis using Authorization header
    
    Args:
        semgrep_data: Raw Semgrep JSON data
        auto_fix_threshold: Confidence threshold for automatic fixes
        suppress_threshold: Confidence threshold for suppression
        current_user: Authenticated user (from Authorization header)
        
    Returns:
        Agentic analysis results with intelligent decisions
    """
    try:
        # Check tier permissions
        if not TierService.can_use_agentic_ai(current_user.tier):
            raise HTTPException(
                status_code=403,
                detail="Agentic AI features require Pro or Enterprise tier"
            )
        
        # Get or initialize agentic core
        core = get_agentic_core()
        
        # Process with agentic AI
        decisions = core.process_semgrep_findings(
            semgrep_data, auto_fix_threshold, suppress_threshold
        )
        
        # Convert decisions to JSON-serializable format
        decisions_json = []
        for decision in decisions:
            decisions_json.append({
                'finding_id': decision.finding_id,
                'file_path': decision.file_path,
                'line_number': decision.line_number,
                'rule_id': decision.rule_id,
                'action': decision.action.value,
                'confidence': decision.confidence,
                'fp_likelihood': decision.fp_likelihood,
                'fix_confidence': decision.fix_confidence,
                'original_code': decision.original_code,
                'suggested_fix': decision.suggested_fix,
                'explanation': decision.explanation,
                'metadata': decision.metadata
            })
        
        return {
            'success': True,
            'decisions': decisions_json,
            'total_findings': len(decisions),
            'action_summary': _summarize_actions(decisions),
            'thresholds': {
                'auto_fix_threshold': auto_fix_threshold,
                'suppress_threshold': suppress_threshold
            }
        }
        
    except Exception as e:
        error_traceback = traceback.format_exc()
        logger.error(f"Agentic analysis error: {e}")
        logger.error(f"Full traceback: {error_traceback}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@router.get("/agentic/stats-cli")
async def get_agentic_stats_cli(api_key: str = Query(..., description="API key for CLI access")):
    """
    CLI-specific endpoint for agentic AI statistics
    """
    try:
        # Validate API key
        from app.services.auth_service import AuthService
        user_info = AuthService.validate_api_key(api_key)
        if not user_info:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired API key. Please provide a valid API key for CLI access."
            )
        
        stats = agentic_core.get_agent_stats()
        return {
            'success': True,
            'stats': stats
        }
        
    except Exception as e:
        logger.error(f"Error getting agentic stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")

@router.get("/agentic/stats")
async def get_agentic_stats(current_user = Depends(get_current_user)):
    """
    Get statistics about the agentic AI system performance
    """
    try:
        # Check tier permissions
        if not TierService.can_use_agentic_ai(current_user.tier):
            raise HTTPException(
                status_code=403,
                detail="Agentic AI features require Pro or Enterprise tier"
            )
        
        stats = agentic_core.get_agent_stats()
        return {
            'success': True,
            'stats': stats
        }
        
    except Exception as e:
        logger.error(f"Error getting agentic stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")

@router.post("/agentic/feedback")
async def submit_agentic_feedback(
    decision_id: str,
    feedback_type: str,
    feedback_text: str = "",
    confidence_adjustment: float = 0.0,
    current_user = Depends(get_current_user)
):
    """
    Submit feedback for an agentic decision to improve future decisions
    """
    try:
        # Check tier permissions
        if not TierService.can_use_agentic_ai(current_user.tier):
            raise HTTPException(
                status_code=403,
                detail="Agentic AI features require Pro or Enterprise tier"
            )
        
        # Add feedback to memory store
        agentic_core.memory_store.add_user_feedback(
            decision_id, feedback_type, feedback_text, confidence_adjustment
        )
        
        return {
            'success': True,
            'message': 'Feedback submitted successfully'
        }
        
    except Exception as e:
        logger.error(f"Error submitting feedback: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to submit feedback: {str(e)}")

@router.post("/agentic/export")
async def export_agentic_results(
    decisions: List[Dict],
    format: str = "json",
    current_user = Depends(get_current_user)
):
    """
    Export agentic analysis results in various formats
    """
    try:
        # Check tier permissions
        if not TierService.can_use_agentic_ai(current_user.tier):
            raise HTTPException(
                status_code=403,
                detail="Agentic AI features require Pro or Enterprise tier"
            )
        
        # Convert back to AgentDecision objects
        decision_objects = []
        for decision_dict in decisions:
            # This is a simplified conversion - in production you'd want proper validation
            decision_objects.append(AgentDecision(
                finding_id=decision_dict['finding_id'],
                file_path=decision_dict['file_path'],
                line_number=decision_dict['line_number'],
                rule_id=decision_dict['rule_id'],
                action=agentic_core.ActionType(decision_dict['action']),
                confidence=decision_dict['confidence'],
                fp_likelihood=decision_dict['fp_likelihood'],
                fix_confidence=decision_dict['fix_confidence'],
                original_code=decision_dict['original_code'],
                suggested_fix=decision_dict.get('suggested_fix'),
                explanation=decision_dict['explanation'],
                metadata=decision_dict['metadata']
            ))
        
        # Export in requested format
        exported_content = agentic_core.export_decisions(decision_objects, format)
        
        if format == "json":
            return JSONResponse(content=json.loads(exported_content))
        elif format == "markdown":
            return JSONResponse(content={"content": exported_content, "format": "markdown"})
        elif format == "html":
            return JSONResponse(content={"content": exported_content, "format": "html"})
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")
        
    except Exception as e:
        logger.error(f"Error exporting results: {e}")
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")

def _summarize_actions(decisions: List[AgentDecision]) -> Dict[str, int]:
    """Summarize the distribution of actions taken by the agentic system"""
    summary = {}
    for decision in decisions:
        action = decision.action.value
        summary[action] = summary.get(action, 0) + 1
    return summary
