import json
import os
import hashlib
import uuid
import time
from datetime import datetime
from typing import List, Dict, Optional, Any
from fastapi import APIRouter, HTTPException, Query, Body, Depends, Request
from fastapi.responses import Response
from pydantic import BaseModel
import re

from app.services.semgrep_parser import parse_semgrep_json, validate_semgrep_output
from app.services.llm_recommender import generate_fixes
from app.services.report_generator import ReportGenerator
from app.services.auth_service import get_current_user
from app.models.database_models import User
from app.middleware.rate_limiter import rate_limiter

router = APIRouter()

class ReviewResponse(BaseModel):
    upload_id: str
    timestamp: str
    total_vulnerabilities: int
    error_severity_count: int
    warning_severity_count: int
    info_severity_count: int
    unknown_severity_count: int
    findings: List[Dict]
    fixes: List[Dict]
    summary: Dict
    errors: List[Dict] = []

class ReviewRequest(BaseModel):
    format: Optional[str] = "json"  # json, markdown, html
    custom_prompt: Optional[str] = None

@router.post("/review", response_model=ReviewResponse)
async def review_semgrep_results(
    semgrep_data: Any = Body(...),
    format: str = Query("json", description="Output format: json, markdown, html"),
    custom_prompt: Optional[str] = Query(None, description="Custom prompt for Pro/Enterprise users"),
    include_code_context: bool = Query(True, description="Whether to include code context in analysis"),
    current_user: User = Depends(get_current_user),
    request: Request = None
):
    """
    Main endpoint for processing semgrep JSON results.
    Processes JSON data and returns structured fixes.
    """
    # Check rate limit for authenticated users
    if request and not rate_limiter.check_rate_limit(request, is_authenticated=True):
        remaining_time = rate_limiter.get_reset_time(request, is_authenticated=True) - time.time()
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {int(remaining_time)} seconds"
        )
    
    errors = []
    upload_id = None
    
    try:
        # Use the dict directly
        semgrep_dict = semgrep_data
        
        # Validate semgrep structure
        if not isinstance(semgrep_dict, dict):
            raise HTTPException(
                status_code=400,
                detail="Invalid semgrep format. Data must be a JSON object."
            )
        
        if "results" not in semgrep_dict:
            raise HTTPException(
                status_code=400,
                detail="Invalid semgrep format. File must contain a 'results' array."
            )
        
        # Generate upload ID using SHA256 hash of data
        content_str = json.dumps(semgrep_dict, sort_keys=True)
        file_hash = hashlib.sha256(content_str.encode('utf-8')).hexdigest()[:16]
        upload_id = f"{file_hash}_{uuid.uuid4().hex[:8]}"
        
        # Optional: Save to /data/ if DEBUG=True
        if os.getenv("DEBUG", "False").lower() == "true":
            debug_dir = "data"
            os.makedirs(debug_dir, exist_ok=True)
            debug_file = f"{debug_dir}/{upload_id}_semgrep_input.json"
            with open(debug_file, "w") as f:
                json.dump(semgrep_dict, f, indent=2)
        
        # Parse semgrep results with code context
        findings = parse_semgrep_json(semgrep_dict, include_code_context=include_code_context)
        
        # Validate semgrep output and provide recommendations
        validation = validate_semgrep_output(semgrep_dict)
        
        if not findings:
            return ReviewResponse(
                upload_id=upload_id,
                timestamp=datetime.now().isoformat(),
                total_vulnerabilities=0,
                error_severity_count=0,
                warning_severity_count=0,
                info_severity_count=0,
                unknown_severity_count=0,
                findings=[],
                fixes=[],
                summary={"message": "No vulnerabilities found"},
                errors=errors
            )
        
        # Generate fixes with retry logic
        fixes = []
        for finding in findings:
            try:
                # Try to generate fix
                fix_result = generate_fixes([finding], tier=current_user.tier, custom_prompt=custom_prompt)
                if fix_result:
                    fixes.extend(fix_result)
                else:
                    errors.append({
                        "finding_id": finding.get('rule_id', 'unknown'),
                        "file": finding.get('path', 'unknown'),
                        "error": "Failed to generate fix after retry"
                    })
            except Exception as e:
                errors.append({
                    "finding_id": finding.get('rule_id', 'unknown'),
                    "file": finding.get('path', 'unknown'),
                    "error": f"LLM Error: {str(e)}"
                })
        
        # Calculate confidence statistics
        high_confidence = len([f for f in fixes if f.get('confidence_score', 0) >= 0.8])
        medium_confidence = len([f for f in fixes if 0.5 <= f.get('confidence_score', 0) < 0.8])
        low_confidence = len([f for f in fixes if f.get('confidence_score', 0) < 0.5])
        
        # Generate summary
        summary = {
            "total_vulnerabilities": len(findings),
            "high_confidence_fixes": high_confidence,
            "medium_confidence_fixes": medium_confidence,
            "low_confidence_fixes": low_confidence,
            "fix_types": {},
            "severity_distribution": {},
            "errors_count": len(errors),
            "code_context_stats": {
                "findings_with_code": validation["findings_with_code"],
                "findings_without_code": validation["findings_without_code"],
                "code_coverage_percentage": round((validation["findings_with_code"] / len(findings) * 100) if len(findings) > 0 else 0, 1)
            },
            "semgrep_recommendations": validation["recommendations"]
        }
        
        # Analyze fix types and severity
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            summary["severity_distribution"][severity] = summary["severity_distribution"].get(severity, 0) + 1
        
        for fix in fixes:
            fix_type = fix.get('fix_type', 'unknown')
            summary["fix_types"][fix_type] = summary["fix_types"].get(fix_type, 0) + 1
        
        # Create response data
        response_data = {
            "upload_id": upload_id,
            "timestamp": datetime.now().isoformat(),
            "total_vulnerabilities": len(findings),
            "high_confidence_fixes": high_confidence,
            "medium_confidence_fixes": medium_confidence,
            "low_confidence_fixes": low_confidence,
            "findings": findings,
            "fixes": fixes,
            "summary": summary,
            "errors": errors
        }
        
        # Generate report based on format
        if format.lower() in ["markdown", "html"]:
            from app.services.report_generator import ReportGenerator
            report_gen = ReportGenerator()
            report_content = report_gen.generate_report(response_data, format.lower())
            
            if format.lower() == "markdown":
                return Response(content=report_content, media_type="text/markdown")
            else:  # html
                return Response(content=report_content, media_type="text/html")
        else:
            # Return JSON response
            return ReviewResponse(**response_data)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Processing error: {str(e)}")

@router.get("/health")
async def health_check():
    """Health check endpoint for the review service."""
    return {"status": "healthy", "service": "review"}

@router.post("/test-upload")
async def test_upload(data: dict = Body(...)):
    """Simple test endpoint for file upload."""
    print(f"Test upload received data type: {type(data)}")
    print(f"Test upload received data keys: {list(data.keys()) if isinstance(data, dict) else 'Not a dict'}")
    print(f"Test upload data preview: {str(data)[:200]}...")
    return {"message": "Upload received", "data_keys": list(data.keys())}

@router.post("/review-public")
async def review_semgrep_results_public(
    semgrep_data: Any = Body(...),
    format: str = Query("json", description="Output format: json, markdown, html"),
    custom_prompt: Optional[str] = Query(None, description="Custom prompt for Pro/Enterprise users"),
    include_code_context: bool = Query(True, description="Whether to include code context in analysis")
):
    """
    Public endpoint for processing semgrep JSON results (for dashboard use).
    This endpoint does not require authentication and uses FREE tier.
    """
    errors = []
    upload_id = None
    
    try:
        # Use the dict directly
        semgrep_dict = semgrep_data
        
        # Validate semgrep structure
        if not isinstance(semgrep_dict, dict):
            raise HTTPException(
                status_code=400,
                detail="Invalid semgrep format. Data must be a JSON object."
            )
        
        if "results" not in semgrep_dict:
            raise HTTPException(
                status_code=400,
                detail="Invalid semgrep format. File must contain a 'results' array."
            )
        
        # Generate upload ID using SHA256 hash of data
        content_str = json.dumps(semgrep_dict, sort_keys=True)
        file_hash = hashlib.sha256(content_str.encode('utf-8')).hexdigest()[:16]
        upload_id = f"{file_hash}_{uuid.uuid4().hex[:8]}"
        
        # Optional: Save to /data/ if DEBUG=True
        if os.getenv("DEBUG", "False").lower() == "true":
            debug_dir = "data"
            os.makedirs(debug_dir, exist_ok=True)
            debug_file = f"{debug_dir}/{upload_id}_semgrep_input.json"
            with open(debug_file, "w") as f:
                json.dump(semgrep_dict, f, indent=2)
        
        # Parse semgrep results with code context
        findings = parse_semgrep_json(semgrep_dict, include_code_context=include_code_context)
        
        # Validate semgrep output and provide recommendations
        validation = validate_semgrep_output(semgrep_dict)
        
        if not findings:
            return ReviewResponse(
                upload_id=upload_id,
                timestamp=datetime.now().isoformat(),
                total_vulnerabilities=0,
                error_severity_count=0,
                warning_severity_count=0,
                info_severity_count=0,
                unknown_severity_count=0,
                findings=[],
                fixes=[],
                summary={"message": "No vulnerabilities found"},
                errors=errors
            )
        
        # Generate fixes with retry logic (using FREE tier for public endpoint)
        fixes = []
        for finding in findings:
            try:
                # Try to generate fix (using FREE tier for public endpoint)
                fix_result = generate_fixes([finding], tier="FREE", custom_prompt=custom_prompt)
                if fix_result:
                    fixes.extend(fix_result)
                else:
                    errors.append({
                        "finding_id": finding.get('rule_id', 'unknown'),
                        "file": finding.get('path', 'unknown'),
                        "error": "Failed to generate fix after retry"
                    })
            except Exception as e:
                errors.append({
                    "finding_id": finding.get('rule_id', 'unknown'),
                    "file": finding.get('path', 'unknown'),
                    "error": f"LLM Error: {str(e)}"
                })
        
        # Calculate severity-based statistics
        error_severity = len([f for f in findings if f.get('severity', 'UNKNOWN') == 'ERROR'])
        warning_severity = len([f for f in findings if f.get('severity', 'UNKNOWN') == 'WARNING'])
        info_severity = len([f for f in findings if f.get('severity', 'UNKNOWN') == 'INFO'])
        unknown_severity = len([f for f in findings if f.get('severity', 'UNKNOWN') not in ['ERROR', 'WARNING', 'INFO']])
        
        # Generate summary
        summary = {
            "total_vulnerabilities": len(findings),
            "error_severity_count": error_severity,
            "warning_severity_count": warning_severity,
            "info_severity_count": info_severity,
            "unknown_severity_count": unknown_severity,
            "fix_types": {},
            "severity_distribution": {},
            "errors_count": len(errors),
            "code_context_stats": {
                "findings_with_code": validation["findings_with_code"],
                "findings_without_code": validation["findings_without_code"],
                "code_coverage_percentage": round((validation["findings_with_code"] / len(findings) * 100) if len(findings) > 0 else 0, 1)
            },
            "semgrep_recommendations": validation["recommendations"]
        }
        
        # Analyze fix types and severity
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            summary["severity_distribution"][severity] = summary["severity_distribution"].get(severity, 0) + 1
        
        for fix in fixes:
            fix_type = fix.get('fix_type', 'unknown')
            summary["fix_types"][fix_type] = summary["fix_types"].get(fix_type, 0) + 1
        
        # Create response data
        response_data = {
            "upload_id": upload_id,
            "timestamp": datetime.now().isoformat(),
            "total_vulnerabilities": len(findings),
            "error_severity_count": error_severity,
            "warning_severity_count": warning_severity,
            "info_severity_count": info_severity,
            "unknown_severity_count": unknown_severity,
            "findings": findings,
            "fixes": fixes,
            "summary": summary,
            "errors": errors
        }
        
        # Generate report based on format
        if format.lower() in ["markdown", "html"]:
            from app.services.report_generator import ReportGenerator
            report_gen = ReportGenerator()
            report_content = report_gen.generate_report(response_data, format.lower())
            
            if format.lower() == "markdown":
                return Response(content=report_content, media_type="text/markdown")
            else:  # html
                return Response(content=report_content, media_type="text/html")
        else:
            # Return JSON response
            return ReviewResponse(**response_data)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Processing error: {str(e)}")

@router.post("/review-agentic", response_model=ReviewResponse)
async def review_semgrep_results_agentic(
    semgrep_data: Any = Body(...),
    format: str = Query("json", description="Output format: json, markdown, html"),
    custom_prompt: Optional[str] = Query(None, description="Custom prompt for Pro/Enterprise users"),
    include_code_context: bool = Query(True, description="Whether to include code context in analysis"),
    current_user: User = Depends(get_current_user),
    request: Request = None
):
    """
    Enhanced endpoint for agentic AI processing with fix validation, dependencies, and context.
    Provides richer data for automated fix application workflows.
    """
    # Reuse existing logic but enhance the response
    base_response = await review_semgrep_results(
        semgrep_data=semgrep_data,
        format=format,
        custom_prompt=custom_prompt,
        include_code_context=include_code_context,
        current_user=current_user,
        request=request
    )
    
    # Enhance fixes with additional data for agentic AI
    enhanced_fixes = []
    for fix in base_response.fixes:
        enhanced_fix = await enhance_fix_for_agentic_ai(fix, base_response.findings)
        enhanced_fixes.append(enhanced_fix)
    
    # Create enhanced response
    enhanced_response = ReviewResponse(
        upload_id=base_response.upload_id,
        timestamp=base_response.timestamp,
        total_vulnerabilities=base_response.total_vulnerabilities,
        high_confidence_fixes=base_response.high_confidence_fixes,
        medium_confidence_fixes=base_response.medium_confidence_fixes,
        low_confidence_fixes=base_response.low_confidence_fixes,
        findings=base_response.findings,
        fixes=enhanced_fixes,
        summary=base_response.summary,
        errors=base_response.errors
    )
    
    return enhanced_response

async def enhance_fix_for_agentic_ai(fix: Dict, findings: List[Dict]) -> Dict:
    """
    Enhance a fix with additional data for agentic AI processing.
    """
    # Find the corresponding finding
    finding = next((f for f in findings if f['rule_id'] == fix['rule_id']), None)
    
    enhanced_fix = fix.copy()
    
    # Add validation data
    enhanced_fix['validation'] = await generate_fix_validation(fix, finding)
    
    # Add context data
    enhanced_fix['context'] = await extract_function_context(finding)
    
    # Add dependency data
    enhanced_fix['dependencies'] = await analyze_fix_dependencies(fix, findings)
    
    # Add fix metadata
    enhanced_fix['metadata'] = {
        'fix_id': f"fix_{hash(fix['rule_id'] + fix['file_path'] + str(fix['line_number']))}",
        'created_at': datetime.now().isoformat(),
        'fix_category': categorize_fix(fix),
        'estimated_effort': estimate_fix_effort(fix),
        'risk_level': assess_fix_risk(fix)
    }
    
    return enhanced_fix

async def generate_fix_validation(fix: Dict, finding: Dict) -> Dict:
    """
    Generate validation data for a fix.
    """
    validation = {
        'syntax_check': True,  # Will be validated during application
        'test_coverage': 'unknown',
        'breaking_changes': False,
        'dependencies_affected': [],
        'backward_compatibility': True,
        'security_impact': 'positive',
        'performance_impact': 'minimal'
    }
    
    # Analyze fix type for potential issues
    if fix['fix_type'] == 'line_replacement':
        validation['breaking_changes'] = False
        validation['test_coverage'] = 'partial'
    elif fix['fix_type'] == 'generic_fix':
        validation['test_coverage'] = 'none'
        validation['breaking_changes'] = 'unknown'
    
    # Check for potential breaking changes
    if 'import' in fix.get('suggested_fix', '').lower():
        validation['dependencies_affected'] = ['imports']
    
    return validation

async def extract_function_context(finding: Dict) -> Dict:
    """
    Extract function and class context from the finding.
    """
    context = {
        'function_name': None,
        'class_name': None,
        'scope': 'unknown',
        'related_functions': [],
        'file_structure': 'unknown'
    }
    
    if not finding:
        return context
    
    # Try to extract function name from code context
    code_lines = finding.get('code', [])
    if code_lines:
        # Look for function definitions
        for line in code_lines:
            if 'def ' in line:
                func_match = re.search(r'def\s+(\w+)', line)
                if func_match:
                    context['function_name'] = func_match.group(1)
                    context['scope'] = 'function'
                    break
        
        # Look for class definitions
        for line in code_lines:
            if 'class ' in line:
                class_match = re.search(r'class\s+(\w+)', line)
                if class_match:
                    context['class_name'] = class_match.group(1)
                    context['scope'] = 'class_method'
                    break
    
    return context

async def analyze_fix_dependencies(fix: Dict, findings: List[Dict]) -> Dict:
    """
    Analyze dependencies between fixes.
    """
    dependencies = {
        'requires_fixes': [],
        'conflicts_with': [],
        'order': 1,
        'affected_files': [fix['file_path']],
        'import_dependencies': fix.get('required_imports', [])
    }
    
    # Check for fixes that should be applied first
    for other_fix in findings:
        if other_fix['rule_id'] == fix['rule_id']:
            continue
            
        # Check if this fix depends on another fix in the same file
        if (other_fix['path'] == fix['file_path'] and 
            other_fix['start_line'] < fix['line_number']):
            dependencies['requires_fixes'].append(other_fix['rule_id'])
    
    # Check for potential conflicts
    for other_fix in findings:
        if other_fix['rule_id'] == fix['rule_id']:
            continue
            
        # Check for overlapping line ranges
        if (other_fix['path'] == fix['file_path'] and
            other_fix['start_line'] <= fix['line_number'] <= other_fix['end_line']):
            dependencies['conflicts_with'].append(other_fix['rule_id'])
    
    return dependencies

def categorize_fix(fix: Dict) -> str:
    """
    Categorize the fix type for better organization.
    """
    fix_text = fix.get('suggested_fix', '').lower()
    
    if 'sql' in fix_text or 'query' in fix_text:
        return 'sql_injection'
    elif 'xss' in fix_text or 'html' in fix_text or 'template' in fix_text:
        return 'xss'
    elif 'path' in fix_text or 'file' in fix_text:
        return 'path_traversal'
    elif 'debug' in fix_text:
        return 'debug_removal'
    elif 'import' in fix_text:
        return 'import_fix'
    else:
        return 'general_security'

def estimate_fix_effort(fix: Dict) -> str:
    """
    Estimate the effort required to apply the fix.
    """
    fix_type = fix.get('fix_type', '')
    confidence = fix.get('confidence_score', 0.5)
    
    if fix_type == 'line_replacement' and confidence > 0.8:
        return 'low'
    elif fix_type == 'line_replacement':
        return 'medium'
    else:
        return 'high'

def assess_fix_risk(fix: Dict) -> str:
    """
    Assess the risk level of applying the fix.
    """
    confidence = fix.get('confidence_score', 0.5)
    impact = fix.get('impact', 'medium')
    
    if confidence > 0.8 and impact == 'low':
        return 'low'
    elif confidence > 0.6:
        return 'medium'
    else:
        return 'high'

@router.get("/semgrep-config")
async def get_semgrep_config(
    target_path: str = Query(".", description="Target path to scan"),
    rules: str = Query("auto", description="Semgrep rules to use"),
    include_parse_tree: bool = Query(True, description="Include parse tree for better code extraction"),
    max_lines_per_finding: int = Query(20, description="Maximum lines per finding")
):
    """Get optimal Semgrep command for Semio integration."""
    from app.services.semgrep_config import get_optimal_semgrep_command, validate_semgrep_installation
    
    # Generate optimal command
    command = get_optimal_semgrep_command(
        target_path=target_path,
        rules=rules,
        include_parse_tree=include_parse_tree,
        max_lines_per_finding=max_lines_per_finding
    )
    
    # Check Semgrep installation
    installation_status = validate_semgrep_installation()
    
    return {
        "semgrep_command": command,
        "installation_status": installation_status,
        "recommendations": [
            "Use --include-parse-tree for better code extraction",
            "Use --max-lines-per-finding 20 for more context",
            "Ensure source files are accessible for fallback code reading"
        ]
    }

@router.post("/apply-fixes")
async def apply_fixes_agentic(
    semio_report: Dict = Body(...),
    auto_apply_high_confidence: bool = Query(True, description="Auto-apply fixes with confidence >= 0.8"),
    require_approval_medium: bool = Query(True, description="Require approval for medium confidence fixes"),
    current_user: User = Depends(get_current_user),
    request: Request = None
):
    """
    Agentic AI endpoint for applying security fixes with approval workflow.
    """
    try:
        # Validate the Semio report structure
        if 'fixes' not in semio_report:
            raise HTTPException(status_code=400, detail="Invalid Semio report: missing 'fixes' field")
        
        fixes = semio_report['fixes']
        if not fixes:
            return {
                "message": "No fixes to apply",
                "applied_fixes": [],
                "pending_approval": [],
                "rejected_fixes": []
            }
        
        # Categorize fixes by confidence level
        high_confidence_fixes = [f for f in fixes if f.get('confidence_score', 0) >= 0.8]
        medium_confidence_fixes = [f for f in fixes if 0.5 <= f.get('confidence_score', 0) < 0.8]
        low_confidence_fixes = [f for f in fixes if f.get('confidence_score', 0) < 0.5]
        
        applied_fixes = []
        pending_approval = []
        rejected_fixes = []
        
        # Auto-apply high confidence fixes
        if auto_apply_high_confidence:
            for fix in high_confidence_fixes:
                try:
                    result = await apply_single_fix(fix)
                    applied_fixes.append({
                        "fix_id": fix.get('metadata', {}).get('fix_id', 'unknown'),
                        "rule_id": fix['rule_id'],
                        "file_path": fix['file_path'],
                        "line_number": fix['line_number'],
                        "status": "applied",
                        "result": result
                    })
                except Exception as e:
                    rejected_fixes.append({
                        "fix_id": fix.get('metadata', {}).get('fix_id', 'unknown'),
                        "rule_id": fix['rule_id'],
                        "file_path": fix['file_path'],
                        "line_number": fix['line_number'],
                        "status": "failed",
                        "error": str(e)
                    })
        
        # Queue medium confidence fixes for approval
        if require_approval_medium:
            for fix in medium_confidence_fixes:
                approval_request = await create_approval_request(fix, current_user)
                pending_approval.append(approval_request)
        
        # Reject low confidence fixes
        for fix in low_confidence_fixes:
            rejected_fixes.append({
                "fix_id": fix.get('metadata', {}).get('fix_id', 'unknown'),
                "rule_id": fix['rule_id'],
                "file_path": fix['file_path'],
                "line_number": fix['line_number'],
                "status": "rejected",
                "reason": "Low confidence score"
            })
        
        return {
            "message": f"Processed {len(fixes)} fixes",
            "applied_fixes": applied_fixes,
            "pending_approval": pending_approval,
            "rejected_fixes": rejected_fixes,
            "summary": {
                "total_fixes": len(fixes),
                "applied": len(applied_fixes),
                "pending_approval": len(pending_approval),
                "rejected": len(rejected_fixes)
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error applying fixes: {str(e)}")

async def apply_single_fix(fix: Dict) -> Dict:
    """
    Apply a single fix to the codebase.
    """
    # This is a placeholder implementation
    # In a real implementation, you would:
    # 1. Read the target file
    # 2. Apply the fix at the specified line
    # 3. Validate the syntax
    # 4. Write the file back
    
    return {
        "status": "simulated",
        "message": f"Fix would be applied to {fix['file_path']} at line {fix['line_number']}",
        "original_code": fix.get('original_code', ''),
        "new_code": fix.get('suggested_fix', ''),
        "validation_passed": True
    }

async def create_approval_request(fix: Dict, user: User) -> Dict:
    """
    Create an approval request for a fix.
    """
    return {
        "approval_id": f"approval_{hash(fix['rule_id'] + fix['file_path'] + str(fix['line_number']))}",
        "fix_id": fix.get('metadata', {}).get('fix_id', 'unknown'),
        "rule_id": fix['rule_id'],
        "file_path": fix['file_path'],
        "line_number": fix['line_number'],
        "confidence_score": fix.get('confidence_score', 0),
        "suggested_fix": fix.get('suggested_fix', ''),
        "explanation": fix.get('explanation', ''),
        "impact": fix.get('impact', 'medium'),
        "created_by": user.username,
        "created_at": datetime.now().isoformat(),
        "status": "pending",
        "approval_url": f"/approve-fix/{fix.get('metadata', {}).get('fix_id', 'unknown')}"
    }

@router.post("/review-cli")
async def review_semgrep_results_cli(
    semgrep_data: Any = Body(...),
    format: str = Query("json", description="Output format: json, markdown, html"),
    custom_prompt: Optional[str] = Query(None, description="Custom prompt for Pro/Enterprise users"),
    include_code_context: bool = Query(True, description="Whether to include code context in analysis"),
    api_key: str = Query(..., description="API key for CLI access")
):
    """
    CLI-specific endpoint for processing semgrep JSON results.
    This endpoint allows direct API access with API key authentication.
    No rate limiting applied for CLI workflows.
    """
    errors = []
    upload_id = None
    
    try:
        # Validate API key
        from app.services.auth_service import AuthService
        user_info = AuthService.validate_api_key(api_key)
        if not user_info:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired API key. Please provide a valid API key for CLI access."
            )
        
        # Use the dict directly
        semgrep_dict = semgrep_data
        
        # Validate semgrep structure
        if not isinstance(semgrep_dict, dict):
            raise HTTPException(
                status_code=400,
                detail="Invalid semgrep format. Data must be a JSON object."
            )
        
        if "results" not in semgrep_dict:
            raise HTTPException(
                status_code=400,
                detail="Invalid semgrep format. File must contain a 'results' array."
            )
        
        # Generate upload ID using SHA256 hash of data
        content_str = json.dumps(semgrep_dict, sort_keys=True)
        file_hash = hashlib.sha256(content_str.encode('utf-8')).hexdigest()[:16]
        upload_id = f"{file_hash}_{uuid.uuid4().hex[:8]}"
        
        # Optional: Save to /data/ if DEBUG=True
        if os.getenv("DEBUG", "False").lower() == "true":
            debug_dir = "data"
            os.makedirs(debug_dir, exist_ok=True)
            debug_file = f"{debug_dir}/{upload_id}_semgrep_input.json"
            with open(debug_file, "w") as f:
                json.dump(semgrep_dict, f, indent=2)
        
        # Parse semgrep results with code context
        findings = parse_semgrep_json(semgrep_dict, include_code_context=include_code_context)
        
        # Validate semgrep output and provide recommendations
        validation = validate_semgrep_output(semgrep_dict)
        
        # Add false positive analysis to each finding
        from app.services.false_positive_filter import FalsePositiveFilter
        fp_filter = FalsePositiveFilter()
        
        enhanced_findings = []
        for finding in findings:
            # Analyze for false positive likelihood
            fp_score, validation_details = fp_filter.analyze_finding(finding)
            
            # Add false positive analysis to the finding
            enhanced_finding = finding.copy()
            enhanced_finding['false_positive_analysis'] = {
                'is_likely_false_positive': fp_score > 0.7,
                'confidence_score': fp_score,
                'validation_details': validation_details,
                'reasoning': _generate_fp_reasoning(validation_details, finding)
            }
            enhanced_findings.append(enhanced_finding)
        
        if not enhanced_findings:
            return ReviewResponse(
                upload_id=upload_id,
                timestamp=datetime.now().isoformat(),
                total_vulnerabilities=0,
                error_severity_count=0,
                warning_severity_count=0,
                info_severity_count=0,
                unknown_severity_count=0,
                findings=[],
                fixes=[],
                summary={"message": "No vulnerabilities found"},
                errors=errors
            )
        
        # Generate fixes with retry logic (using FREE tier for CLI endpoint)
        fixes = []
        for finding in enhanced_findings:
            try:
                # Try to generate fix (using FREE tier for CLI endpoint)
                fix_result = generate_fixes([finding], tier="FREE", custom_prompt=custom_prompt)
                if fix_result:
                    fixes.extend(fix_result)
                else:
                    errors.append({
                        "finding_id": finding.get('rule_id', 'unknown'),
                        "file": finding.get('path', 'unknown'),
                        "error": "Failed to generate fix after retry"
                    })
            except Exception as e:
                errors.append({
                    "finding_id": finding.get('rule_id', 'unknown'),
                    "file": finding.get('path', 'unknown'),
                    "error": f"LLM Error: {str(e)}"
                })
        
        # Calculate severity-based statistics
        error_severity = len([f for f in enhanced_findings if f.get('severity', 'UNKNOWN') == 'ERROR'])
        warning_severity = len([f for f in enhanced_findings if f.get('severity', 'UNKNOWN') == 'WARNING'])
        info_severity = len([f for f in enhanced_findings if f.get('severity', 'UNKNOWN') == 'INFO'])
        unknown_severity = len([f for f in enhanced_findings if f.get('severity', 'UNKNOWN') not in ['ERROR', 'WARNING', 'INFO']])
        
        # Generate summary
        summary = {
            "total_vulnerabilities": len(enhanced_findings),
            "error_severity_count": error_severity,
            "warning_severity_count": warning_severity,
            "info_severity_count": info_severity,
            "unknown_severity_count": unknown_severity,
            "fix_types": {},
            "severity_distribution": {},
            "errors_count": len(errors),
            "code_context_stats": {
                "findings_with_code": validation["findings_with_code"],
                "findings_without_code": validation["findings_without_code"],
                "code_coverage_percentage": round((validation["findings_with_code"] / len(enhanced_findings) * 100) if len(enhanced_findings) > 0 else 0, 1)
            },
            "semgrep_recommendations": validation["recommendations"]
        }
        
        # Analyze fix types and severity
        for finding in enhanced_findings:
            severity = finding.get('severity', 'UNKNOWN')
            summary["severity_distribution"][severity] = summary["severity_distribution"].get(severity, 0) + 1
        
        for fix in fixes:
            fix_type = fix.get('fix_type', 'unknown')
            summary["fix_types"][fix_type] = summary["fix_types"].get(fix_type, 0) + 1
        
        # Create response data
        response_data = {
            "upload_id": upload_id,
            "timestamp": datetime.now().isoformat(),
            "total_vulnerabilities": len(enhanced_findings),
            "error_severity_count": error_severity,
            "warning_severity_count": warning_severity,
            "info_severity_count": info_severity,
            "unknown_severity_count": unknown_severity,
            "findings": enhanced_findings,
            "fixes": fixes,
            "summary": summary,
            "errors": errors
        }
        
        # Generate report based on format
        if format.lower() in ["markdown", "html"]:
            from app.services.report_generator import ReportGenerator
            report_gen = ReportGenerator()
            report_content = report_gen.generate_report(response_data, format.lower())
            
            if format.lower() == "markdown":
                return Response(content=report_content, media_type="text/markdown")
            else:  # html
                return Response(content=report_content, media_type="text/html")
        else:
            # Return JSON response
            return ReviewResponse(**response_data)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Processing error: {str(e)}")

@router.post("/review-agentic-cli")
async def review_semgrep_results_agentic_cli(
    semgrep_data: Any = Body(...),
    format: str = Query("json", description="Output format: json, markdown, html"),
    custom_prompt: Optional[str] = Query(None, description="Custom prompt for Pro/Enterprise users"),
    include_code_context: bool = Query(True, description="Whether to include code context in analysis"),
    api_key: str = Query(..., description="API key for CLI access")
):
    """
    CLI-specific enhanced endpoint for agentic AI processing.
    Provides enhanced data for automated fix application workflows.
    No rate limiting applied for CLI workflows.
    """
    # Validate API key
    from app.services.auth_service import AuthService
    user_info = AuthService.validate_api_key(api_key)
    if not user_info:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired API key. Please provide a valid API key for CLI access."
        )
    
    # Reuse existing logic but enhance the response
    base_response = await review_semgrep_results_cli(
        semgrep_data=semgrep_data,
        format=format,
        custom_prompt=custom_prompt,
        include_code_context=include_code_context,
        api_key=api_key
    )
    
    # Enhance fixes with additional data for agentic AI
    enhanced_fixes = []
    for fix in base_response.fixes:
        enhanced_fix = await enhance_fix_for_agentic_ai(fix, base_response.findings)
        enhanced_fixes.append(enhanced_fix)
    
    # Create enhanced response
    enhanced_response = ReviewResponse(
        upload_id=base_response.upload_id,
        timestamp=base_response.timestamp,
        total_vulnerabilities=base_response.total_vulnerabilities,
        high_confidence_fixes=base_response.high_confidence_fixes,
        medium_confidence_fixes=base_response.medium_confidence_fixes,
        low_confidence_fixes=base_response.low_confidence_fixes,
        findings=base_response.findings,
        fixes=enhanced_fixes,
        summary=base_response.summary,
        errors=base_response.errors
    )
    
    return enhanced_response

def _generate_fp_reasoning(validation_details: Dict[str, Any], finding: Dict[str, Any]) -> str:
    """Generate human-readable false positive reasoning."""
    reasoning_parts = []
    
    # Check rule-based analysis
    rule_analysis = validation_details.get('rule_based_analysis', {})
    if rule_analysis.get('passed'):
        matches = rule_analysis.get('matches', [])
        if matches:
            reasoning_parts.append(f"Rule-based analysis identified {len(matches)} indicators:")
            for match in matches[:3]:  # Show first 3 matches
                reasoning_parts.append(f"  • {match}")
    
    # Check LLM analysis
    llm_analysis = validation_details.get('llm_analysis', {})
    if llm_analysis.get('used') and llm_analysis.get('analysis'):
        reasoning_parts.append("AI analysis provided additional context for this assessment.")
    
    # Check specific context flags
    if validation_details.get('test_file_detected'):
        reasoning_parts.append("This finding is in test code, which is typically safe from exploitation.")
    
    if validation_details.get('mock_code_detected'):
        reasoning_parts.append("This finding is in mock/simulation code, not production code.")
    
    if validation_details.get('debug_code_detected'):
        reasoning_parts.append("This finding is in debug/development code, not production code.")
    
    if validation_details.get('high_confidence_rule'):
        reasoning_parts.append("This matches a high-confidence false positive pattern.")
    
    # Add confidence information
    confidence = validation_details.get('confidence_score', 0)
    if confidence > 0.8:
        reasoning_parts.append(f"High confidence ({confidence:.1%}) that this is a false positive.")
    elif confidence > 0.6:
        reasoning_parts.append(f"Moderate confidence ({confidence:.1%}) that this is a false positive.")
    else:
        reasoning_parts.append(f"Low confidence ({confidence:.1%}) - manual review recommended.")
    
    if not reasoning_parts:
        reasoning_parts.append("No specific false positive indicators found.")
    
    return "\n".join(reasoning_parts)
