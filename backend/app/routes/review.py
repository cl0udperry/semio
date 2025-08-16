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
    high_confidence_fixes: int
    medium_confidence_fixes: int
    low_confidence_fixes: int
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
                high_confidence_fixes=0,
                medium_confidence_fixes=0,
                low_confidence_fixes=0,
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
                high_confidence_fixes=0,
                medium_confidence_fixes=0,
                low_confidence_fixes=0,
                findings=[],
                fixes=[],
                summary={"message": "No vulnerabilities found"},
                errors=errors
            )
        
        # Generate fixes with retry logic (using FREE tier)
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
