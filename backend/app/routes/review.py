import json
import os
import asyncio
import hashlib
import uuid
from datetime import datetime
from typing import List, Dict, Optional
from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks, Query
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

from app.services.semgrep_parser import parse_semgrep_json
from app.services.llm_recommender import generate_fixes
from app.services.report_generator import ReportGenerator

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
    file: UploadFile = File(...),
    format: str = Query("json", description="Output format: json, markdown, html"),
    custom_prompt: Optional[str] = Query(None, description="Custom prompt for Pro/Enterprise users")
):
    """
    Main endpoint for processing semgrep JSON results.
    Processes file in memory and returns structured fixes.
    """
    errors = []
    upload_id = None
    
    try:
        # Validate file type
        if not file.filename.endswith('.json'):
            raise HTTPException(status_code=400, detail="File must be a JSON file")
        
        # Read file content in memory
        content = await file.read()
        
        # Generate upload ID using SHA256 hash of file contents
        file_hash = hashlib.sha256(content).hexdigest()[:16]
        upload_id = f"{file_hash}_{uuid.uuid4().hex[:8]}"
        
        # Parse JSON with better error handling
        try:
            semgrep_data = json.loads(content.decode('utf-8'))
        except json.JSONDecodeError as e:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid JSON file: {str(e)}. Please ensure the file contains valid JSON."
            )
        
        # Validate semgrep structure
        if not isinstance(semgrep_data, dict) or "results" not in semgrep_data:
            raise HTTPException(
                status_code=400,
                detail="Invalid semgrep format. File must contain a 'results' array."
            )
        
        # Optional: Save to /data/ if DEBUG=True
        if os.getenv("DEBUG", "False").lower() == "true":
            debug_dir = "data"
            os.makedirs(debug_dir, exist_ok=True)
            debug_file = f"{debug_dir}/{upload_id}_semgrep_input.json"
            with open(debug_file, "wb") as f:
                f.write(content)
        
        # Parse semgrep results
        findings = parse_semgrep_json(semgrep_data)
        
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
                fix_result = generate_fixes([finding], custom_prompt=custom_prompt)
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
            "errors_count": len(errors)
        }
        
        # Analyze fix types and severity
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            summary["severity_distribution"][severity] = summary["severity_distribution"].get(severity, 0) + 1
        
        for fix in fixes:
            fix_type = fix.get('fix_type', 'unknown')
            summary["fix_types"][fix_type] = summary["fix_types"].get(fix_type, 0) + 1
        
        return ReviewResponse(
            upload_id=upload_id,
            timestamp=datetime.now().isoformat(),
            total_vulnerabilities=len(findings),
            high_confidence_fixes=high_confidence,
            medium_confidence_fixes=medium_confidence,
            low_confidence_fixes=low_confidence,
            findings=findings,
            fixes=fixes,
            summary=summary,
            errors=errors
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Processing error: {str(e)}")

@router.get("/health")
async def health_check():
    """Health check endpoint for the review service."""
    return {"status": "healthy", "service": "review"}
