from fastapi import APIRouter, Depends, HTTPException, status
from app.services.scanner_parsers import detect_and_parse, detect_scanner
from app.services.llm_recommender import generate_fixes
from app.services.auth_service import get_current_user
from app.models.database_models import User
from pydantic import BaseModel, ConfigDict
from typing import Dict, Any

router = APIRouter()

class ScanRequest(BaseModel):
    results: list
    

@router.post("/scan")
async def handle_scan(
    data: dict,
    current_user: User = Depends(get_current_user)
):
    """
    Process Semgrep scan results and generate fixes.
    Requires authentication.
    """
    try:
        parsed_issues = detect_and_parse(data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    scanner = detect_scanner(data)
    response = generate_fixes(parsed_issues, tier=current_user.tier)
    return {"scanner": scanner, "fixes": response}
    
