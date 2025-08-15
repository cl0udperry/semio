from fastapi import APIRouter
from app.services.semgrep_parser import parse_semgrep_json
from app.services.llm_recommender import generate_fixes
from pydantic import BaseModel, ConfigDict
from typing import Dict, Any

router = APIRouter()

class ScanRequest(BaseModel):
    results: list
    

@router.post("/scan")
async def handle_scan(data: dict):
    parsed_issues = parse_semgrep_json(data)
    response = generate_fixes(parsed_issues)
    return {"fixes": response}
    
