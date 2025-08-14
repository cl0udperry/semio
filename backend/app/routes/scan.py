from fastapi import APIRouter, Request
from app.services.semgrep_parser import parse_semgrep_json
from app.services.llm_recommender import generate_fixes

router = APIRouter()

@router.post("/scan")
async def handle_scan(request: Request):
    data = await request.json()
    parsed_issues = parse_semgrep_json(data)
    response = generate_fixes(parsed_issues)
    return {"fixes": response}
    
