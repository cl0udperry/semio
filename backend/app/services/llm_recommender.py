import os
import json
import re
from anthropic import Anthropic
from dotenv import load_dotenv
from .semgrep_parser import extract_context_for_fix
from ..models.user import UserTier
from .tier_service import TierService

load_dotenv()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
MODEL = "claude-haiku-4-5-20251001"

SYSTEM_PROMPT = os.getenv(
    "SECURE_REVIEW_SYSTEM_PROMPT",
    "You are a security code expert specializing in automated vulnerability remediation. "
    "Your role is to: 1) Analyze: Identify the specific security vulnerability in the provided code "
    "2) Fix: Provide minimal, production-ready code changes that address only the flagged issue "
    "3) Maintain: Preserve the original functionality and code structure "
    "4) Validate: Ensure fixes use real, secure libraries and follow best practices. "
    "IMPORTANT: Return ONLY valid JSON in the exact format specified. "
    "Do not include explanations outside the JSON structure. "
    "Keep fixes minimal and focused on the specific line that needs to be changed."
)

_shared_client: Anthropic | None = None

if ANTHROPIC_API_KEY:
    try:
        _shared_client = Anthropic(api_key=ANTHROPIC_API_KEY)
    except Exception as e:
        print(f"Warning: Failed to initialize Anthropic client: {e}")


def get_llm_client(tier: UserTier, user_api_key: str = None) -> Anthropic | None:
    """Return Anthropic client for the given tier."""
    if tier == UserTier.ENTERPRISE and user_api_key:
        try:
            return Anthropic(api_key=user_api_key)
        except Exception as e:
            print(f"Warning: Failed to initialize enterprise client: {e}")
            return None
    return _shared_client


def _call_claude(client: Anthropic, user_prompt: str) -> str:
    """Send a single-turn message and return the text response."""
    message = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )
    return message.content[0].text


def _parse_json_response(raw: str) -> dict | None:
    """Strip markdown fences and parse JSON. Returns None on failure."""
    cleaned = raw.strip()
    cleaned = re.sub(r'^```json\s*', '', cleaned)
    cleaned = re.sub(r'\s*```$', '', cleaned)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None


def _build_prompt(context: dict, has_code: bool, custom_prompt: str | None, tier: UserTier) -> str:
    if custom_prompt and TierService.can_use_custom_prompts(tier):
        return custom_prompt

    file_ext = context['file_path'].split('.')[-1] if '.' in context['file_path'] else 'text'

    if has_code:
        return f"""Vulnerability Analysis Request:

**Vulnerability Type:** {context['vulnerability_type']}
**File:** {context['file_path']}
**Line:** {context['line_number']}
**Severity:** {context['severity']}
**Vulnerable Code:**
```{file_ext}
{context['vulnerable_code']}
```
**Description:** {context['description']}

Requirements:
- Provide a minimal, line-by-line fix
- Use only real, secure libraries
- Maintain original functionality
- Focus only on the flagged vulnerability

Response Format (JSON only):
{{
    "suggested_fix": "exact line replacement code",
    "confidence_score": 0.95,
    "fix_type": "line_replacement",
    "explanation": "brief security explanation",
    "required_imports": ["import statement if needed"],
    "impact": "low|medium|high"
}}

Return ONLY the JSON object, no additional text."""
    else:
        return f"""Generic Security Fix Request:

**Vulnerability Type:** {context['vulnerability_type']}
**File:** {context['file_path']}
**Line:** {context['line_number']}
**Severity:** {context['severity']}
**Description:** {context['description']}

No code snippet is available. Provide a generic secure implementation pattern.

Response Format (JSON only):
{{
    "suggested_fix": "minimal secure code example",
    "confidence_score": 0.95,
    "fix_type": "generic_fix",
    "explanation": "brief security explanation",
    "required_imports": ["import statement if needed"],
    "impact": "low|medium|high"
}}

Return ONLY the JSON object, no additional text."""


def generate_fixes(findings, tier: UserTier = UserTier.FREE, user_api_key: str = None, custom_prompt: str = None):
    """Generate structured security fixes with confidence scores."""
    client = get_llm_client(tier, user_api_key)
    suggestions = []

    if not client:
        for finding in findings:
            suggestions.append({
                "rule_id": finding['rule_id'],
                "file_path": finding['path'],
                "line_number": finding['start_line'],
                "original_code": finding.get('code', 'No code snippet available'),
                "suggested_fix": "LLM service not available. Check ANTHROPIC_API_KEY.",
                "confidence_score": 0.0,
                "fix_type": "error",
                "explanation": "LLM service unavailable",
                "required_imports": [],
                "impact": "unknown",
            })
        return suggestions

    for finding in findings:
        context = extract_context_for_fix(finding)
        has_code = bool(context['vulnerable_code'] and context['vulnerable_code'] != "Code not available")

        semgrep_confidence = None
        meta_conf = finding.get('metadata', {}).get('confidence', '').upper()
        semgrep_confidence = {'HIGH': 0.9, 'MEDIUM': 0.6, 'LOW': 0.3}.get(meta_conf)

        prompt = _build_prompt(context, has_code, custom_prompt, tier)

        try:
            raw = _call_claude(client, prompt)
            parsed = _parse_json_response(raw)

            if parsed:
                final_confidence = semgrep_confidence if semgrep_confidence is not None else parsed.get("confidence_score", 0.8)
                fix = parsed.get("suggested_fix", raw)

                if parsed.get("fix_type") == "line_replacement" and "\n" in fix:
                    fix = fix.split('\n')[0].strip()

                if not has_code:
                    fix = "**GENERIC FIX** - No code snippet in Semgrep report.\n\n" + fix

                suggestions.append({
                    "rule_id": finding['rule_id'],
                    "file_path": finding['path'],
                    "line_number": finding['start_line'],
                    "original_code": finding.get('code', 'No code snippet available'),
                    "suggested_fix": fix,
                    "confidence_score": final_confidence,
                    "fix_type": parsed.get("fix_type", "line_replacement" if has_code else "generic_fix"),
                    "explanation": parsed.get("explanation", ""),
                    "required_imports": parsed.get("required_imports", []),
                    "impact": parsed.get("impact", "medium"),
                })
            else:
                final_confidence = semgrep_confidence or 0.7
                fix = raw.split('\n')[0].strip() if '\n' in raw else raw
                if not has_code:
                    fix = "**GENERIC FIX**\n\n" + fix
                suggestions.append({
                    "rule_id": finding['rule_id'],
                    "file_path": finding['path'],
                    "line_number": finding['start_line'],
                    "original_code": finding.get('code', 'No code snippet available'),
                    "suggested_fix": fix,
                    "confidence_score": final_confidence,
                    "fix_type": "unstructured",
                    "explanation": "LLM returned unstructured response",
                    "required_imports": [],
                    "impact": "medium",
                })

        except Exception as e:
            fix = f"LLM Error: {e}"
            if not has_code:
                fix = "**GENERIC FIX**\n\n" + fix
            suggestions.append({
                "rule_id": finding['rule_id'],
                "file_path": finding['path'],
                "line_number": finding['start_line'],
                "original_code": finding.get('code', 'No code snippet available'),
                "suggested_fix": fix,
                "confidence_score": 0.0,
                "fix_type": "error",
                "explanation": f"Error: {e}",
                "required_imports": [],
                "impact": "unknown",
            })

    return suggestions
