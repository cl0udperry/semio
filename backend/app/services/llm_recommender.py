import os
import json
from openai import OpenAI
from dotenv import load_dotenv
import httpx
from .semgrep_parser import extract_context_for_fix
from ..models.user import UserTier
from .tier_service import TierService

load_dotenv()

# Shared API key for free/pro users
shared_api_key = os.getenv("GOOGLE_API_KEY")
system_prompt = os.getenv("SECURE_REVIEW_SYSTEM_PROMPT", "You are a security code expert specializing in automated vulnerability remediation. Your role is to: 1) Analyze: Identify the specific security vulnerability in the provided code 2) Fix: Provide minimal, production-ready code changes that address only the flagged issue 3) Maintain: Preserve the original functionality and code structure 4) Validate: Ensure fixes use real, secure libraries and follow best practices. IMPORTANT: Return ONLY valid JSON in the exact format specified. Do not include explanations outside the JSON structure. Keep fixes minimal and focused on the specific line that needs to be changed.")

user_template = os.getenv("SECURE_REVIEW_USER_TEMPLATE", "Vulnerability Analysis Request: Vulnerability Type: {vulnerability_type} File: {file_path} Line: {line_number} Severity: {severity} Vulnerable Code: {vulnerable_code} Description: {description} Requirements: - Provide a minimal, line-by-line fix - Use only real, secure libraries - Maintain original functionality - Focus only on the flagged vulnerability Response Format (JSON only): Return ONLY a JSON object with: suggested_fix, confidence_score, fix_type, explanation, required_imports, impact")

httpx_client = httpx.Client(verify=False, timeout=60.0)

# Initialize shared gemini client for free/pro users
shared_gemini = None
if shared_api_key:
    try:
        shared_gemini = OpenAI(api_key=shared_api_key, base_url="https://generativelanguage.googleapis.com/v1beta/openai/", http_client=httpx_client)
    except Exception as e:
        print(f"Warning: Failed to initialize shared Gemini client: {e}")
        shared_gemini = None

def get_llm_client(tier: UserTier, user_api_key: str = None):
    """Get appropriate LLM client based on user tier."""
    if tier == UserTier.ENTERPRISE and user_api_key:
        # Enterprise users use their own API key
        try:
            return OpenAI(api_key=user_api_key, http_client=httpx_client)
        except Exception as e:
            print(f"Warning: Failed to initialize enterprise LLM client: {e}")
            return None
    else:
        # Free and Pro users use shared client
        return shared_gemini

def generate_fixes(findings, tier: UserTier = UserTier.FREE, user_api_key: str = None, custom_prompt: str = None):
    """
    Generate structured security fixes with confidence scores.
    Returns minimal, line-by-line fixes when possible.
    Supports tier-based features like custom prompts.
    """
    suggestions = []
    
    # Get appropriate LLM client
    llm_client = get_llm_client(tier, user_api_key)
    
    # Check if LLM client is available
    if not llm_client:
        for finding in findings:
            suggestions.append({
                "rule_id": finding['rule_id'],
                "file_path": finding['path'],
                "line_number": finding['start_line'],
                "original_code": finding.get('code', 'No code snippet available'),
                "suggested_fix": "LLM service not available. Please check your API key configuration.",
                "confidence_score": 0.0,
                "fix_type": "error",
                "explanation": "LLM service unavailable",
                "required_imports": [],
                "impact": "unknown"
            })
        return suggestions
    
    for finding in findings:
        # Build enhanced prompt with more context
        context = extract_context_for_fix(finding)
        
        # Check if code snippet is available
        has_code_snippet = context['vulnerable_code'] and context['vulnerable_code'] != "Code not available"
        
        # Get Semgrep confidence if available
        semgrep_confidence = None
        if 'metadata' in finding and 'confidence' in finding['metadata']:
            confidence_str = finding['metadata']['confidence'].upper()
            if confidence_str == 'HIGH':
                semgrep_confidence = 0.9
            elif confidence_str == 'MEDIUM':
                semgrep_confidence = 0.6
            elif confidence_str == 'LOW':
                semgrep_confidence = 0.3
        
        # Use custom prompt if available and tier allows it
        if custom_prompt and TierService.can_use_custom_prompts(tier):
            base_prompt = custom_prompt
        else:
            # Determine language from file extension
            file_ext = context['file_path'].split('.')[-1] if '.' in context['file_path'] else 'text'
            
            if has_code_snippet:
                base_prompt = f"""
 Vulnerability Analysis Request:
 
 **Vulnerability Type:** {context['vulnerability_type']}
 **File:** {context['file_path']}
 **Line:** {context['line_number']}
 **Severity:** {context['severity']}
 **Vulnerable Code:**
 ```{file_ext}
 {context['vulnerable_code']}
 ```
 **Description:** {context['description']}
 
 **Requirements:**
 - Provide a minimal, line-by-line fix
 - Use only real, secure libraries
 - Maintain original functionality
 - Focus only on the flagged vulnerability
 - Return ONLY the exact line replacement, not a complex structure
 
 **Response Format (JSON only):**
 ```json
 {{
     "suggested_fix": "exact line replacement code",
     "confidence_score": 0.95,
     "fix_type": "line_replacement",
     "explanation": "brief security explanation",
     "required_imports": ["import statement if needed"],
     "impact": "low|medium|high"
 }}
 ```
 
 Return ONLY the JSON object, no additional text.
 """
            else:
                base_prompt = f"""
Generic Security Fix Request:

**Vulnerability Type:** {context['vulnerability_type']}
**File:** {context['file_path']}
**Line:** {context['line_number']}
**Severity:** {context['severity']}
**Description:** {context['description']}

**Note:** No code snippet is available from the Semgrep report. Provide a generic fix based on the vulnerability type and context.

**Requirements:**
- Provide a generic, secure implementation pattern
- Use only real, secure libraries
- Focus on the specific vulnerability type
- Include best practices for this type of issue
- Keep the fix minimal and focused

**Response Format (JSON only):**
```json
{{
    "suggested_fix": "minimal secure code example",
    "confidence_score": 0.95,
    "fix_type": "generic_fix",
    "explanation": "brief security explanation",
    "required_imports": ["import statement if needed"],
    "impact": "low|medium|high"
}}
```

Return ONLY the JSON object, no additional text.
"""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": base_prompt}
        ]
        
        try: 
            response = llm_client.chat.completions.create(model="gemini-2.0-flash", messages=messages)
            answer = response.choices[0].message.content
            
            # Try to parse structured response
            try:
                import json
                import re
                
                # Clean the response - remove markdown code blocks if present
                cleaned_answer = answer.strip()
                if cleaned_answer.startswith('```json'):
                    cleaned_answer = re.sub(r'^```json\s*', '', cleaned_answer)
                if cleaned_answer.endswith('```'):
                    cleaned_answer = re.sub(r'\s*```$', '', cleaned_answer)
                
                structured_fix = json.loads(cleaned_answer)
                # Use Semgrep confidence if available, otherwise use LLM confidence
                final_confidence = semgrep_confidence if semgrep_confidence is not None else structured_fix.get("confidence_score", 0.8)
                
                # Add disclaimer for generic fixes
                suggested_fix = structured_fix.get("suggested_fix", answer)
                
                # Clean up the suggested fix - take only the first line if it's a line replacement
                if structured_fix.get("fix_type") == "line_replacement" and "\n" in suggested_fix:
                    suggested_fix = suggested_fix.split('\n')[0].strip()
                
                if not has_code_snippet:
                    disclaimer = "**GENERIC FIX SUGGESTION** - No vulnerable code was provided in the Semgrep report. This is a general security pattern for this type of vulnerability.\n\n"
                    suggested_fix = disclaimer + suggested_fix
                
                suggestions.append({
                    "rule_id": finding['rule_id'],
                    "file_path": finding['path'],
                    "line_number": finding['start_line'],
                    "original_code": finding.get('code', 'No code snippet available'),
                    "suggested_fix": suggested_fix,
                    "confidence_score": final_confidence,
                    "fix_type": structured_fix.get("fix_type", "line_replacement" if has_code_snippet else "generic_fix"),
                    "explanation": structured_fix.get("explanation", ""),
                    "required_imports": structured_fix.get("required_imports", []),
                    "impact": structured_fix.get("impact", "medium")
                })
            except json.JSONDecodeError:
                # Fallback to unstructured response
                final_confidence = semgrep_confidence if semgrep_confidence is not None else 0.7
                
                # Add disclaimer for generic fixes
                suggested_fix = answer
                
                # Clean up the suggested fix - take only the first line if it's a line replacement
                if "\n" in suggested_fix:
                    suggested_fix = suggested_fix.split('\n')[0].strip()
                
                if not has_code_snippet:
                    disclaimer = "**GENERIC FIX SUGGESTION** - No vulnerable code was provided in the Semgrep report. This is a general security pattern for this type of vulnerability.\n\n"
                    suggested_fix = disclaimer + answer
                
                suggestions.append({
                    "rule_id": finding['rule_id'],
                    "file_path": finding['path'],
                    "line_number": finding['start_line'],
                    "original_code": finding.get('code', 'No code snippet available'),
                    "suggested_fix": suggested_fix,
                    "confidence_score": final_confidence,
                    "fix_type": "unstructured" if has_code_snippet else "generic_fix",
                    "explanation": "LLM provided unstructured fix",
                    "required_imports": [],
                    "impact": "medium"
                })
                
        except Exception as e:
            # Add disclaimer for generic fixes even in error cases
            suggested_fix = f"LLM Error: {e}"
            if not has_code_snippet:
                disclaimer = "**GENERIC FIX SUGGESTION** - No vulnerable code was provided in the Semgrep report. This is a general security pattern for this type of vulnerability.\n\n"
                suggested_fix = disclaimer + f"LLM Error: {e}"
            
            suggestions.append({
                "rule_id": finding['rule_id'],
                "file_path": finding['path'],
                "line_number": finding['start_line'],
                "original_code": finding.get('code', 'No code snippet available'),
                "suggested_fix": suggested_fix,
                "confidence_score": 0.0,
                "fix_type": "error",
                "explanation": f"Error generating fix: {e}",
                "required_imports": [],
                "impact": "unknown"
            })
    
    return suggestions