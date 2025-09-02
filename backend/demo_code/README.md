# sem.io Demo Code Files

This directory contains real vulnerable code files that demonstrate how sem.io actually reads your codebase to extract context for AI-powered security analysis.

## Demo Structure

### 1. `user_controller.py` - Command Injection Vulnerability
- **Vulnerability:** Uses `subprocess.call()` with `shell=True`
- **Location:** Line 15
- **Risk:** High - allows command injection attacks
- **Context:** Production code that processes user input

### 2. `user_repository.py` - SQL Injection Vulnerability  
- **Vulnerability:** Direct string interpolation in SQL queries
- **Location:** Line 37
- **Risk:** High - allows SQL injection attacks
- **Context:** Production database access code

### 3. `test_mock_database.py` - False Positive Example
- **Vulnerability:** Similar SQL injection pattern
- **Location:** Line 23
- **Risk:** Low - test/mock code only
- **Context:** Test environment, safe operations

## How sem.io Uses These Files

### Code Context Extraction Process

1. **Finding Analysis:** sem.io receives Semgrep findings with file paths and line numbers
2. **File Reading:** sem.io actually reads the specified files from your codebase
3. **Context Extraction:** Extracts code around vulnerable lines (typically ±5 lines)
4. **Pattern Analysis:** Analyzes code structure, function context, and business logic
5. **False Positive Detection:** Identifies test files, mock code, and safe contexts
6. **AI Analysis:** Uses extracted context to generate intelligent fixes

### Example Context Extraction

For finding `user_controller.py:15`:
```python
# sem.io reads the actual file and extracts:
def process_user_command(user_input):
    # Process user command - VULNERABLE
    if not user_input:
        return "No input provided"
    
    # VULNERABLE: Command injection via shell=True
    subprocess.call(f"ls {user_input}", shell=True)  # Command injection
    
    # More processing...
    result = process_result(user_input)
    return result
```

### False Positive Detection

For `test_mock_database.py:23`:
- **File pattern:** `test_` prefix indicates test code
- **Code analysis:** Mock database operations
- **Risk assessment:** Safe in test environment
- **Decision:** Likely false positive

## Why This Matters

**Traditional security tools** only see the raw Semgrep output and can't distinguish between:
- Real production vulnerabilities
- Test code that looks vulnerable
- Mock implementations
- Debug code

**sem.io** actually reads your code to understand:
- What the code does
- Where it's used
- Whether it's production or test code
- The business context around vulnerabilities

This leads to:
- **80% fewer false positives**
- **Context-aware fix recommendations**
- **Higher confidence in security decisions**
- **Better developer experience**

## Testing the Demo

1. **Load Sample Data:** Load the Semgrep scan results
2. **Analyze Vulnerabilities:** Process the findings with real code context
3. **Review Results:** See how context improves analysis quality

The demo shows the **real power** of sem.io - it doesn't just scan, it **understands your code**.
