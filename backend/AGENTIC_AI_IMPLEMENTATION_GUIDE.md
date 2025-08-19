# 🤖 Agentic AI Implementation Guide for Semio

This guide explains how to implement agentic AI fix application using Semio's enhanced endpoints.

## 🎯 **Overview**

Semio now provides enhanced endpoints that fill the gaps in your original report:
- ✅ **Fix validation data** - Syntax checks, breaking changes, dependencies
- ✅ **Dependency relationships** - Fix order, conflicts, requirements
- ✅ **Function/class context** - Scope, related functions, file structure
- ✅ **Agentic AI workflow** - Auto-apply, approval, rejection logic

## 🚀 **New Semio Endpoints**

### **1. Enhanced Report Generation**
```bash
POST /api/review-agentic
```
**Purpose:** Generate Semio reports with enhanced data for agentic AI

**Enhanced Response Structure:**
```json
{
  "fixes": [
    {
      "rule_id": "python.security.weak-crypto",
      "file_path": "src/example.py",
      "line_number": 15,
      "suggested_fix": "import bcrypt; password = bcrypt.hashpw(input_data.encode(), bcrypt.gensalt())",
      "confidence_score": 0.9,
      "fix_type": "line_replacement",
      "explanation": "Replace MD5 with bcrypt for secure password hashing",
      "required_imports": ["import bcrypt"],
      "impact": "high",
      
      // NEW: Enhanced data for agentic AI
      "validation": {
        "syntax_check": true,
        "test_coverage": "partial",
        "breaking_changes": false,
        "dependencies_affected": ["imports"],
        "backward_compatibility": true,
        "security_impact": "positive",
        "performance_impact": "minimal"
      },
      
      "context": {
        "function_name": "hash_password",
        "class_name": null,
        "scope": "function",
        "related_functions": [],
        "file_structure": "unknown"
      },
      
      "dependencies": {
        "requires_fixes": [],
        "conflicts_with": [],
        "order": 1,
        "affected_files": ["src/example.py"],
        "import_dependencies": ["import bcrypt"]
      },
      
      "metadata": {
        "fix_id": "fix_12345",
        "created_at": "2025-08-18T15:02:27.497772",
        "fix_category": "weak_crypto",
        "estimated_effort": "low",
        "risk_level": "low"
      }
    }
  ]
}
```

### **2. Agentic Fix Application**
```bash
POST /api/apply-fixes
```
**Purpose:** Apply fixes with intelligent approval workflow

**Request:**
```json
{
  "semio_report": { /* Enhanced Semio report */ },
  "auto_apply_high_confidence": true,
  "require_approval_medium": true
}
```

**Response:**
```json
{
  "message": "Processed 9 fixes",
  "applied_fixes": [
    {
      "fix_id": "fix_12345",
      "rule_id": "python.security.weak-crypto",
      "file_path": "src/example.py",
      "line_number": 15,
      "status": "applied",
      "result": {
        "status": "applied",
        "message": "Fix applied successfully",
        "original_code": "password = hashlib.md5(input_data).hexdigest()",
        "new_code": "password = bcrypt.hashpw(input_data.encode(), bcrypt.gensalt())",
        "validation_passed": true
      }
    }
  ],
  "pending_approval": [
    {
      "approval_id": "approval_67890",
      "fix_id": "fix_67890",
      "rule_id": "python.security.sql-injection",
      "file_path": "src/database.py",
      "line_number": 29,
      "confidence_score": 0.6,
      "suggested_fix": "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
      "explanation": "Use parameterized queries to prevent SQL injection",
      "impact": "high",
      "created_by": "developer",
      "created_at": "2025-08-18T15:02:27.497772",
      "status": "pending",
      "approval_url": "/approve-fix/fix_67890"
    }
  ],
  "rejected_fixes": [
    {
      "fix_id": "fix_11111",
      "rule_id": "python.security.xss",
      "file_path": "src/template.py",
      "line_number": 46,
      "status": "rejected",
      "reason": "Low confidence score"
    }
  ],
  "summary": {
    "total_fixes": 9,
    "applied": 2,
    "pending_approval": 3,
    "rejected": 4
  }
}
```

## 🔧 **Pipeline Integration Strategy**

### **Option 1: Semio-Centric (Recommended)**

**Pipeline Workflow:**
```yaml
# .gitlab-ci.yml
stages:
  - scan
  - analyze
  - apply-fixes
  - approve
  - deploy

semgrep-scan:
  stage: scan
  script:
    - semgrep ci --json --output semgrep-results.json
  artifacts:
    paths: [semgrep-results.json]

semio-analysis:
  stage: analyze
  script:
    - curl -X POST "http://semio-production.eba-di323hkd.ap-southeast-1.elasticbeanstalk.com/api/review-agentic" \
      -H "X-Semio-UI: gitlab-pipeline" \
      -H "User-Agent: Semio-GitLab-Pipeline/1.0" \
      -H "Content-Type: application/json" \
      -d @semgrep-results.json \
      -o semio-report.json
  artifacts:
    paths: [semio-report.json]

apply-fixes:
  stage: apply-fixes
  script:
    - curl -X POST "http://semio-production.eba-di323hkd.ap-southeast-1.elasticbeanstalk.com/api/apply-fixes" \
      -H "X-Semio-UI: gitlab-pipeline" \
      -H "User-Agent: Semio-GitLab-Pipeline/1.0" \
      -H "Content-Type: application/json" \
      -d @semio-report.json \
      -o fix-results.json
  artifacts:
    paths: [fix-results.json]
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

### **Option 2: Pipeline-Centric**

**Pipeline Workflow:**
```yaml
semio-analysis:
  stage: analyze
  script:
    - curl -X POST "http://semio-production.eba-di323hkd.ap-southeast-1.elasticbeanstalk.com/api/review-agentic" \
      -H "X-Semio-UI: gitlab-pipeline" \
      -H "User-Agent: Semio-GitLab-Pipeline/1.0" \
      -H "Content-Type: application/json" \
      -d @semgrep-results.json \
      -o semio-report.json
    - python apply_fixes.py semio-report.json
  artifacts:
    paths: [semio-report.json, fix-results.json]
```

**apply_fixes.py:**
```python
import json
import sys
import subprocess

def apply_fixes(semio_report_path):
    with open(semio_report_path) as f:
        report = json.load(f)
    
    fixes = report['fixes']
    
    # Categorize by confidence
    high_conf = [f for f in fixes if f['confidence_score'] >= 0.8]
    medium_conf = [f for f in fixes if 0.5 <= f['confidence_score'] < 0.8]
    low_conf = [f for f in fixes if f['confidence_score'] < 0.5]
    
    # Auto-apply high confidence fixes
    for fix in high_conf:
        apply_single_fix(fix)
    
    # Create MR for medium confidence fixes
    if medium_conf:
        create_merge_request(medium_conf)
    
    # Log low confidence fixes
    for fix in low_conf:
        print(f"Low confidence fix rejected: {fix['rule_id']}")

def apply_single_fix(fix):
    # Read file
    with open(fix['file_path'], 'r') as f:
        lines = f.readlines()
    
    # Apply fix
    line_idx = fix['line_number'] - 1
    lines[line_idx] = fix['suggested_fix'] + '\n'
    
    # Write file
    with open(fix['file_path'], 'w') as f:
        f.writelines(lines)
    
    # Git operations
    subprocess.run(['git', 'add', fix['file_path']])
    subprocess.run(['git', 'commit', '-m', f"Auto-fix: {fix['rule_id']}"])

def create_merge_request(fixes):
    # Create branch
    branch_name = f"security-fixes-{int(time.time())}"
    subprocess.run(['git', 'checkout', '-b', branch_name])
    
    # Apply fixes
    for fix in fixes:
        apply_single_fix(fix)
    
    # Push and create MR
    subprocess.run(['git', 'push', 'origin', branch_name])
    # Use GitLab API to create MR
```

## 🎯 **Implementation Steps**

### **Step 1: Test Enhanced Semio Endpoint**
```bash
# Test the enhanced endpoint
curl -X POST "http://semio-production.eba-di323hkd.ap-southeast-1.elasticbeanstalk.com/api/review-agentic" \
  -H "X-Semio-UI: gitlab-pipeline" \
  -H "User-Agent: Semio-GitLab-Pipeline/1.0" \
  -H "Content-Type: application/json" \
  -d @semgrep-results.json
```

### **Step 2: Implement Pipeline Integration**
Choose your preferred approach (Semio-centric or Pipeline-centric) and implement the workflow.

### **Step 3: Add Approval Workflow**
```python
# approval_workflow.py
def handle_approval_requests(pending_approvals):
    for approval in pending_approvals:
        if approval['confidence_score'] >= 0.7:
            # Auto-approve high-medium confidence
            approve_fix(approval)
        else:
            # Send notification to developer
            notify_developer(approval)

def approve_fix(approval):
    # Apply the fix
    apply_single_fix(approval)
    
    # Update approval status
    approval['status'] = 'approved'
    approval['approved_at'] = datetime.now().isoformat()
```

### **Step 4: Add Rollback Mechanism**
```python
def rollback_fix(fix_id):
    # Get fix history
    fix_history = get_fix_history(fix_id)
    
    # Revert the change
    with open(fix_history['file_path'], 'r') as f:
        lines = f.readlines()
    
    lines[fix_history['line_number'] - 1] = fix_history['original_code']
    
    with open(fix_history['file_path'], 'w') as f:
        f.writelines(lines)
    
    # Commit rollback
    subprocess.run(['git', 'add', fix_history['file_path']])
    subprocess.run(['git', 'commit', '-m', f"Rollback: {fix_history['rule_id']}"])
```

## 📊 **Enhanced Data Quality**

### **Before (Original Report):**
```json
{
  "fixes": [
    {
      "suggested_fix": "Use parameterized queries",
      "confidence_score": 0.3,
      "fix_type": "line_replacement"
    }
  ]
}
```

### **After (Enhanced Report):**
```json
{
  "fixes": [
    {
      "suggested_fix": "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
      "confidence_score": 0.3,
      "fix_type": "line_replacement",
      "validation": {
        "syntax_check": true,
        "breaking_changes": false,
        "dependencies_affected": []
      },
      "context": {
        "function_name": "get_user",
        "scope": "function"
      },
      "dependencies": {
        "requires_fixes": [],
        "conflicts_with": [],
        "order": 1
      },
      "metadata": {
        "fix_id": "fix_12345",
        "fix_category": "sql_injection",
        "estimated_effort": "low",
        "risk_level": "low"
      }
    }
  ]
}
```

## 🎉 **Benefits of This Approach**

1. **Centralized Intelligence** - All AI logic stays in Semio
2. **Consistent Processing** - Same reasoning across all pipelines
3. **Rich Context** - Enhanced data for better decision making
4. **Flexible Workflow** - Choose your preferred integration approach
5. **Scalable** - Other pipelines can use the same endpoints
6. **Maintainable** - One codebase to update and improve

## 🚀 **Next Steps**

1. **Deploy the enhanced Semio** with the new endpoints
2. **Test the enhanced report generation** with your existing pipeline
3. **Choose your integration approach** (Semio-centric or Pipeline-centric)
4. **Implement the approval workflow** based on your team's preferences
5. **Add monitoring and rollback capabilities** for production safety

This approach gives you a solid foundation for agentic AI fix application while maintaining flexibility for your specific workflow needs!
