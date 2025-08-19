#!/usr/bin/env python3
"""
Test script to demonstrate differences between /review-cli and /review-agentic-cli endpoints
"""

import json
import requests
import os

# Configuration
API_URL = "http://localhost:8000"
API_KEY = "0af351ad031c16c2e6e67bafe39c8dfa73d44e812d5f8213b0b6fff163d2fd83"

def test_endpoint_differences():
    """Test and compare the differences between review-cli and review-agentic-cli endpoints"""
    
    # Load the test data
    with open("test_semgrep_data.json", "r") as f:
        semgrep_data = json.load(f)
    
    print("🔍 Comparing /review-cli vs /review-agentic-cli Endpoints")
    print("=" * 60)
    
    # Test regular CLI review endpoint
    print("\n📤 Testing /api/review-cli endpoint...")
    try:
        response = requests.post(
            f"{API_URL}/api/review-cli",
            params={
                "api_key": API_KEY,
                "format": "json"
            },
            json=semgrep_data,
            timeout=30
        )
        
        if response.status_code == 200:
            regular_result = response.json()
            print("✅ Regular CLI review endpoint successful")
            
            # Show regular fix structure
            if regular_result.get('fixes'):
                regular_fix = regular_result['fixes'][0]
                print(f"\n📋 REGULAR CLI FIX STRUCTURE:")
                print(f"  - Rule ID: {regular_fix.get('rule_id')}")
                print(f"  - File: {regular_fix.get('file_path')}")
                print(f"  - Line: {regular_fix.get('line_number')}")
                print(f"  - Confidence: {regular_fix.get('confidence_score')}")
                print(f"  - Fix Type: {regular_fix.get('fix_type')}")
                print(f"  - Impact: {regular_fix.get('impact')}")
                print(f"  - Suggested Fix: {regular_fix.get('suggested_fix')}")
                print(f"  - Explanation: {regular_fix.get('explanation', 'N/A')[:100]}...")
                
                # Show what fields are missing in regular endpoint
                missing_fields = []
                for field in ['validation', 'context', 'dependencies', 'metadata']:
                    if field not in regular_fix:
                        missing_fields.append(field)
                
                print(f"  - Missing fields: {missing_fields}")
        else:
            print(f"❌ Regular CLI review failed: {response.status_code}")
            print(f"Response: {response.text}")
            return
            
    except Exception as e:
        print(f"❌ Error testing regular CLI review: {e}")
        return
    
    # Test agentic CLI review endpoint
    print("\n🤖 Testing /api/review-agentic-cli endpoint...")
    try:
        response = requests.post(
            f"{API_URL}/api/review-agentic-cli",
            params={
                "api_key": API_KEY,
                "format": "json"
            },
            json=semgrep_data,
            timeout=60  # Agentic takes longer
        )
        
        if response.status_code == 200:
            agentic_result = response.json()
            print("✅ Agentic CLI review endpoint successful")
            
            # Show agentic fix structure
            if agentic_result.get('fixes'):
                agentic_fix = agentic_result['fixes'][0]
                print(f"\n🤖 AGENTIC CLI FIX STRUCTURE:")
                print(f"  - Rule ID: {agentic_fix.get('rule_id')}")
                print(f"  - File: {agentic_fix.get('file_path')}")
                print(f"  - Line: {agentic_fix.get('line_number')}")
                print(f"  - Confidence: {agentic_fix.get('confidence_score')}")
                print(f"  - Fix Type: {agentic_fix.get('fix_type')}")
                print(f"  - Impact: {agentic_fix.get('impact')}")
                print(f"  - Suggested Fix: {agentic_fix.get('suggested_fix')}")
                print(f"  - Explanation: {agentic_fix.get('explanation', 'N/A')[:100]}...")
                
                # Show enhanced fields
                print(f"\n🔧 ENHANCED FIELDS:")
                
                # Validation data
                validation = agentic_fix.get('validation', {})
                print(f"  📊 VALIDATION:")
                print(f"    - Syntax Check: {validation.get('syntax_check')}")
                print(f"    - Test Coverage: {validation.get('test_coverage')}")
                print(f"    - Breaking Changes: {validation.get('breaking_changes')}")
                print(f"    - Security Impact: {validation.get('security_impact')}")
                print(f"    - Performance Impact: {validation.get('performance_impact')}")
                
                # Context data
                context = agentic_fix.get('context', {})
                print(f"  📍 CONTEXT:")
                print(f"    - Function: {context.get('function_name')}")
                print(f"    - Class: {context.get('class_name')}")
                print(f"    - Scope: {context.get('scope')}")
                
                # Dependencies
                dependencies = agentic_fix.get('dependencies', {})
                print(f"  🔗 DEPENDENCIES:")
                print(f"    - Requires Fixes: {dependencies.get('requires_fixes')}")
                print(f"    - Conflicts With: {dependencies.get('conflicts_with')}")
                print(f"    - Order: {dependencies.get('order')}")
                print(f"    - Affected Files: {dependencies.get('affected_files')}")
                
                # Metadata
                metadata = agentic_fix.get('metadata', {})
                print(f"  📋 METADATA:")
                print(f"    - Fix ID: {metadata.get('fix_id')}")
                print(f"    - Category: {metadata.get('fix_category')}")
                print(f"    - Estimated Effort: {metadata.get('estimated_effort')}")
                print(f"    - Risk Level: {metadata.get('risk_level')}")
                
        else:
            print(f"❌ Agentic CLI review failed: {response.status_code}")
            print(f"Response: {response.text}")
            return
            
    except Exception as e:
        print(f"❌ Error testing agentic CLI review: {e}")
        return
    
    # Compare the results
    print(f"\n📊 COMPARISON SUMMARY:")
    print("=" * 60)
    
    regular_fixes = regular_result.get('fixes', [])
    agentic_fixes = agentic_result.get('fixes', [])
    
    print(f"  Regular CLI Endpoint Fixes: {len(regular_fixes)}")
    print(f"  Agentic CLI Endpoint Fixes: {len(agentic_fixes)}")
    
    if regular_fixes and agentic_fixes:
        regular_fix = regular_fixes[0]
        agentic_fix = agentic_fixes[0]
        
        print(f"\n🔍 KEY DIFFERENCES:")
        print(f"  - Regular fix has {len(regular_fix)} fields")
        print(f"  - Agentic fix has {len(agentic_fix)} fields")
        
        # Show additional fields in agentic
        regular_fields = set(regular_fix.keys())
        agentic_fields = set(agentic_fix.keys())
        additional_fields = agentic_fields - regular_fields
        
        print(f"  - Additional fields in agentic: {list(additional_fields)}")
        
        print(f"\n💡 USE CASES:")
        print(f"  📋 Regular /review-cli:")
        print(f"    - Quick security analysis")
        print(f"    - Basic fix suggestions")
        print(f"    - Standard reporting")
        print(f"    - Lower processing time")
        print(f"    - CI/CD integration")
        
        print(f"  🤖 Agentic /review-agentic-cli:")
        print(f"    - Automated fix application")
        print(f"    - Dependency analysis")
        print(f"    - Risk assessment")
        print(f"    - Context-aware fixes")
        print(f"    - Enhanced validation")
        print(f"    - Advanced CI/CD workflows")

if __name__ == "__main__":
    test_endpoint_differences()
