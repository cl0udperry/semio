#!/usr/bin/env python3
"""
Test script for GitLab integration with Semio
"""

import os
import json
import requests
from typing import Dict, Any

# Configuration
API_URL = os.getenv("SEMIO_API_URL", "http://semio-production.eba-di323hkd.ap-southeast-1.elasticbeanstalk.com")
API_KEY = os.getenv("SEMIO_API_KEY", "test-api-key")

def test_connectivity():
    """Test basic connectivity."""
    try:
        response = requests.get(f"{API_URL}/health", timeout=10)
        if response.status_code == 200:
            print(f"✅ API connectivity: OK")
            return True
        else:
            print(f"❌ API connectivity: Failed (Status: {response.status_code})")
            return False
    except Exception as e:
        print(f"❌ API connectivity: Failed ({e})")
        return False

def test_cli_endpoint():
    """Test the CLI endpoint with API key."""
    try:
        # Sample Semgrep results
        sample_data = {
            "results": [
                {
                    "check_id": "python.security.weak-crypto",
                    "path": "test.py",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {
                        "message": "Test vulnerability",
                        "severity": "WARNING"
                    }
                }
            ]
        }
        
        headers = {
            "Content-Type": "application/json"
        }
        
        params = {
            "api_key": API_KEY,
            "format": "json"
        }
        
        response = requests.post(
            f"{API_URL}/api/review-cli",
            json=sample_data,
            headers=headers,
            params=params,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ CLI endpoint: OK")
            print(f"   Upload ID: {result.get('upload_id', 'N/A')}")
            print(f"   Vulnerabilities: {result.get('total_vulnerabilities', 0)}")
            return True
        else:
            print(f"❌ CLI endpoint: Failed (Status: {response.status_code})")
            print(f"   Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ CLI endpoint: Failed ({e})")
        return False

def test_agentic_cli_endpoint():
    """Test the agentic CLI endpoint with API key."""
    try:
        # Sample Semgrep results
        sample_data = {
            "results": [
                {
                    "check_id": "python.security.weak-crypto",
                    "path": "test.py",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {
                        "message": "Test vulnerability",
                        "severity": "WARNING"
                    }
                }
            ]
        }
        
        headers = {
            "Content-Type": "application/json"
        }
        
        params = {
            "api_key": API_KEY,
            "format": "json"
        }
        
        response = requests.post(
            f"{API_URL}/api/review-agentic-cli",
            json=sample_data,
            headers=headers,
            params=params,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Agentic CLI endpoint: OK")
            print(f"   Upload ID: {result.get('upload_id', 'N/A')}")
            print(f"   Vulnerabilities: {result.get('total_vulnerabilities', 0)}")
            
            # Check for enhanced data
            fixes = result.get('fixes', [])
            if fixes:
                fix = fixes[0]
                print(f"   Enhanced data: ✅")
                print(f"     - Validation: {fix.get('validation', {}).get('syntax_check', 'N/A')}")
                print(f"     - Context: {fix.get('context', {}).get('scope', 'N/A')}")
                print(f"     - Dependencies: {len(fix.get('dependencies', {}).get('requires_fixes', []))}")
                print(f"     - Metadata: {fix.get('metadata', {}).get('fix_category', 'N/A')}")
            else:
                print(f"   Enhanced data: ❌ (No fixes generated)")
            
            return True
        else:
            print(f"❌ Agentic CLI endpoint: Failed (Status: {response.status_code})")
            print(f"   Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Agentic CLI endpoint: Failed ({e})")
        return False

def main():
    """Main test function."""
    print("🔒 Semio GitLab Integration Test")
    print("=" * 50)
    
    print(f"\n📋 Configuration:")
    print(f"   API URL: {API_URL}")
    print(f"   API Key: {API_KEY[:10]}...{API_KEY[-10:] if len(API_KEY) > 20 else '***'}")
    
    # Run tests
    tests = [
        ("API Connectivity", test_connectivity),
        ("CLI Endpoint", test_cli_endpoint),
        ("Agentic CLI Endpoint", test_agentic_cli_endpoint)
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n🧪 Testing {test_name}...")
        result = test_func()
        results.append((test_name, result))
    
    # Summary
    print(f"\n📊 Test Summary:")
    print("=" * 30)
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {test_name}: {status}")
    
    print(f"\n   Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print(f"\n🎉 All tests passed! Your GitLab integration is ready.")
        print(f"\n📖 GitLab CI/CD Configuration:")
        print(f"   SEMIO_API_URL = '{API_URL}'")
        print(f"   SEMIO_API_KEY = 'your-actual-api-key'")
    else:
        print(f"\n⚠️  Some tests failed. Please check your configuration.")

if __name__ == "__main__":
    main()
