#!/usr/bin/env python3
"""
Demo API Key Usage for Semio CLI
This script shows how to use the demo API key for testing.
"""

import os
import requests
import json

# Demo API key (hardcoded in the auth service)
DEMO_API_KEY = "demo-semio-api-key-2024-for-testing-only"

def test_demo_api_key():
    """Test the demo API key with the CLI endpoint."""
    
    # Get API URL from environment or use default
    api_url = os.getenv("SEMIO_API_URL", "http://localhost:8000")
    
    print("Semio Demo API Key Test")
    print("=" * 30)
    print(f"API URL: {api_url}")
    print(f"Demo API Key: {DEMO_API_KEY}")
    print()
    
    # Sample Semgrep data for testing
    sample_data = {
        "results": [
            {
                "check_id": "python.security.weak-crypto",
                "path": "test.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {
                    "message": "Test vulnerability",
                    "severity": "WARNING",
                    "lines": "import hashlib; hashlib.md5('test')"
                }
            }
        ]
    }
    
    try:
        # Test the CLI endpoint with demo API key
        response = requests.post(
            f"{api_url}/api/review-cli",
            json=sample_data,
            params={
                "api_key": DEMO_API_KEY,
                "format": "json"
            },
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Demo API key works!")
            print(f"   Upload ID: {result.get('upload_id', 'N/A')}")
            print(f"   Total Vulnerabilities: {result.get('total_vulnerabilities', 0)}")
            print(f"   Error Severity: {result.get('error_severity_count', 0)}")
            print(f"   Warning Severity: {result.get('warning_severity_count', 0)}")
            print(f"   Info Severity: {result.get('info_severity_count', 0)}")
            print()
            print("🔐 To use this demo key in your environment:")
            print(f"   export SEMIO_API_KEY='{DEMO_API_KEY}'")
            print()
            print("🔐 Or add to your .env file:")
            print(f"   SEMIO_API_KEY={DEMO_API_KEY}")
            print()
            print("🔐 For GitLab CI/CD, add as a variable:")
            print(f"   SEMIO_API_KEY = {DEMO_API_KEY}")
            
        else:
            print(f"❌ Demo API key test failed: {response.status_code}")
            print(f"   Response: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

def show_usage_examples():
    """Show usage examples with the demo API key."""
    
    print("\n" + "="*50)
    print("USAGE EXAMPLES")
    print("="*50)
    
    print("\n1. Using with CLI tool:")
    print("   export SEMIO_API_KEY='demo-semio-api-key-2024-for-testing-only'")
    print("   python semio_cli.py")
    
    print("\n2. Using with curl:")
    print("   curl -X POST 'http://localhost:8000/api/review-cli' \\")
    print("     -H 'Content-Type: application/json' \\")
    print("     -d @semgrep-results.json \\")
    print("     -G \\")
    print("     -d 'api_key=demo-semio-api-key-2024-for-testing-only'")
    
    print("\n3. Using with GitLab CI/CD:")
    print("   # In GitLab project variables:")
    print("   SEMIO_API_KEY = demo-semio-api-key-2024-for-testing-only")
    print("   SEMIO_API_URL = http://your-semio-instance.com")
    
    print("\n4. Using with Python requests:")
    print("   import requests")
    print("   response = requests.post(")
    print("       'http://localhost:8000/api/review-cli',")
    print("       json=semgrep_data,")
    print("       params={'api_key': 'demo-semio-api-key-2024-for-testing-only'}")
    print("   )")

if __name__ == "__main__":
    test_demo_api_key()
    show_usage_examples()
