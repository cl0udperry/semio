#!/usr/bin/env python3
"""
Semio CLI Tool
A simple command-line interface for testing Semio API connectivity and authentication.
"""

import os
import sys
import json
import requests
from typing import Dict, Any, Optional

# Configuration
DEFAULT_API_URL = "http://localhost:8000"
API_URL = os.getenv("SEMIO_API_URL", DEFAULT_API_URL)

def print_banner():
    """Print CLI banner."""
    print("Semio CLI Tool")
    print("=" * 50)

def test_connectivity() -> bool:
    """Test basic connectivity to Semio API."""
    try:
        response = requests.get(f"{API_URL}/health", timeout=10)
        if response.status_code == 200:
            print(f"Connected to Semio API at: {API_URL}")
            return True
        else:
            print(f"API returned status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Failed to connect to Semio API: {e}")
        return False

def test_cli_endpoint(api_key: str) -> bool:
    """Test the CLI-specific endpoint."""
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
            "api_key": api_key,
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
            print(f"CLI endpoint: OK")
            print(f"   Upload ID: {result.get('upload_id', 'N/A')}")
            print(f"   Vulnerabilities: {result.get('total_vulnerabilities', 0)}")
            print(f"   High Confidence Fixes: {result.get('high_confidence_fixes', 0)}")
            print(f"   Medium Confidence Fixes: {result.get('medium_confidence_fixes', 0)}")
            print(f"   Low Confidence Fixes: {result.get('low_confidence_fixes', 0)}")
            return True
        else:
            print(f"CLI endpoint: Failed (Status: {response.status_code})")
            print(f"   Response: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"CLI endpoint request failed: {e}")
        return False

def test_agentic_cli_endpoint(api_key: str) -> bool:
    """Test the CLI-specific agentic endpoint."""
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
            "api_key": api_key,
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
            print(f"Agentic CLI endpoint: OK")
            print(f"   Upload ID: {result.get('upload_id', 'N/A')}")
            print(f"   Vulnerabilities: {result.get('total_vulnerabilities', 0)}")
            
            # Check for enhanced data
            fixes = result.get('fixes', [])
            if fixes:
                fix = fixes[0]
                print(f"   Enhanced data: Yes")
                print(f"     - Validation: {fix.get('validation', {}).get('syntax_check', 'N/A')}")
                print(f"     - Context: {fix.get('context', {}).get('scope', 'N/A')}")
                print(f"     - Dependencies: {len(fix.get('dependencies', {}).get('requires_fixes', []))}")
                print(f"     - Metadata: {fix.get('metadata', {}).get('fix_category', 'N/A')}")
            else:
                print(f"   Enhanced data: No (No fixes generated)")
            
            return True
        else:
            print(f"Agentic CLI endpoint: Failed (Status: {response.status_code})")
            print(f"   Response: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"Agentic CLI endpoint request failed: {e}")
        return False

def test_semgrep_analysis_cli(api_key: str, semgrep_file: str) -> bool:
    """Test Semgrep analysis with CLI endpoint."""
    try:
        # Read Semgrep results file
        with open(semgrep_file, 'r') as f:
            semgrep_data = json.load(f)
        
        headers = {
            "Content-Type": "application/json"
        }
        
        params = {
            "api_key": api_key,
            "format": "json"
        }
        
        response = requests.post(
            f"{API_URL}/api/review-cli", 
            json=semgrep_data, 
            headers=headers,
            params=params,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"Semgrep analysis successful!")
            print(f"   Upload ID: {result['upload_id']}")
            print(f"   Total Vulnerabilities: {result['total_vulnerabilities']}")
            print(f"   High Confidence Fixes: {result['high_confidence_fixes']}")
            print(f"   Medium Confidence Fixes: {result['medium_confidence_fixes']}")
            print(f"   Low Confidence Fixes: {result['low_confidence_fixes']}")
            return True
        else:
            print(f"Semgrep analysis failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except FileNotFoundError:
        print(f"Semgrep file not found: {semgrep_file}")
        return False
    except json.JSONDecodeError:
        print(f"Invalid JSON in Semgrep file: {semgrep_file}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"Semgrep analysis request failed: {e}")
        return False

def main():
    """Main CLI function."""
    print_banner()
    
    # Test connectivity
    if not test_connectivity():
        print("\nCannot proceed without API connectivity.")
        sys.exit(1)
    
        print(f"\nCurrent Configuration:")
    print(f"   API URL: {API_URL}")
    print(f"   SEMIO_API_URL env var: {os.getenv('SEMIO_API_URL', 'Not set')}")
    
    # Check if API key is provided
    api_key = os.getenv("SEMIO_API_KEY")
    
    if api_key:
        print(f"\nUsing API key authentication:")
        print(f"   API Key: {api_key[:10]}...{api_key[-10:] if len(api_key) > 20 else '***'}")
        
        # Test CLI endpoints
        print(f"\nTesting CLI endpoints...")
        
        # Test basic CLI endpoint
        cli_success = test_cli_endpoint(api_key)
        
        # Test agentic CLI endpoint
        agentic_success = test_agentic_cli_endpoint(api_key)
        
        # Test Semgrep analysis if file provided
        semgrep_file = os.getenv("SEMGREP_FILE")
        if semgrep_file:
            print(f"\nTesting Semgrep analysis with file: {semgrep_file}")
            test_semgrep_analysis_cli(api_key, semgrep_file)
        else:
            print(f"\nTo test Semgrep analysis, set SEMGREP_FILE environment variable")
        
        if cli_success and agentic_success:
            print(f"\nCLI endpoints working! Your GitLab integration is ready.")
        else:
            print(f"\nSome CLI endpoints failed. Please check your API key.")
    else:
        print(f"\nNo API key found in environment variables.")
        print(f"   Set SEMIO_API_KEY to test CLI endpoints.")
        print(f"   Set SEMGREP_FILE to test Semgrep analysis.")
    
        print(f"\nUsage Examples:")
    print(f"   # Set environment variables:")
    print(f"   export SEMIO_API_URL='http://semio-production.eba-di323hkd.ap-southeast-1.elasticbeanstalk.com'")
    print(f"   export SEMIO_API_KEY='your-api-key-here'")
    print(f"   export SEMGREP_FILE='semgrep-results.json'")
    print(f"   ")
    print(f"   # Run CLI:")
    print(f"   python semio_cli.py")
    print(f"   ")
    print(f"   # GitLab CI/CD Variables:")
    print(f"   SEMIO_API_URL = 'http://semio-production.eba-di323hkd.ap-southeast-1.elasticbeanstalk.com'")
    print(f"   SEMIO_API_KEY = 'your-api-key-here'")

if __name__ == "__main__":
    main()
