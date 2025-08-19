#!/usr/bin/env python3
"""
Test Semio API with real Semgrep data
"""

import json
import requests
import os

# Configuration
API_URL = "http://localhost:8000"
API_KEY = "0af351ad031c16c2e6e67bafe39c8dfa73d44e812d5f8213b0b6fff163d2fd83"

def test_semio_with_real_data():
    """Test Semio API with real Semgrep vulnerability data"""
    
    # Load the test data
    with open("test_semgrep_data.json", "r") as f:
        semgrep_data = json.load(f)
    
    print("🔍 Testing Semio with Real Semgrep Data")
    print("=" * 50)
    
    # Test CLI endpoint
    print("📤 Sending data to Semio CLI endpoint...")
    
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
        
        print(f"✅ Response Status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            
            print("\n📊 SEMIO ANALYSIS RESULTS")
            print("=" * 50)
            print(f"Upload ID: {result.get('upload_id', 'N/A')}")
            print(f"Timestamp: {result.get('timestamp', 'N/A')}")
            print(f"Total Vulnerabilities: {result.get('total_vulnerabilities', 0)}")
            print(f"High Confidence Fixes: {result.get('high_confidence_fixes', 0)}")
            print(f"Medium Confidence Fixes: {result.get('medium_confidence_fixes', 0)}")
            print(f"Low Confidence Fixes: {result.get('low_confidence_fixes', 0)}")
            
            # Show findings
            findings = result.get('findings', [])
            print(f"\n🔍 FINDINGS ({len(findings)} found):")
            for i, finding in enumerate(findings, 1):
                print(f"\n  {i}. Rule: {finding.get('rule_id', 'N/A')}")
                print(f"     File: {finding.get('path', 'N/A')}")
                print(f"     Lines: {finding.get('start_line', 'N/A')}-{finding.get('end_line', 'N/A')}")
                print(f"     Message: {finding.get('message', 'N/A')[:100]}...")
                print(f"     Severity: {finding.get('severity', 'N/A')}")
            
            # Show fixes
            fixes = result.get('fixes', [])
            print(f"\n🔧 FIXES ({len(fixes)} suggested):")
            for i, fix in enumerate(fixes, 1):
                print(f"\n  {i}. File: {fix.get('file_path', 'N/A')}")
                print(f"     Line: {fix.get('line_number', 'N/A')}")
                print(f"     Confidence: {fix.get('confidence_score', 'N/A')}")
                print(f"     Fix Type: {fix.get('fix_type', 'N/A')}")
                print(f"     Impact: {fix.get('impact', 'N/A')}")
                print(f"     Suggested Fix: {fix.get('suggested_fix', 'N/A')}")
                print(f"     Explanation: {fix.get('explanation', 'N/A')[:100]}...")
            
            # Show summary
            summary = result.get('summary', {})
            print(f"\n📈 SUMMARY:")
            print(f"  Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
            print(f"  High Confidence Fixes: {summary.get('high_confidence_fixes', 0)}")
            print(f"  Medium Confidence Fixes: {summary.get('medium_confidence_fixes', 0)}")
            print(f"  Low Confidence Fixes: {summary.get('low_confidence_fixes', 0)}")
            
            fix_types = summary.get('fix_types', {})
            if fix_types:
                print(f"  Fix Types: {fix_types}")
            
            severity_dist = summary.get('severity_distribution', {})
            if severity_dist:
                print(f"  Severity Distribution: {severity_dist}")
            
        else:
            print(f"❌ Error: {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"❌ Error testing Semio API: {e}")

def test_agentic_cli():
    """Test the agentic CLI endpoint"""
    
    # Load the test data
    with open("test_semgrep_data.json", "r") as f:
        semgrep_data = json.load(f)
    
    print("\n🤖 Testing Semio Agentic CLI Endpoint")
    print("=" * 50)
    
    try:
        response = requests.post(
            f"{API_URL}/api/review-agentic-cli",
            params={
                "api_key": API_KEY,
                "format": "json"
            },
            json=semgrep_data,
            timeout=60  # Agentic endpoint might take longer
        )
        
        print(f"✅ Response Status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            
            print(f"\n🤖 AGENTIC ANALYSIS RESULTS")
            print("=" * 50)
            print(f"Upload ID: {result.get('upload_id', 'N/A')}")
            print(f"Timestamp: {result.get('timestamp', 'N/A')}")
            print(f"Total Vulnerabilities: {result.get('total_vulnerabilities', 0)}")
            print(f"High Confidence Fixes: {result.get('high_confidence_fixes', 0)}")
            print(f"Medium Confidence Fixes: {result.get('medium_confidence_fixes', 0)}")
            print(f"Low Confidence Fixes: {result.get('low_confidence_fixes', 0)}")
            
            # Show findings
            findings = result.get('findings', [])
            print(f"\n🔍 FINDINGS ({len(findings)} found):")
            for i, finding in enumerate(findings, 1):
                print(f"\n  {i}. Rule: {finding.get('rule_id', 'N/A')}")
                print(f"     File: {finding.get('path', 'N/A')}")
                print(f"     Lines: {finding.get('start_line', 'N/A')}-{finding.get('end_line', 'N/A')}")
                print(f"     Message: {finding.get('message', 'N/A')[:100]}...")
                print(f"     Severity: {finding.get('severity', 'N/A')}")
            
            # Show fixes
            fixes = result.get('fixes', [])
            print(f"\n🔧 FIXES ({len(fixes)} suggested):")
            for i, fix in enumerate(fixes, 1):
                print(f"\n  {i}. File: {fix.get('file_path', 'N/A')}")
                print(f"     Line: {fix.get('line_number', 'N/A')}")
                print(f"     Confidence: {fix.get('confidence_score', 'N/A')}")
                print(f"     Fix Type: {fix.get('fix_type', 'N/A')}")
                print(f"     Impact: {fix.get('impact', 'N/A')}")
                print(f"     Suggested Fix: {fix.get('suggested_fix', 'N/A')}")
                print(f"     Explanation: {fix.get('explanation', 'N/A')[:100]}...")
            
        else:
            print(f"❌ Error: {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"❌ Error testing Agentic CLI API: {e}")

def test_output_formats():
    """Test different output formats"""
    
    # Load the test data
    with open("test_semgrep_data.json", "r") as f:
        semgrep_data = json.load(f)
    
    print("\n📄 Testing Different Output Formats")
    print("=" * 50)
    
    formats = ["json", "markdown", "html"]
    
    for fmt in formats:
        print(f"\n📤 Testing {fmt.upper()} format...")
        
        try:
            response = requests.post(
                f"{API_URL}/api/review-cli",
                params={
                    "api_key": API_KEY,
                    "format": fmt
                },
                json=semgrep_data,
                timeout=30
            )
            
            print(f"✅ {fmt.upper()} Response Status: {response.status_code}")
            
            if response.status_code == 200:
                if fmt == "json":
                    result = response.json()
                    print(f"   Upload ID: {result.get('upload_id', 'N/A')}")
                    print(f"   Total Vulnerabilities: {result.get('total_vulnerabilities', 0)}")
                    print(f"   Fixes Suggested: {len(result.get('fixes', []))}")
                else:
                    # For markdown and HTML, show first few lines
                    content = response.text
                    print(f"   Content Length: {len(content)} characters")
                    print(f"   Preview: {content[:200]}...")
                    
                    # Save to file for inspection
                    filename = f"semio_output_{fmt}.{fmt}"
                    with open(filename, "w", encoding="utf-8") as f:
                        f.write(content)
                    print(f"   Saved to: {filename}")
            else:
                print(f"❌ Error: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Error testing {fmt} format: {e}")

if __name__ == "__main__":
    test_semio_with_real_data()
    test_agentic_cli()
    test_output_formats()
