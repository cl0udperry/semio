#!/usr/bin/env python3
"""
Automated Production Testing Script for Semio
Run this script to test critical functionality before production deployment
"""

import os
import sys
import json
import requests
import time
from typing import Dict, Any, List

# Configuration
API_URL = os.getenv("SEMIO_API_URL", "http://localhost:8000")
API_KEY = os.getenv("SEMIO_API_KEY", "test-api-key")
ADMIN_EMAIL = os.getenv("SEMIO_ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.getenv("SEMIO_ADMIN_PASSWORD", "admin123456")

class ProductionTester:
    def __init__(self):
        self.test_results = []
        self.failed_tests = []
        
    def log_test(self, test_name: str, success: bool, details: str = ""):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"   {details}")
        
        self.test_results.append({
            "test": test_name,
            "success": success,
            "details": details
        })
        
        if not success:
            self.failed_tests.append(test_name)
    
    def test_health_endpoint(self) -> bool:
        """Test health endpoint"""
        try:
            response = requests.get(f"{API_URL}/health", timeout=10)
            success = response.status_code == 200
            self.log_test("Health Endpoint", success, f"Status: {response.status_code}")
            return success
        except Exception as e:
            self.log_test("Health Endpoint", False, f"Error: {e}")
            return False
    
    def test_root_endpoint(self) -> bool:
        """Test root endpoint"""
        try:
            response = requests.get(f"{API_URL}/", timeout=10)
            success = response.status_code == 200
            self.log_test("Root Endpoint", success, f"Status: {response.status_code}")
            return success
        except Exception as e:
            self.log_test("Root Endpoint", False, f"Error: {e}")
            return False
    
    def test_cli_endpoint(self) -> bool:
        """Test CLI endpoint with API key"""
        try:
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
            
            params = {
                "api_key": API_KEY,
                "format": "json"
            }
            
            response = requests.post(
                f"{API_URL}/api/review-cli",
                json=sample_data,
                params=params,
                timeout=30
            )
            
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            if success:
                result = response.json()
                details += f", Upload ID: {result.get('upload_id', 'N/A')}"
            
            self.log_test("CLI Endpoint", success, details)
            return success
            
        except Exception as e:
            self.log_test("CLI Endpoint", False, f"Error: {e}")
            return False
    
    def test_agentic_cli_endpoint(self) -> bool:
        """Test agentic CLI endpoint"""
        try:
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
            
            params = {
                "api_key": API_KEY,
                "format": "json"
            }
            
            response = requests.post(
                f"{API_URL}/api/review-agentic-cli",
                json=sample_data,
                params=params,
                timeout=30
            )
            
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            if success:
                result = response.json()
                details += f", Upload ID: {result.get('upload_id', 'N/A')}"
            
            self.log_test("Agentic CLI Endpoint", success, details)
            return success
            
        except Exception as e:
            self.log_test("Agentic CLI Endpoint", False, f"Error: {e}")
            return False
    
    def test_invalid_api_key(self) -> bool:
        """Test CLI endpoint with invalid API key"""
        try:
            sample_data = {"results": []}
            params = {"api_key": "invalid-key", "format": "json"}
            
            response = requests.post(
                f"{API_URL}/api/review-cli",
                json=sample_data,
                params=params,
                timeout=10
            )
            
            success = response.status_code == 401
            self.log_test("Invalid API Key Rejection", success, f"Status: {response.status_code}")
            return success
            
        except Exception as e:
            self.log_test("Invalid API Key Rejection", False, f"Error: {e}")
            return False
    
    def test_missing_api_key(self) -> bool:
        """Test CLI endpoint without API key"""
        try:
            sample_data = {"results": []}
            
            response = requests.post(
                f"{API_URL}/api/review-cli",
                json=sample_data,
                timeout=10
            )
            
            success = response.status_code == 422  # Validation error for missing parameter
            self.log_test("Missing API Key Rejection", success, f"Status: {response.status_code}")
            return success
            
        except Exception as e:
            self.log_test("Missing API Key Rejection", False, f"Error: {e}")
            return False
    
    def test_invalid_semgrep_data(self) -> bool:
        """Test with invalid semgrep data"""
        try:
            invalid_data = {"invalid": "data"}
            params = {"api_key": API_KEY, "format": "json"}
            
            response = requests.post(
                f"{API_URL}/api/review-cli",
                json=invalid_data,
                params=params,
                timeout=10
            )
            
            success = response.status_code == 400
            self.log_test("Invalid Semgrep Data Rejection", success, f"Status: {response.status_code}")
            return success
            
        except Exception as e:
            self.log_test("Invalid Semgrep Data Rejection", False, f"Error: {e}")
            return False
    
    def test_rate_limiting(self) -> bool:
        """Test access control on public endpoint"""
        try:
            # This test verifies that the public endpoint is properly restricted
            # It should return 403 for direct API access (UI-only restriction)
            sample_data = {"results": []}
            
            # Make multiple rapid requests to test access control
            responses = []
            for i in range(5):
                try:
                    response = requests.post(
                        f"{API_URL}/api/review-public",
                        json=sample_data,
                        timeout=5
                    )
                    responses.append(response.status_code)
                except Exception:
                    responses.append("ERROR")
                time.sleep(0.1)  # Small delay between requests
            
            # Check if all requests are properly blocked (403)
            # This indicates the UI-only restriction is working
            all_blocked = all(code == 403 for code in responses if isinstance(code, int))
            self.log_test("Access Control (UI-Only)", all_blocked, f"Response codes: {responses}")
            return all_blocked
            
        except Exception as e:
            self.log_test("Access Control (UI-Only)", False, f"Error: {e}")
            return False
    
    def test_different_formats(self) -> bool:
        """Test different output formats"""
        try:
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
            
            formats = ["json", "markdown", "html"]
            success_count = 0
            
            for fmt in formats:
                try:
                    params = {"api_key": API_KEY, "format": fmt}
                    response = requests.post(
                        f"{API_URL}/api/review-cli",
                        json=sample_data,
                        params=params,
                        timeout=15
                    )
                    
                    if response.status_code == 200:
                        success_count += 1
                        
                except Exception:
                    pass
            
            success = success_count >= 2  # At least 2 formats should work
            self.log_test("Output Formats", success, f"Working formats: {success_count}/3")
            return success
            
        except Exception as e:
            self.log_test("Output Formats", False, f"Error: {e}")
            return False
    
    def test_environment_variables(self) -> bool:
        """Test required environment variables"""
        required_vars = ["SEMIO_API_URL", "SEMIO_API_KEY"]
        missing_vars = []
        
        for var in required_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        success = len(missing_vars) == 0
        details = f"Missing: {missing_vars}" if missing_vars else "All required vars set"
        self.log_test("Environment Variables", success, details)
        return success
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all production tests"""
        print("🚀 Starting Semio Production Tests")
        print("=" * 50)
        
        # Run all tests
        tests = [
            self.test_environment_variables,
            self.test_health_endpoint,
            self.test_root_endpoint,
            self.test_cli_endpoint,
            self.test_agentic_cli_endpoint,
            self.test_invalid_api_key,
            self.test_missing_api_key,
            self.test_invalid_semgrep_data,
            self.test_rate_limiting,
            self.test_different_formats,
        ]
        
        for test in tests:
            test()
        
        # Summary
        print("\n" + "=" * 50)
        print("📊 TEST SUMMARY")
        print("=" * 50)
        
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r["success"]])
        failed_tests = len(self.failed_tests)
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if self.failed_tests:
            print(f"\n❌ Failed Tests:")
            for test in self.failed_tests:
                print(f"   - {test}")
        
        # Overall result
        all_passed = failed_tests == 0
        if all_passed:
            print("\n🎉 ALL TESTS PASSED! Ready for production deployment.")
        else:
            print(f"\n⚠️  {failed_tests} test(s) failed. Please fix before production deployment.")
        
        return {
            "total": total_tests,
            "passed": passed_tests,
            "failed": failed_tests,
            "success_rate": (passed_tests/total_tests)*100,
            "all_passed": all_passed,
            "failed_tests": self.failed_tests,
            "results": self.test_results
        }

def main():
    """Main function"""
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("""
Semio Production Testing Script

Usage:
    python run_production_tests.py

Environment Variables:
    SEMIO_API_URL     - Semio API URL (default: http://localhost:8000)
    SEMIO_API_KEY     - API key for testing
    SEMIO_ADMIN_EMAIL - Admin email for testing
    SEMIO_ADMIN_PASSWORD - Admin password for testing

Examples:
    # Test against local server
    python run_production_tests.py
    
    # Test against production server
    SEMIO_API_URL=https://your-production-url.com python run_production_tests.py
        """)
        return
    
    tester = ProductionTester()
    results = tester.run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if results["all_passed"] else 1)

if __name__ == "__main__":
    main()
