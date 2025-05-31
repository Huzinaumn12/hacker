
import requests
import time
import sys
from datetime import datetime

class VulnScannerAPITester:
    def __init__(self, base_url="https://58099319-9255-4784-abd0-7aca43e40fef.preview.emergentagent.com"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.scan_id = None

    def run_test(self, name, method, endpoint, expected_status, data=None):
        """Run a single API test"""
        url = f"{self.base_url}{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                return success, response.json()
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                print(f"Response: {response.text}")
                return False, {}

        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False, {}

    def test_root_endpoint(self):
        """Test the root API endpoint"""
        return self.run_test(
            "Root API Endpoint",
            "GET",
            "/api/",
            200
        )

    def test_tools_status(self):
        """Test the tools status endpoint"""
        success, response = self.run_test(
            "Tools Status Endpoint",
            "GET",
            "/api/tools-status",
            200
        )
        
        if success:
            print(f"Available tools: {response['available_tools']} of {response['total_tools']}")
            for tool, available in response['tools'].items():
                status = "✅" if available else "❌"
                print(f"  {status} {tool}")
        
        return success, response

    def test_start_scan(self, target="scanme.nmap.org"):
        """Test starting a vulnerability scan"""
        success, response = self.run_test(
            "Start Scan Endpoint",
            "POST",
            "/api/scan",
            200,
            data={"url": target, "scan_type": "comprehensive"}
        )
        
        if success and 'scan_id' in response:
            self.scan_id = response['scan_id']
            print(f"Scan started with ID: {self.scan_id}")
        
        return success, response

    def test_get_scan_status(self):
        """Test getting scan status"""
        if not self.scan_id:
            print("❌ No scan ID available to check status")
            return False, {}
        
        return self.run_test(
            "Get Scan Status Endpoint",
            "GET",
            f"/api/scan/{self.scan_id}",
            200
        )

    def test_list_scans(self):
        """Test listing all scans"""
        return self.run_test(
            "List Scans Endpoint",
            "GET",
            "/api/scans",
            200
        )

    def test_delete_scan(self):
        """Test deleting a scan"""
        if not self.scan_id:
            print("❌ No scan ID available to delete")
            return False, {}
        
        return self.run_test(
            "Delete Scan Endpoint",
            "DELETE",
            f"/api/scan/{self.scan_id}",
            200
        )

    def wait_for_scan_completion(self, timeout=180):
        """Wait for scan to complete with timeout"""
        if not self.scan_id:
            print("❌ No scan ID available to monitor")
            return False, {}
        
        print(f"\n⏳ Waiting for scan to complete (timeout: {timeout}s)...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            success, response = self.run_test(
                "Check Scan Progress",
                "GET",
                f"/api/scan/{self.scan_id}",
                200
            )
            
            if not success:
                return False, {}
            
            progress = response.get('progress', 0)
            status = response.get('status', '')
            
            print(f"  Progress: {progress}% - Status: {status}")
            
            if status == 'completed':
                print("✅ Scan completed successfully!")
                return True, response
            elif status == 'failed':
                print(f"❌ Scan failed: {response.get('error', 'Unknown error')}")
                return False, response
            
            # Wait before checking again
            time.sleep(5)
        
        print("❌ Scan timed out")
        return False, {}

def main():
    # Setup
    tester = VulnScannerAPITester()
    
    # Run tests
    print("🔰 Starting VulnScanner API Tests 🔰")
    print(f"Base URL: {tester.base_url}")
    print("=" * 50)
    
    # Test root endpoint
    tester.test_root_endpoint()
    
    # Test tools status
    tester.test_tools_status()
    
    # Test list scans (before starting a new one)
    tester.test_list_scans()
    
    # Start a scan
    scan_success, _ = tester.test_start_scan()
    if not scan_success:
        print("❌ Failed to start scan, stopping tests")
        return 1
    
    # Wait for scan to complete (with timeout)
    completion_success, scan_results = tester.wait_for_scan_completion(timeout=120)
    
    if completion_success:
        # Print scan results summary
        if 'summary' in scan_results:
            print("\n📊 Scan Results Summary:")
            print(f"  Total vulnerabilities: {scan_results['summary']['total_vulnerabilities']}")
            print("  Severity breakdown:")
            for severity, count in scan_results['summary']['severity_breakdown'].items():
                print(f"    {severity}: {count}")
        
        # Print some vulnerabilities if found
        if 'vulnerabilities' in scan_results and scan_results['vulnerabilities']:
            print("\n🔍 Sample Vulnerabilities Found:")
            for i, vuln in enumerate(scan_results['vulnerabilities'][:3]):  # Show first 3
                print(f"  {i+1}. [{vuln.get('severity', 'Unknown')}] {vuln.get('description', 'No description')}")
            
            if len(scan_results['vulnerabilities']) > 3:
                print(f"  ... and {len(scan_results['vulnerabilities']) - 3} more")
    
    # Test delete scan
    tester.test_delete_scan()
    
    # Print results
    print("\n" + "=" * 50)
    print(f"📊 Tests passed: {tester.tests_passed}/{tester.tests_run}")
    print("=" * 50)
    
    return 0 if tester.tests_passed == tester.tests_run else 1

if __name__ == "__main__":
    sys.exit(main())
      