
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
        self.vuln_index = None

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
            
            # Verify all 8 tools are available
            expected_tools = ['nmap', 'nikto', 'dirb', 'sqlmap', 'whatweb', 'subfinder', 'gobuster', 'sslscan']
            all_tools_available = all(response['tools'].get(tool, False) for tool in expected_tools)
            if all_tools_available:
                print("✅ All 8 security tools are available")
            else:
                print("❌ Not all security tools are available")
                missing_tools = [tool for tool in expected_tools if not response['tools'].get(tool, False)]
                print(f"  Missing tools: {', '.join(missing_tools)}")
        
        return success, response

    def test_start_scan(self, target="scanme.nmap.org", include_subdomains=True):
        """Test starting a vulnerability scan"""
        success, response = self.run_test(
            "Start Scan Endpoint",
            "POST",
            "/api/scan",
            200,
            data={
                "url": target, 
                "scan_type": "comprehensive", 
                "include_subdomains": include_subdomains
            }
        )
        
        if success and 'scan_id' in response:
            self.scan_id = response['scan_id']
            print(f"Scan started with ID: {self.scan_id}")
            print(f"Subdomain enumeration enabled: {include_subdomains}")
        
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

    def test_exploitation_guidance(self):
        """Test exploitation guidance endpoint"""
        if not self.scan_id or self.vuln_index is None:
            print("❌ No scan ID or vulnerability index available for exploitation guidance")
            return False, {}
        
        success, response = self.run_test(
            "Exploitation Guidance Endpoint",
            "GET",
            f"/api/scan/{self.scan_id}/exploitation/{self.vuln_index}",
            200
        )
        
        if success:
            print("\n🎯 Exploitation Guidance Details:")
            
            # Check for exploitation data structure
            if 'exploitation' in response:
                exploit_data = response['exploitation']
                print(f"  Title: {exploit_data.get('title', 'N/A')}")
                print(f"  Severity: {exploit_data.get('severity', 'N/A')}")
                
                # Check for manual steps
                if 'manual_steps' in exploit_data and exploit_data['manual_steps']:
                    print("  ✅ Manual exploitation steps provided")
                else:
                    print("  ❌ Manual exploitation steps missing")
                
                # Check for automated tools
                if 'automated_tools' in exploit_data and exploit_data['automated_tools']:
                    print("  ✅ Automated tool commands provided")
                else:
                    print("  ❌ Automated tool commands missing")
                
                # Check for impact assessment
                if 'impact' in exploit_data and exploit_data['impact']:
                    print("  ✅ Impact assessment provided")
                else:
                    print("  ❌ Impact assessment missing")
                
                # Check for remediation advice
                if 'remediation' in exploit_data and exploit_data['remediation']:
                    print("  ✅ Remediation advice provided")
                else:
                    print("  ❌ Remediation advice missing")
            else:
                print("  ❌ Exploitation data missing from response")
        
        return success, response

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

    def check_subdomain_enumeration(self, scan_results):
        """Check if subdomain enumeration worked"""
        if 'subdomains' in scan_results and isinstance(scan_results['subdomains'], list):
            print(f"\n🌐 Subdomain Enumeration Results:")
            print(f"  Found {len(scan_results['subdomains'])} subdomains")
            
            # Print some subdomains if found
            if scan_results['subdomains']:
                for i, subdomain in enumerate(scan_results['subdomains'][:5]):  # Show first 5
                    print(f"  {i+1}. {subdomain}")
                
                if len(scan_results['subdomains']) > 5:
                    print(f"  ... and {len(scan_results['subdomains']) - 5} more")
                
                return True
            else:
                print("  No subdomains found (this might be normal depending on the target)")
                return True
        else:
            print("❌ Subdomain enumeration data missing from scan results")
            return False

def main():
    # Setup
    tester = VulnScannerAPITester()
    
    # Run tests
    print("🔰 Starting Enhanced VulnScanner Pro API Tests 🔰")
    print(f"Base URL: {tester.base_url}")
    print("=" * 50)
    
    # Test root endpoint
    tester.test_root_endpoint()
    
    # Test tools status - verify all 8 tools are available
    tools_success, tools_response = tester.test_tools_status()
    if not tools_success:
        print("❌ Failed to get tools status, but continuing tests")
    
    # Test list scans (before starting a new one)
    tester.test_list_scans()
    
    # Start a comprehensive scan with subdomain enumeration enabled
    scan_success, _ = tester.test_start_scan(include_subdomains=True)
    if not scan_success:
        print("❌ Failed to start scan, stopping tests")
        return 1
    
    # Wait for scan to complete (with timeout)
    completion_success, scan_results = tester.wait_for_scan_completion(timeout=180)
    
    if completion_success:
        # Print scan results summary
        if 'summary' in scan_results:
            print("\n📊 Scan Results Summary:")
            print(f"  Total vulnerabilities: {scan_results['summary']['total_vulnerabilities']}")
            print("  Severity breakdown:")
            for severity, count in scan_results['summary']['severity_breakdown'].items():
                print(f"    {severity}: {count}")
            
            # Check if all tools were used
            if 'tools_used' in scan_results['summary']:
                print(f"  Tools used: {', '.join(scan_results['summary']['tools_used'])}")
        
        # Check subdomain enumeration results
        tester.check_subdomain_enumeration(scan_results)
        
        # Print some vulnerabilities if found
        if 'vulnerabilities' in scan_results and scan_results['vulnerabilities']:
            print("\n🔍 Sample Vulnerabilities Found:")
            for i, vuln in enumerate(scan_results['vulnerabilities'][:3]):  # Show first 3
                print(f"  {i+1}. [{vuln.get('severity', 'Unknown')}] {vuln.get('description', 'No description')}")
                
                # Check if exploitation data is present
                if 'exploitation' in vuln:
                    print(f"    ✅ Has exploitation guidance")
                else:
                    print(f"    ❌ Missing exploitation guidance")
            
            if len(scan_results['vulnerabilities']) > 3:
                print(f"  ... and {len(scan_results['vulnerabilities']) - 3} more")
            
            # Set a vulnerability index for exploitation guidance testing
            if scan_results['vulnerabilities']:
                tester.vuln_index = 0
                
                # Test exploitation guidance endpoint
                tester.test_exploitation_guidance()
        else:
            print("\n⚠️ No vulnerabilities found in scan results")
    
    # Test delete scan
    tester.test_delete_scan()
    
    # Print results
    print("\n" + "=" * 50)
    print(f"📊 Tests passed: {tester.tests_passed}/{tester.tests_run}")
    print("=" * 50)
    
    return 0 if tester.tests_passed == tester.tests_run else 1

if __name__ == "__main__":
    sys.exit(main())
      