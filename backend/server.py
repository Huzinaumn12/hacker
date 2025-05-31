from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any
import subprocess
import json
import asyncio
import uuid
import os
from datetime import datetime
import re
from urllib.parse import urlparse
import socket

app = FastAPI(title="VulnScanner Pro", description="Advanced Vulnerability Scanner with Exploitation Guidance")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scan results (replace with MongoDB in production)
scan_results = {}
active_scans = {}

class ScanTarget(BaseModel):
    url: str
    scan_type: str = "comprehensive"  # comprehensive, web, network, ssl, subdomain
    custom_ports: Optional[str] = None
    include_subdomains: bool = True

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class ExploitationKnowledgeBase:
    """Database of vulnerability exploitation techniques and methodologies"""
    
    @staticmethod
    def get_exploitation_guidance(vulnerability_type: str, description: str, tool: str) -> Dict[str, Any]:
        """Get exploitation guidance for a specific vulnerability"""
        
        # Common vulnerability patterns and their exploitation guidance
        exploits = {
            'sql_injection': {
                'title': 'SQL Injection Exploitation',
                'severity': 'Critical',
                'description': 'SQL injection vulnerabilities allow attackers to manipulate database queries',
                'manual_steps': [
                    '1. Identify the injection point (parameter, header, etc.)',
                    '2. Test for basic SQL injection: \' OR 1=1--',
                    '3. Enumerate database structure: UNION SELECT NULL, table_name FROM information_schema.tables',
                    '4. Extract sensitive data: UNION SELECT username, password FROM users',
                    '5. Consider blind SQL injection techniques if direct output is not visible'
                ],
                'automated_tools': [
                    'sqlmap -u "http://target.com/page.php?id=1" --dbs',
                    'sqlmap -u "http://target.com/page.php?id=1" --tables -D database_name',
                    'sqlmap -u "http://target.com/page.php?id=1" --dump -T table_name'
                ],
                'impact': 'Complete database compromise, data exfiltration, privilege escalation',
                'remediation': 'Use parameterized queries, input validation, least privilege database accounts'
            },
            'xss': {
                'title': 'Cross-Site Scripting (XSS) Exploitation',
                'severity': 'High',
                'description': 'XSS allows injection of malicious scripts into web pages',
                'manual_steps': [
                    '1. Identify reflection points in the application',
                    '2. Test basic payload: <script>alert("XSS")</script>',
                    '3. Bypass filters with encoding: %3Cscript%3Ealert("XSS")%3C/script%3E',
                    '4. Try alternative payloads: <img src=x onerror=alert("XSS")>',
                    '5. For stored XSS, inject payload into forms/comments'
                ],
                'automated_tools': [
                    'XSSer -u "http://target.com/search?q=PAYLOAD"',
                    'Burp Suite XSS scanner',
                    'OWASP ZAP XSS scanner'
                ],
                'impact': 'Session hijacking, credential theft, defacement, phishing',
                'remediation': 'Input validation, output encoding, Content Security Policy (CSP)'
            },
            'directory_traversal': {
                'title': 'Directory Traversal Exploitation',
                'severity': 'High',
                'description': 'Path traversal allows access to files outside the web root',
                'manual_steps': [
                    '1. Identify file inclusion parameters',
                    '2. Test basic traversal: ../../../etc/passwd',
                    '3. Try URL encoding: %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                    '4. Test Windows paths: ..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                    '5. Look for sensitive files: config files, logs, source code'
                ],
                'automated_tools': [
                    'dirb http://target.com /usr/share/dirb/wordlists/common.txt',
                    'gobuster dir -u http://target.com -w /usr/share/wordlists/common.txt',
                    'ffuf -w wordlist.txt -u http://target.com/FUZZ'
                ],
                'impact': 'Information disclosure, source code exposure, configuration file access',
                'remediation': 'Input validation, chroot jails, proper file permissions'
            },
            'open_port': {
                'title': 'Open Port Service Exploitation',
                'severity': 'Medium',
                'description': 'Open ports may run vulnerable services',
                'manual_steps': [
                    '1. Banner grab to identify service version',
                    '2. Search for CVEs related to the service',
                    '3. Check for default credentials',
                    '4. Test for misconfigurations',
                    '5. Look for known exploits in Metasploit/ExploitDB'
                ],
                'automated_tools': [
                    'nmap -sV -sC target.com -p [PORT]',
                    'nc target.com [PORT]',
                    'searchsploit [SERVICE_NAME] [VERSION]'
                ],
                'impact': 'Service compromise, lateral movement, information disclosure',
                'remediation': 'Close unnecessary ports, update services, configure firewalls'
            },
            'ssl_vulnerability': {
                'title': 'SSL/TLS Security Issues',
                'severity': 'Medium',
                'description': 'SSL/TLS misconfigurations can lead to man-in-the-middle attacks',
                'manual_steps': [
                    '1. Check SSL certificate validity and chain',
                    '2. Test for weak cipher suites',
                    '3. Check for SSL vulnerabilities (Heartbleed, POODLE, etc.)',
                    '4. Verify HSTS implementation',
                    '5. Test certificate pinning'
                ],
                'automated_tools': [
                    'sslscan target.com',
                    'sslyze target.com',
                    'testssl.sh target.com'
                ],
                'impact': 'Man-in-the-middle attacks, credential interception, data tampering',
                'remediation': 'Use strong cipher suites, implement HSTS, regular certificate updates'
            }
        }
        
        # Analyze vulnerability description to determine type
        desc_lower = description.lower()
        
        if any(term in desc_lower for term in ['sql', 'injection', 'union']):
            return exploits['sql_injection']
        elif any(term in desc_lower for term in ['xss', 'script', 'cross-site']):
            return exploits['xss']
        elif any(term in desc_lower for term in ['directory', 'traversal', 'path']):
            return exploits['directory_traversal']
        elif any(term in desc_lower for term in ['ssl', 'tls', 'certificate']):
            return exploits['ssl_vulnerability']
        elif tool == 'nmap' and any(term in desc_lower for term in ['open', 'port']):
            return exploits['open_port']
        else:
            # Generic exploitation guidance
            return {
                'title': 'General Security Finding',
                'severity': 'Info',
                'description': 'Security finding requires manual analysis',
                'manual_steps': [
                    '1. Research the specific vulnerability or finding',
                    '2. Check CVE databases for known exploits',
                    '3. Search security advisories and exploit databases',
                    '4. Test manually for exploitability',
                    '5. Document findings and impact'
                ],
                'automated_tools': [
                    'searchsploit [VULNERABILITY_TERM]',
                    'Google: "[VULNERABILITY] exploit"',
                    'Check ExploitDB, CVE databases'
                ],
                'impact': 'Varies depending on specific vulnerability',
                'remediation': 'Follow vendor security advisories and best practices'
            }

class VulnerabilityScanner:
    def __init__(self):
        self.tools_available = self.check_tools()
        self.exploit_kb = ExploitationKnowledgeBase()
    
    def check_tools(self) -> Dict[str, bool]:
        """Check which security tools are available"""
        tools = {
            'nmap': False,
            'nikto': False,
            'dirb': False,
            'sqlmap': False,
            'whatweb': False,
            'subfinder': False,
            'gobuster': False,
            'sslscan': False
        }
        
        # Different commands to check tool availability
        tool_commands = {
            'nmap': ['nmap', '--version'],
            'nikto': ['nikto', '-Version'],
            'dirb': ['dirb'],
            'sqlmap': ['sqlmap', '--version'],
            'whatweb': ['whatweb', '--version'],
            'subfinder': ['subfinder', '-version'],
            'gobuster': ['gobuster', 'version'],
            'sslscan': ['sslscan', '--version']
        }
        
        for tool, cmd in tool_commands.items():
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=5)
                # Tool is available if it doesn't fail with FileNotFoundError
                tools[tool] = True
            except FileNotFoundError:
                # Tool not found
                tools[tool] = False
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                # Tool exists but command failed - still consider it available
                tools[tool] = True
        
        return tools
    
    def extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return urlparse(url).netloc
    
    async def run_subdomain_enumeration(self, target: str) -> Dict[str, Any]:
        """Run subdomain enumeration"""
        try:
            domain = self.extract_domain(target)
            subdomains = []
            
            if self.tools_available.get('subfinder'):
                # Run subfinder
                cmd = ['subfinder', '-d', domain, '-silent']
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    subdomain_list = stdout.decode().strip().split('\n')
                    subdomains = [sub.strip() for sub in subdomain_list if sub.strip() and sub.strip() != domain]
            
            return {
                'subdomains': subdomains,
                'count': len(subdomains),
                'tool': 'subfinder'
            }
                
        except Exception as e:
            return {'error': f'Subdomain enumeration error: {str(e)}'}
    
    async def run_nmap_scan(self, target: str) -> Dict[str, Any]:
        """Run nmap scan on target"""
        try:
            domain = self.extract_domain(target)
            
            # Comprehensive nmap scan
            cmd = ['nmap', '-sV', '-sC', '-O', '--script', 'vuln', '-T4', '-p-', domain]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return self.parse_nmap_output(stdout.decode())
            else:
                return {'error': f'Nmap failed: {stderr.decode()}'}
                
        except Exception as e:
            return {'error': f'Nmap execution error: {str(e)}'}
    
    def parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parse nmap output for vulnerabilities"""
        vulnerabilities = []
        open_ports = []
        
        lines = output.split('\n')
        current_port = None
        
        for line in lines:
            line = line.strip()
            
            # Extract open ports
            if '/tcp' in line and 'open' in line:
                port_match = re.search(r'(\d+)/tcp\s+open\s+([^\s]+)', line)
                if port_match:
                    port = port_match.group(1)
                    service = port_match.group(2)
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'protocol': 'tcp'
                    })
                    current_port = port
                    
                    # Add open port as a finding
                    vulnerabilities.append({
                        'type': 'Open Port',
                        'port': port,
                        'service': service,
                        'description': f'Open port {port} running {service}',
                        'severity': self.assess_severity(f'open port {service}'),
                        'tool': 'nmap'
                    })
            
            # Extract vulnerabilities from script results
            if '|' in line and any(vuln_keyword in line.lower() for vuln_keyword in 
                                 ['cve-', 'vulnerable', 'exploit', 'backdoor', 'weak']):
                vulnerabilities.append({
                    'type': 'Network Vulnerability',
                    'port': current_port,
                    'description': line.strip('|').strip(),
                    'severity': self.assess_severity(line),
                    'tool': 'nmap'
                })
        
        return {
            'open_ports': open_ports,
            'vulnerabilities': vulnerabilities,
            'raw_output': output
        }
    
    async def run_nikto_scan(self, target: str) -> Dict[str, Any]:
        """Run nikto web vulnerability scan"""
        try:
            if not target.startswith(('http://', 'https://')):
                target = 'http://' + target
            
            cmd = ['nikto', '-h', target, '-Format', 'csv', '-output', '/tmp/nikto_output.csv']
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse CSV output if available
            try:
                with open('/tmp/nikto_output.csv', 'r') as f:
                    return self.parse_nikto_csv(f.read())
            except:
                # Fallback to parsing stdout
                return self.parse_nikto_text(stdout.decode())
                
        except Exception as e:
            return {'error': f'Nikto execution error: {str(e)}'}
    
    def parse_nikto_csv(self, csv_data: str) -> Dict[str, Any]:
        """Parse nikto CSV output"""
        vulnerabilities = []
        lines = csv_data.split('\n')
        
        for line in lines[1:]:  # Skip header
            if line.strip():
                parts = line.split('","')
                if len(parts) >= 7:
                    vulnerabilities.append({
                        'type': 'Web Vulnerability',
                        'description': parts[6].strip('"'),
                        'url': parts[1].strip('"'),
                        'severity': self.assess_severity(parts[6]),
                        'tool': 'nikto'
                    })
        
        return {'vulnerabilities': vulnerabilities}
    
    def parse_nikto_text(self, output: str) -> Dict[str, Any]:
        """Parse nikto text output as fallback"""
        vulnerabilities = []
        lines = output.split('\n')
        
        for line in lines:
            if '+' in line and any(keyword in line.lower() for keyword in 
                                 ['osvdb', 'cve', 'vulnerable', 'exploit', 'risk']):
                vulnerabilities.append({
                    'type': 'Web Vulnerability',
                    'description': line.strip('+').strip(),
                    'severity': self.assess_severity(line),
                    'tool': 'nikto'
                })
        
        return {'vulnerabilities': vulnerabilities}
    
    async def run_gobuster_scan(self, target: str) -> Dict[str, Any]:
        """Run directory enumeration with gobuster"""
        try:
            if not target.startswith(('http://', 'https://')):
                target = 'http://' + target
            
            # Use gobuster if available, otherwise fallback to dirb
            if self.tools_available.get('gobuster'):
                cmd = ['gobuster', 'dir', '-u', target, '-w', '/usr/share/dirb/wordlists/common.txt', '-t', '50']
            else:
                cmd = ['dirb', target, '/usr/share/dirb/wordlists/common.txt', '-w']
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if self.tools_available.get('gobuster'):
                return self.parse_gobuster_output(stdout.decode(), target)
            else:
                return self.parse_dirb_output(stdout.decode(), target)
                
        except Exception as e:
            return {'error': f'Directory enumeration error: {str(e)}'}
    
    def parse_gobuster_output(self, output: str, base_url: str) -> Dict[str, Any]:
        """Parse gobuster output"""
        directories = []
        lines = output.split('\n')
        
        for line in lines:
            if line.startswith('/') and '(Status: 200)' in line:
                path = line.split()[0]
                directories.append({
                    'type': 'Directory/File Found',
                    'url': base_url + path,
                    'description': f'Discovered directory/file: {path}',
                    'severity': 'Info',
                    'tool': 'gobuster'
                })
        
        return {'discoveries': directories}
    
    def parse_dirb_output(self, output: str, base_url: str) -> Dict[str, Any]:
        """Parse dirb output for discovered directories"""
        directories = []
        lines = output.split('\n')
        
        for line in lines:
            if '==>' in line and 'DIRECTORY' in line:
                dir_match = re.search(r'==> DIRECTORY: (.+)', line)
                if dir_match:
                    directories.append({
                        'type': 'Directory Found',
                        'url': dir_match.group(1).strip(),
                        'description': 'Discovered directory',
                        'severity': 'Info',
                        'tool': 'dirb'
                    })
            elif '+' in line and base_url in line:
                # Found file/page
                url_match = re.search(r'\+ (.+?) \(', line)
                if url_match:
                    directories.append({
                        'type': 'File/Page Found',
                        'url': url_match.group(1).strip(),
                        'description': 'Discovered file or page',
                        'severity': 'Info',
                        'tool': 'dirb'
                    })
        
        return {'discoveries': directories}
    
    async def run_sslscan(self, target: str) -> Dict[str, Any]:
        """Run SSL/TLS scan"""
        try:
            domain = self.extract_domain(target)
            
            if not self.tools_available.get('sslscan'):
                return {'error': 'SSLScan not available'}
            
            cmd = ['sslscan', '--show-certificate', domain]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return self.parse_sslscan_output(stdout.decode())
            else:
                return {'error': f'SSLScan failed: {stderr.decode()}'}
                
        except Exception as e:
            return {'error': f'SSLScan execution error: {str(e)}'}
    
    def parse_sslscan_output(self, output: str) -> Dict[str, Any]:
        """Parse sslscan output"""
        vulnerabilities = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if any(keyword in line.lower() for keyword in ['weak', 'vulnerable', 'deprecated', 'insecure']):
                vulnerabilities.append({
                    'type': 'SSL/TLS Issue',
                    'description': line,
                    'severity': self.assess_severity(line),
                    'tool': 'sslscan'
                })
        
        return {'vulnerabilities': vulnerabilities}
    
    def assess_severity(self, description: str) -> str:
        """Assess vulnerability severity based on description"""
        description_lower = description.lower()
        
        if any(keyword in description_lower for keyword in 
               ['critical', 'remote code execution', 'rce', 'backdoor', 'shell']):
            return 'Critical'
        elif any(keyword in description_lower for keyword in 
                 ['high', 'sql injection', 'xss', 'csrf', 'authentication bypass']):
            return 'High'
        elif any(keyword in description_lower for keyword in 
                 ['medium', 'information disclosure', 'directory traversal']):
            return 'Medium'
        elif any(keyword in description_lower for keyword in 
                 ['low', 'banner', 'version disclosure']):
            return 'Low'
        else:
            return 'Info'
    
    def add_exploitation_guidance(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Add exploitation guidance to vulnerabilities"""
        enhanced_vulns = []
        
        for vuln in vulnerabilities:
            # Get exploitation guidance
            exploit_info = self.exploit_kb.get_exploitation_guidance(
                vuln.get('type', ''),
                vuln.get('description', ''),
                vuln.get('tool', '')
            )
            
            # Add exploitation data to vulnerability
            enhanced_vuln = vuln.copy()
            enhanced_vuln['exploitation'] = exploit_info
            enhanced_vulns.append(enhanced_vuln)
        
        return enhanced_vulns
    
    async def comprehensive_scan(self, target: str, scan_id: str, include_subdomains: bool = True):
        """Run comprehensive vulnerability scan with exploitation guidance"""
        try:
            scan_results[scan_id] = {
                'status': 'running',
                'target': target,
                'start_time': datetime.now().isoformat(),
                'progress': 0,
                'results': {},
                'vulnerabilities': [],
                'subdomains': [],
                'summary': {}
            }
            
            # Phase 1: Subdomain enumeration (if requested)
            if include_subdomains:
                scan_results[scan_id]['progress'] = 5
                scan_results[scan_id]['status'] = 'Enumerating subdomains...'
                
                subdomain_results = await self.run_subdomain_enumeration(target)
                scan_results[scan_id]['results']['subdomains'] = subdomain_results
                if 'subdomains' in subdomain_results:
                    scan_results[scan_id]['subdomains'] = subdomain_results['subdomains']
            
            # Phase 2: Network scanning
            scan_results[scan_id]['progress'] = 20
            scan_results[scan_id]['status'] = 'Running network scan (Nmap)...'
            
            nmap_results = await self.run_nmap_scan(target)
            scan_results[scan_id]['results']['nmap'] = nmap_results
            scan_results[scan_id]['progress'] = 40
            
            # Phase 3: Web vulnerability scanning
            scan_results[scan_id]['status'] = 'Running web vulnerability scan (Nikto)...'
            nikto_results = await self.run_nikto_scan(target)
            scan_results[scan_id]['results']['nikto'] = nikto_results
            scan_results[scan_id]['progress'] = 60
            
            # Phase 4: Directory enumeration
            scan_results[scan_id]['status'] = 'Running directory enumeration...'
            dir_results = await self.run_gobuster_scan(target)
            scan_results[scan_id]['results']['directory'] = dir_results
            scan_results[scan_id]['progress'] = 80
            
            # Phase 5: SSL/TLS scanning
            scan_results[scan_id]['status'] = 'Running SSL/TLS scan...'
            ssl_results = await self.run_sslscan(target)
            scan_results[scan_id]['results']['ssl'] = ssl_results
            scan_results[scan_id]['progress'] = 90
            
            # Phase 6: Compile results and add exploitation guidance
            scan_results[scan_id]['status'] = 'Adding exploitation guidance...'
            
            all_vulnerabilities = []
            
            if 'vulnerabilities' in nmap_results:
                all_vulnerabilities.extend(nmap_results['vulnerabilities'])
            if 'vulnerabilities' in nikto_results:
                all_vulnerabilities.extend(nikto_results['vulnerabilities'])
            if 'discoveries' in dir_results:
                all_vulnerabilities.extend(dir_results['discoveries'])
            if 'vulnerabilities' in ssl_results:
                all_vulnerabilities.extend(ssl_results['vulnerabilities'])
            
            # Add exploitation guidance to vulnerabilities
            enhanced_vulnerabilities = self.add_exploitation_guidance(all_vulnerabilities)
            
            # Generate summary
            severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
            for vuln in enhanced_vulnerabilities:
                severity = vuln.get('severity', 'Info')
                severity_counts[severity] += 1
            
            scan_results[scan_id]['vulnerabilities'] = enhanced_vulnerabilities
            scan_results[scan_id]['summary'] = {
                'total_vulnerabilities': len(enhanced_vulnerabilities),
                'severity_breakdown': severity_counts,
                'tools_used': [tool for tool, available in self.tools_available.items() if available],
                'subdomain_count': len(scan_results[scan_id]['subdomains']) if include_subdomains else 0
            }
            
            scan_results[scan_id]['status'] = 'completed'
            scan_results[scan_id]['progress'] = 100
            scan_results[scan_id]['end_time'] = datetime.now().isoformat()
            
        except Exception as e:
            scan_results[scan_id]['status'] = 'failed'
            scan_results[scan_id]['error'] = str(e)

# Initialize scanner
scanner = VulnerabilityScanner()

@app.get("/api/")
async def root():
    return {"message": "VulnScanner Pro - Advanced Vulnerability Scanner with Exploitation Guidance"}

@app.get("/api/tools-status")
async def get_tools_status():
    """Get status of available security tools"""
    return {
        "tools": scanner.tools_available,
        "total_tools": len(scanner.tools_available),
        "available_tools": sum(scanner.tools_available.values())
    }

@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(target: ScanTarget, background_tasks: BackgroundTasks):
    """Start a comprehensive vulnerability scan"""
    scan_id = str(uuid.uuid4())
    
    # Validate target
    if not target.url:
        raise HTTPException(status_code=400, detail="Target URL is required")
    
    # Start background scan
    background_tasks.add_task(
        scanner.comprehensive_scan, 
        target.url, 
        scan_id, 
        target.include_subdomains
    )
    
    active_scans[scan_id] = target.url
    
    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"Comprehensive vulnerability scan started for {target.url}"
    )

@app.get("/api/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """Get scan results by ID"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_results[scan_id]

@app.get("/api/scan/{scan_id}/exploitation/{vuln_index}")
async def get_exploitation_guidance(scan_id: str, vuln_index: int):
    """Get detailed exploitation guidance for a specific vulnerability"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    vulnerabilities = scan_results[scan_id].get('vulnerabilities', [])
    
    if vuln_index >= len(vulnerabilities):
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    vulnerability = vulnerabilities[vuln_index]
    
    return {
        'vulnerability': vulnerability,
        'exploitation': vulnerability.get('exploitation', {}),
        'index': vuln_index
    }

@app.get("/api/scans")
async def list_scans():
    """List all scans"""
    return {
        "active_scans": len(active_scans),
        "completed_scans": len([s for s in scan_results.values() if s['status'] == 'completed']),
        "scans": list(scan_results.keys())
    }

@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete scan results"""
    if scan_id in scan_results:
        del scan_results[scan_id]
    if scan_id in active_scans:
        del active_scans[scan_id]
    
    return {"message": "Scan deleted successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)