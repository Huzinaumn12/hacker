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

app = FastAPI(title="VulnScanner", description="Comprehensive Vulnerability Scanner for Ethical Pentesting")

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
    scan_type: str = "comprehensive"  # comprehensive, web, network, ssl
    custom_ports: Optional[str] = None

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class VulnerabilityScanner:
    def __init__(self):
        self.tools_available = self.check_tools()
    
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
            'nikto': ['nikto', '-h'],
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
    
    async def run_nmap_scan(self, target: str) -> Dict[str, Any]:
        """Run nmap scan on target"""
        try:
            domain = self.extract_domain(target)
            
            # Basic nmap scan
            cmd = ['nmap', '-sV', '-sC', '-O', '--script', 'vuln', '-T4', domain]
            
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
            
            cmd = ['nikto', '-h', target, '-Format', 'json', '-output', '/tmp/nikto_output.json']
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Read JSON output if available
            try:
                with open('/tmp/nikto_output.json', 'r') as f:
                    nikto_data = json.load(f)
                return self.parse_nikto_output(nikto_data)
            except:
                # Fallback to parsing stdout
                return self.parse_nikto_text(stdout.decode())
                
        except Exception as e:
            return {'error': f'Nikto execution error: {str(e)}'}
    
    def parse_nikto_output(self, nikto_data: Dict) -> Dict[str, Any]:
        """Parse nikto JSON output"""
        vulnerabilities = []
        
        if 'vulnerabilities' in nikto_data:
            for vuln in nikto_data['vulnerabilities']:
                vulnerabilities.append({
                    'type': 'Web Vulnerability',
                    'description': vuln.get('msg', 'Unknown vulnerability'),
                    'url': vuln.get('url', ''),
                    'severity': self.assess_severity(vuln.get('msg', '')),
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
    
    async def run_dirb_scan(self, target: str) -> Dict[str, Any]:
        """Run directory enumeration with dirb"""
        try:
            if not target.startswith(('http://', 'https://')):
                target = 'http://' + target
            
            cmd = ['dirb', target, '/usr/share/dirb/wordlists/common.txt', '-w']
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return self.parse_dirb_output(stdout.decode(), target)
                
        except Exception as e:
            return {'error': f'Dirb execution error: {str(e)}'}
    
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
    
    async def comprehensive_scan(self, target: str, scan_id: str):
        """Run comprehensive vulnerability scan"""
        try:
            scan_results[scan_id] = {
                'status': 'running',
                'target': target,
                'start_time': datetime.now().isoformat(),
                'progress': 0,
                'results': {},
                'vulnerabilities': [],
                'summary': {}
            }
            
            # Update progress
            scan_results[scan_id]['progress'] = 10
            scan_results[scan_id]['status'] = 'Running Nmap scan...'
            
            # Run nmap scan
            nmap_results = await self.run_nmap_scan(target)
            scan_results[scan_id]['results']['nmap'] = nmap_results
            scan_results[scan_id]['progress'] = 30
            
            # Run nikto scan
            scan_results[scan_id]['status'] = 'Running Nikto scan...'
            nikto_results = await self.run_nikto_scan(target)
            scan_results[scan_id]['results']['nikto'] = nikto_results
            scan_results[scan_id]['progress'] = 60
            
            # Run dirb scan
            scan_results[scan_id]['status'] = 'Running directory enumeration...'
            dirb_results = await self.run_dirb_scan(target)
            scan_results[scan_id]['results']['dirb'] = dirb_results
            scan_results[scan_id]['progress'] = 90
            
            # Compile all vulnerabilities
            all_vulnerabilities = []
            
            if 'vulnerabilities' in nmap_results:
                all_vulnerabilities.extend(nmap_results['vulnerabilities'])
            if 'vulnerabilities' in nikto_results:
                all_vulnerabilities.extend(nikto_results['vulnerabilities'])
            if 'discoveries' in dirb_results:
                all_vulnerabilities.extend(dirb_results['discoveries'])
            
            # Generate summary
            severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
            for vuln in all_vulnerabilities:
                severity = vuln.get('severity', 'Info')
                severity_counts[severity] += 1
            
            scan_results[scan_id]['vulnerabilities'] = all_vulnerabilities
            scan_results[scan_id]['summary'] = {
                'total_vulnerabilities': len(all_vulnerabilities),
                'severity_breakdown': severity_counts,
                'tools_used': list(self.tools_available.keys())
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
    return {"message": "VulnScanner API - Comprehensive Vulnerability Scanner"}

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
    background_tasks.add_task(scanner.comprehensive_scan, target.url, scan_id)
    
    active_scans[scan_id] = target.url
    
    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"Vulnerability scan started for {target.url}"
    )

@app.get("/api/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """Get scan results by ID"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_results[scan_id]

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