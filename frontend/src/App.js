import React, { useState, useEffect } from 'react';
import './App.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

function App() {
  const [target, setTarget] = useState('');
  const [includeSubdomains, setIncludeSubdomains] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [results, setResults] = useState(null);
  const [toolsStatus, setToolsStatus] = useState(null);
  const [progress, setProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState('');
  const [activeTab, setActiveTab] = useState('vulnerabilities');
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [exploitationData, setExploitationData] = useState(null);

  useEffect(() => {
    fetchToolsStatus();
  }, []);

  useEffect(() => {
    let interval;
    if (scanId && scanning) {
      interval = setInterval(() => {
        fetchScanResults();
      }, 2000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [scanId, scanning]);

  const fetchToolsStatus = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/tools-status`);
      const data = await response.json();
      setToolsStatus(data);
    } catch (error) {
      console.error('Error fetching tools status:', error);
    }
  };

  const startScan = async () => {
    if (!target.trim()) {
      alert('Please enter a target URL or domain');
      return;
    }

    setScanning(true);
    setResults(null);
    setProgress(0);
    setScanStatus('Initializing comprehensive scan...');
    setActiveTab('vulnerabilities');

    try {
      const response = await fetch(`${BACKEND_URL}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: target,
          scan_type: 'comprehensive',
          include_subdomains: includeSubdomains
        }),
      });

      const data = await response.json();
      setScanId(data.scan_id);
    } catch (error) {
      console.error('Error starting scan:', error);
      setScanning(false);
      alert('Error starting scan. Please try again.');
    }
  };

  const fetchScanResults = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/scan/${scanId}`);
      const data = await response.json();
      
      setProgress(data.progress || 0);
      setScanStatus(data.status || '');
      
      if (data.status === 'completed') {
        setResults(data);
        setScanning(false);
      } else if (data.status === 'failed') {
        setScanning(false);
        alert('Scan failed: ' + (data.error || 'Unknown error'));
      }
    } catch (error) {
      console.error('Error fetching scan results:', error);
    }
  };

  const fetchExploitationGuidance = async (vulnIndex) => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/scan/${scanId}/exploitation/${vulnIndex}`);
      const data = await response.json();
      setExploitationData(data);
      setSelectedVuln(vulnIndex);
    } catch (error) {
      console.error('Error fetching exploitation guidance:', error);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'Critical': return 'text-red-600 bg-red-100 border-red-300';
      case 'High': return 'text-orange-600 bg-orange-100 border-orange-300';
      case 'Medium': return 'text-yellow-600 bg-yellow-100 border-yellow-300';
      case 'Low': return 'text-blue-600 bg-blue-100 border-blue-300';
      default: return 'text-gray-600 bg-gray-100 border-gray-300';
    }
  };

  const getToolIcon = (tool) => {
    const icons = {
      nmap: '🌐',
      nikto: '🔍',
      dirb: '📁',
      gobuster: '⚡',
      sqlmap: '💉',
      whatweb: '🕷️',
      subfinder: '🔎',
      sslscan: '🔐'
    };
    return icons[tool] || '🔧';
  };

  const ExploitationModal = () => {
    if (!exploitationData) return null;

    const { vulnerability, exploitation } = exploitationData;

    return (
      <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50 p-4">
        <div className="bg-gray-800 rounded-lg max-w-4xl w-full max-h-full overflow-y-auto">
          {/* Header */}
          <div className="p-6 border-b border-gray-700">
            <div className="flex items-center justify-between">
              <h2 className="text-2xl font-bold text-white flex items-center">
                <span className="text-3xl mr-3">🎯</span>
                Exploitation Guidance
              </h2>
              <button
                onClick={() => setExploitationData(null)}
                className="text-gray-400 hover:text-white text-2xl"
              >
                ×
              </button>
            </div>
          </div>

          {/* Content */}
          <div className="p-6 space-y-6">
            {/* Vulnerability Info */}
            <div className="bg-gray-700 rounded-lg p-4">
              <h3 className="text-lg font-semibold text-white mb-2">Vulnerability Details</h3>
              <div className="space-y-2">
                <div className="flex items-center space-x-2">
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${getSeverityColor(vulnerability.severity)}`}>
                    {vulnerability.severity}
                  </span>
                  <span className="text-sm bg-gray-600 px-2 py-1 rounded text-white">
                    {getToolIcon(vulnerability.tool)} {vulnerability.tool}
                  </span>
                </div>
                <p className="text-gray-300">{vulnerability.description}</p>
                {vulnerability.url && (
                  <p className="text-blue-400 text-sm break-all">{vulnerability.url}</p>
                )}
              </div>
            </div>

            {/* Exploitation Details */}
            <div className="bg-gray-700 rounded-lg p-4">
              <h3 className="text-xl font-semibold text-white mb-4">{exploitation.title}</h3>
              <p className="text-gray-300 mb-4">{exploitation.description}</p>
              
              {/* Impact */}
              <div className="mb-4">
                <h4 className="text-lg font-semibold text-red-400 mb-2">🚨 Potential Impact</h4>
                <p className="text-gray-300 bg-red-900 bg-opacity-30 p-3 rounded">{exploitation.impact}</p>
              </div>

              {/* Manual Steps */}
              <div className="mb-4">
                <h4 className="text-lg font-semibold text-yellow-400 mb-2">📋 Manual Exploitation Steps</h4>
                <div className="bg-gray-800 p-4 rounded">
                  {exploitation.manual_steps.map((step, index) => (
                    <div key={index} className="mb-2 text-gray-300">{step}</div>
                  ))}
                </div>
              </div>

              {/* Automated Tools */}
              <div className="mb-4">
                <h4 className="text-lg font-semibold text-green-400 mb-2">🤖 Automated Tools & Commands</h4>
                <div className="bg-gray-900 p-4 rounded font-mono text-sm">
                  {exploitation.automated_tools.map((tool, index) => (
                    <div key={index} className="mb-2 text-green-300">
                      <span className="text-gray-500">$ </span>{tool}
                    </div>
                  ))}
                </div>
              </div>

              {/* Remediation */}
              <div>
                <h4 className="text-lg font-semibold text-blue-400 mb-2">🛡️ Remediation</h4>
                <p className="text-gray-300 bg-blue-900 bg-opacity-30 p-3 rounded">{exploitation.remediation}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="text-3xl">🛡️</div>
              <div>
                <h1 className="text-3xl font-bold text-white">VulnScanner Pro</h1>
                <p className="text-sm text-gray-400">Advanced Vulnerability Scanner with Exploitation Guidance</p>
              </div>
            </div>
            <div className="text-right">
              <div className="text-sm text-gray-400">For Ethical Pentesting</div>
              <div className="text-xs text-red-400">⚠️ Use only on authorized targets</div>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Tools Status */}
        {toolsStatus && (
          <div className="mb-8 bg-gray-800 rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4 flex items-center">
              <span className="text-xl mr-2">🔧</span>
              Security Tools Arsenal
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
              {Object.entries(toolsStatus.tools).map(([tool, available]) => (
                <div key={tool} className={`p-3 rounded-lg text-center transition-all ${
                  available ? 'bg-green-900 border border-green-700 hover:bg-green-800' : 'bg-red-900 border border-red-700'
                }`}>
                  <div className="text-2xl mb-1">{getToolIcon(tool)}</div>
                  <div className="text-sm font-medium">{tool}</div>
                  <div className={`text-xs ${available ? 'text-green-400' : 'text-red-400'}`}>
                    {available ? 'Ready' : 'Missing'}
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-4 text-sm text-gray-400">
              {toolsStatus.available_tools} of {toolsStatus.total_tools} tools ready for engagement
            </div>
          </div>
        )}

        {/* Scan Configuration */}
        <div className="bg-gray-800 rounded-lg p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4 flex items-center">
            <span className="text-xl mr-2">🎯</span>
            Target Configuration
          </h2>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Target URL or Domain
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g., example.com or https://example.com"
                className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                disabled={scanning}
              />
            </div>

            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="subdomains"
                checked={includeSubdomains}
                onChange={(e) => setIncludeSubdomains(e.target.checked)}
                disabled={scanning}
                className="w-4 h-4 text-blue-600 bg-gray-700 border-gray-600 rounded focus:ring-blue-500"
              />
              <label htmlFor="subdomains" className="text-sm text-gray-300">
                Include subdomain enumeration
              </label>
            </div>
            
            <button
              onClick={startScan}
              disabled={scanning || !target.trim()}
              className={`w-full py-3 px-6 rounded-lg font-semibold text-lg ${
                scanning || !target.trim()
                  ? 'bg-gray-600 cursor-not-allowed'
                  : 'bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-700 hover:to-orange-700 transform hover:scale-105'
              } transition-all duration-200`}
            >
              {scanning ? (
                <div className="flex items-center justify-center space-x-2">
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                  <span>Scanning... {progress}%</span>
                </div>
              ) : (
                <div className="flex items-center justify-center space-x-2">
                  <span>🚀</span>
                  <span>Launch Comprehensive Attack</span>
                </div>
              )}
            </button>
          </div>
        </div>

        {/* Scan Progress */}
        {scanning && (
          <div className="bg-gray-800 rounded-lg p-6 mb-8">
            <h3 className="text-lg font-semibold mb-4 flex items-center">
              <span className="text-xl mr-2">⏳</span>
              Attack Progress
            </h3>
            
            <div className="space-y-4">
              <div className="w-full bg-gray-700 rounded-full h-4 overflow-hidden">
                <div 
                  className="bg-gradient-to-r from-red-500 via-orange-500 to-yellow-500 h-4 rounded-full transition-all duration-300 relative"
                  style={{ width: `${progress}%` }}
                >
                  <div className="absolute inset-0 bg-white opacity-30 animate-pulse"></div>
                </div>
              </div>
              
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">{scanStatus}</span>
                <span className="text-white font-medium">{progress}%</span>
              </div>
            </div>
          </div>
        )}

        {/* Results */}
        {results && (
          <div className="space-y-8">
            {/* Summary Dashboard */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h3 className="text-xl font-semibold mb-4 flex items-center">
                <span className="text-xl mr-2">📊</span>
                Attack Summary
              </h3>
              
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                {Object.entries(results.summary.severity_breakdown).map(([severity, count]) => (
                  <div key={severity} className={`p-4 rounded-lg border ${getSeverityColor(severity)} transition-transform hover:scale-105`}>
                    <div className="text-3xl font-bold">{count}</div>
                    <div className="text-sm font-medium">{severity}</div>
                  </div>
                ))}
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm text-gray-400">
                <div>Total Issues: <span className="text-white font-semibold">{results.summary.total_vulnerabilities}</span></div>
                <div>Subdomains Found: <span className="text-white font-semibold">{results.summary.subdomain_count}</span></div>
                <div>Scan Completed: <span className="text-white font-semibold">{new Date(results.end_time).toLocaleString()}</span></div>
              </div>
            </div>

            {/* Navigation Tabs */}
            <div className="bg-gray-800 rounded-lg">
              <div className="border-b border-gray-700">
                <nav className="flex space-x-8 px-6">
                  {[
                    { id: 'vulnerabilities', name: 'Vulnerabilities', icon: '🔍', count: results.vulnerabilities.length },
                    { id: 'subdomains', name: 'Subdomains', icon: '🌐', count: results.subdomains?.length || 0 },
                    { id: 'ports', name: 'Open Ports', icon: '🔌', count: results.results.nmap?.open_ports?.length || 0 }
                  ].map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={`py-4 px-2 border-b-2 font-medium text-sm flex items-center space-x-2 ${
                        activeTab === tab.id
                          ? 'border-red-500 text-red-400'
                          : 'border-transparent text-gray-400 hover:text-gray-300'
                      }`}
                    >
                      <span>{tab.icon}</span>
                      <span>{tab.name}</span>
                      <span className="bg-gray-600 text-white text-xs px-2 py-1 rounded-full">{tab.count}</span>
                    </button>
                  ))}
                </nav>
              </div>

              <div className="p-6">
                {/* Vulnerabilities Tab */}
                {activeTab === 'vulnerabilities' && (
                  <div className="space-y-4">
                    {results.vulnerabilities.length === 0 ? (
                      <div className="text-center py-8 text-gray-400">
                        <div className="text-4xl mb-2">✅</div>
                        <div>No vulnerabilities detected!</div>
                      </div>
                    ) : (
                      results.vulnerabilities.map((vuln, index) => (
                        <div key={index} className="bg-gray-700 border border-gray-600 rounded-lg p-4 hover:bg-gray-650 transition-colors">
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex items-center space-x-3">
                              <span className={`px-3 py-1 rounded-full text-sm font-medium border ${getSeverityColor(vuln.severity)}`}>
                                {vuln.severity}
                              </span>
                              <span className="text-sm bg-gray-600 px-2 py-1 rounded text-white">
                                {getToolIcon(vuln.tool)} {vuln.tool}
                              </span>
                            </div>
                            <div className="flex items-center space-x-2">
                              <span className="text-sm text-gray-400">{vuln.type}</span>
                              <button
                                onClick={() => fetchExploitationGuidance(index)}
                                className="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm font-medium transition-colors"
                              >
                                🎯 Exploit
                              </button>
                            </div>
                          </div>
                          
                          <div className="text-white mb-2">{vuln.description}</div>
                          
                          {vuln.url && (
                            <div className="text-sm text-blue-400 break-all mb-2">{vuln.url}</div>
                          )}
                          
                          {vuln.port && (
                            <div className="text-sm text-gray-400">Port: {vuln.port}</div>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                )}

                {/* Subdomains Tab */}
                {activeTab === 'subdomains' && (
                  <div className="space-y-4">
                    {results.subdomains?.length === 0 ? (
                      <div className="text-center py-8 text-gray-400">
                        <div className="text-4xl mb-2">🌐</div>
                        <div>No subdomains discovered</div>
                      </div>
                    ) : (
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {results.subdomains?.map((subdomain, index) => (
                          <div key={index} className="bg-gray-700 border border-gray-600 rounded-lg p-4">
                            <div className="text-white font-medium break-all">{subdomain}</div>
                            <div className="text-sm text-gray-400 mt-1">Discovered subdomain</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Open Ports Tab */}
                {activeTab === 'ports' && (
                  <div className="space-y-4">
                    {results.results.nmap?.open_ports?.length === 0 ? (
                      <div className="text-center py-8 text-gray-400">
                        <div className="text-4xl mb-2">🔌</div>
                        <div>No open ports detected</div>
                      </div>
                    ) : (
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {results.results.nmap?.open_ports?.map((port, index) => (
                          <div key={index} className="bg-gray-700 border border-gray-600 rounded-lg p-4">
                            <div className="flex items-center justify-between mb-2">
                              <div className="text-lg font-semibold text-white">Port {port.port}</div>
                              <div className="text-sm bg-blue-600 px-2 py-1 rounded">{port.protocol}</div>
                            </div>
                            <div className="text-gray-400">{port.service}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Exploitation Modal */}
      <ExploitationModal />

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="text-center text-gray-400">
            <div className="text-sm mb-2">⚠️ For Educational and Ethical Penetration Testing Only</div>
            <div className="text-xs">Always obtain proper authorization before scanning any targets</div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;