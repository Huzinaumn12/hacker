import React, { useState, useEffect } from 'react';
import './App.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

function App() {
  const [target, setTarget] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [results, setResults] = useState(null);
  const [toolsStatus, setToolsStatus] = useState(null);
  const [progress, setProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState('');

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
    setScanStatus('Initializing scan...');

    try {
      const response = await fetch(`${BACKEND_URL}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: target,
          scan_type: 'comprehensive'
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

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'Critical': return 'text-red-600 bg-red-100';
      case 'High': return 'text-orange-600 bg-orange-100';
      case 'Medium': return 'text-yellow-600 bg-yellow-100';
      case 'Low': return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getToolIcon = (tool) => {
    const icons = {
      nmap: '🌐',
      nikto: '🔍',
      dirb: '📁',
      sqlmap: '💉',
      whatweb: '🕷️',
      subfinder: '🔎',
      gobuster: '⚡',
      sslscan: '🔐'
    };
    return icons[tool] || '🔧';
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="text-2xl">🛡️</div>
              <div>
                <h1 className="text-2xl font-bold text-white">VulnScanner</h1>
                <p className="text-sm text-gray-400">Comprehensive Vulnerability Scanner</p>
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
              Security Tools Status
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
              {Object.entries(toolsStatus.tools).map(([tool, available]) => (
                <div key={tool} className={`p-3 rounded-lg text-center ${
                  available ? 'bg-green-900 border border-green-700' : 'bg-red-900 border border-red-700'
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
              {toolsStatus.available_tools} of {toolsStatus.total_tools} tools available
            </div>
          </div>
        )}

        {/* Scan Input */}
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
            
            <button
              onClick={startScan}
              disabled={scanning || !target.trim()}
              className={`w-full py-3 px-6 rounded-lg font-semibold text-lg ${
                scanning || !target.trim()
                  ? 'bg-gray-600 cursor-not-allowed'
                  : 'bg-red-600 hover:bg-red-700 transform hover:scale-105'
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
                  <span>Start Comprehensive Scan</span>
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
              Scan Progress
            </h3>
            
            <div className="space-y-4">
              <div className="w-full bg-gray-700 rounded-full h-3">
                <div 
                  className="bg-gradient-to-r from-red-500 to-orange-500 h-3 rounded-full transition-all duration-300"
                  style={{ width: `${progress}%` }}
                ></div>
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
            {/* Summary */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h3 className="text-xl font-semibold mb-4 flex items-center">
                <span className="text-xl mr-2">📊</span>
                Scan Summary
              </h3>
              
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                {Object.entries(results.summary.severity_breakdown).map(([severity, count]) => (
                  <div key={severity} className={`p-4 rounded-lg ${getSeverityColor(severity)}`}>
                    <div className="text-2xl font-bold">{count}</div>
                    <div className="text-sm font-medium">{severity}</div>
                  </div>
                ))}
              </div>
              
              <div className="text-sm text-gray-400">
                <div>Total Issues Found: {results.summary.total_vulnerabilities}</div>
                <div>Scan completed: {new Date(results.end_time).toLocaleString()}</div>
                <div>Target: {results.target}</div>
              </div>
            </div>

            {/* Vulnerabilities */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h3 className="text-xl font-semibold mb-4 flex items-center">
                <span className="text-xl mr-2">🔍</span>
                Vulnerabilities & Findings
              </h3>
              
              {results.vulnerabilities.length === 0 ? (
                <div className="text-center py-8 text-gray-400">
                  <div className="text-4xl mb-2">✅</div>
                  <div>No vulnerabilities found!</div>
                </div>
              ) : (
                <div className="space-y-4">
                  {results.vulnerabilities.map((vuln, index) => (
                    <div key={index} className="bg-gray-700 border border-gray-600 rounded-lg p-4">
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center space-x-3">
                          <span className={`px-3 py-1 rounded-full text-sm font-medium ${getSeverityColor(vuln.severity)}`}>
                            {vuln.severity}
                          </span>
                          <span className="text-sm bg-gray-600 px-2 py-1 rounded">
                            {getToolIcon(vuln.tool)} {vuln.tool}
                          </span>
                        </div>
                        <span className="text-sm text-gray-400">{vuln.type}</span>
                      </div>
                      
                      <div className="text-white mb-2">{vuln.description}</div>
                      
                      {vuln.url && (
                        <div className="text-sm text-blue-400 break-all">{vuln.url}</div>
                      )}
                      
                      {vuln.port && (
                        <div className="text-sm text-gray-400">Port: {vuln.port}</div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Open Ports */}
            {results.results.nmap && results.results.nmap.open_ports && results.results.nmap.open_ports.length > 0 && (
              <div className="bg-gray-800 rounded-lg p-6">
                <h3 className="text-xl font-semibold mb-4 flex items-center">
                  <span className="text-xl mr-2">🔌</span>
                  Open Ports
                </h3>
                
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {results.results.nmap.open_ports.map((port, index) => (
                    <div key={index} className="bg-gray-700 border border-gray-600 rounded-lg p-4">
                      <div className="flex items-center justify-between">
                        <div className="text-lg font-semibold text-white">Port {port.port}</div>
                        <div className="text-sm bg-blue-600 px-2 py-1 rounded">{port.protocol}</div>
                      </div>
                      <div className="text-gray-400 mt-1">{port.service}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

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