import React, { useState, useEffect } from 'react';
import { Shield, Search, AlertTriangle, TrendingUp, Play, Settings, Download, ChevronRight, BarChart3, PieChart, Activity, Plus, Clock, CheckCircle, XCircle, Loader } from 'lucide-react';

export default function CyberSecurityDashboard() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedProject, setSelectedProject] = useState(null);
  const [selectedScan, setSelectedScan] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');

  const [projects, setProjects] = useState([
    { id: 1, name: 'Production Web Servers', assets: 12, lastScan: '2025-10-14', criticalVulns: 3 },
    { id: 2, name: 'Internal Network Scan', assets: 45, lastScan: '2025-10-13', criticalVulns: 7 },
    { id: 3, name: 'Cloud Infrastructure', assets: 28, lastScan: '2025-10-12', criticalVulns: 2 }
  ]);

  const [scans, setScans] = useState([
    { id: 1, project: 'Production Web Servers', target: '192.168.1.10', status: 'Completed', date: '2025-10-14 14:30', vulns: 15, progress: 100 },
    { id: 2, project: 'Internal Network Scan', target: '10.0.0.0/24', status: 'Running', date: '2025-10-15 09:15', progress: 65 },
    { id: 3, project: 'Cloud Infrastructure', target: 'api.example.com', status: 'Completed', date: '2025-10-13 22:45', vulns: 8, progress: 100 },
    { id: 4, project: 'Production Web Servers', target: 'web.example.com', status: 'Failed', date: '2025-10-12 18:20', progress: 0 }
  ]);

  const [vulnerabilities] = useState([
    { id: 1, cve: 'CVE-2023-12345', cvss: 9.8, severity: 'Critical', name: 'SQL Injection in Login Form', component: 'Web Application', status: 'open' },
    { id: 2, cve: 'CVE-2023-23456', cvss: 8.1, severity: 'High', name: 'Remote Code Execution', component: 'Apache Server', status: 'open' },
    { id: 3, cve: 'CVE-2023-34567', cvss: 7.5, severity: 'High', name: 'Cross-Site Scripting (XSS)', component: 'Web Application', status: 'open' },
    { id: 4, cve: 'CVE-2023-45678', cvss: 5.3, severity: 'Medium', name: 'Information Disclosure', component: 'Nginx', status: 'open' },
    { id: 5, cve: 'CVE-2023-56789', cvss: 3.7, severity: 'Low', name: 'Weak SSL/TLS Configuration', component: 'SSL Certificate', status: 'open' }
  ]);

  useEffect(() => {
    const interval = setInterval(() => {
      setScans(prevScans => prevScans.map(scan => {
        if (scan.status === 'Running' && scan.progress < 100) {
          const newProgress = Math.min(scan.progress + Math.random() * 10, 100);
          if (newProgress >= 100) {
            return { ...scan, progress: 100, status: 'Completed', vulns: Math.floor(Math.random() * 20) + 5 };
          }
          return { ...scan, progress: newProgress };
        }
        return scan;
      }));
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (severity) => {
    const colors = {
      'Critical': 'bg-red-600',
      'High': 'bg-orange-500',
      'Medium': 'bg-yellow-500',
      'Low': 'bg-blue-500'
    };
    return colors[severity] || 'bg-gray-500';
  };

  const getStatusIcon = (status) => {
    if (status === 'Completed') return <CheckCircle size={18} className="text-green-600" />;
    if (status === 'Running') return <Loader size={18} className="text-blue-600 animate-spin" />;
    if (status === 'Failed') return <XCircle size={18} className="text-red-600" />;
    return <Clock size={18} className="text-gray-600" />;
  };

  const filteredVulnerabilities = vulnerabilities.filter(v => {
    const matchesSearch = v.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
                         v.cve.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = severityFilter === 'all' || v.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const filteredScans = scans.filter(s => statusFilter === 'all' || s.status === statusFilter);

  const stats = {
    critical: vulnerabilities.filter(v => v.severity === 'Critical' && v.status === 'open').length,
    high: vulnerabilities.filter(v => v.severity === 'High' && v.status === 'open').length,
    medium: vulnerabilities.filter(v => v.severity === 'Medium' && v.status === 'open').length,
    low: vulnerabilities.filter(v => v.severity === 'Low' && v.status === 'open').length,
    total: vulnerabilities.filter(v => v.status === 'open').length
  };

  return (
    <div className="min-h-screen bg-gray-100">
      <nav className="bg-gradient-to-r from-indigo-600 to-blue-600 text-white shadow-lg">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield size={32} className="animate-pulse" />
              <div>
                <h1 className="text-xl font-bold">AI Cybersecurity Assistant</h1>
                <p className="text-xs opacity-90">Powered by Advanced Threat Intelligence</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <button className="p-2 hover:bg-white/10 rounded-lg transition">
                <Settings size={20} />
              </button>
              <div className="w-10 h-10 bg-white/20 rounded-full flex items-center justify-center font-semibold hover:bg-white/30 transition cursor-pointer">
                SA
              </div>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-6 py-6">
        <div className="flex gap-4 mb-6">
          <button onClick={() => setActiveTab('dashboard')} className={`px-6 py-2 rounded-lg font-medium transition-all ${activeTab === 'dashboard' ? 'bg-white shadow-lg text-blue-600' : 'bg-white/50 text-gray-600 hover:bg-white'}`}>
            Dashboard
          </button>
          <button onClick={() => setActiveTab('scans')} className={`px-6 py-2 rounded-lg font-medium transition-all ${activeTab === 'scans' ? 'bg-white shadow-lg text-blue-600' : 'bg-white/50 text-gray-600 hover:bg-white'}`}>
            Scans
          </button>
          <button onClick={() => setActiveTab('reports')} className={`px-6 py-2 rounded-lg font-medium transition-all ${activeTab === 'reports' ? 'bg-white shadow-lg text-blue-600' : 'bg-white/50 text-gray-600 hover:bg-white'}`}>
            Reports
          </button>
        </div>

        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            <div className="grid grid-cols-4 gap-4">
              <div className="bg-gradient-to-br from-red-500 to-red-600 rounded-lg p-6 text-white transform hover:scale-105 transition-transform cursor-pointer">
                <div className="flex items-center justify-between mb-2">
                  <AlertTriangle size={24} />
                  <span className="text-3xl font-bold">{stats.critical}</span>
                </div>
                <div className="text-sm opacity-90">Critical Vulnerabilities</div>
              </div>
              <div className="bg-gradient-to-br from-orange-500 to-orange-600 rounded-lg p-6 text-white transform hover:scale-105 transition-transform cursor-pointer">
                <div className="flex items-center justify-between mb-2">
                  <TrendingUp size={24} />
                  <span className="text-3xl font-bold">{projects.reduce((sum, p) => sum + p.assets, 0)}</span>
                </div>
                <div className="text-sm opacity-90">Total Assets</div>
              </div>
              <div className="bg-gradient-to-br from-blue-500 to-blue-600 rounded-lg p-6 text-white transform hover:scale-105 transition-transform cursor-pointer">
                <div className="flex items-center justify-between mb-2">
                  <Activity size={24} />
                  <span className="text-3xl font-bold">{stats.total}</span>
                </div>
                <div className="text-sm opacity-90">Open Vulnerabilities</div>
              </div>
              <div className="bg-gradient-to-br from-green-500 to-green-600 rounded-lg p-6 text-white transform hover:scale-105 transition-transform cursor-pointer">
                <div className="flex items-center justify-between mb-2">
                  <Shield size={24} />
                  <span className="text-3xl font-bold">{Math.max(0, 100 - stats.total * 2)}%</span>
                </div>
                <div className="text-sm opacity-90">Security Score</div>
              </div>
            </div>

            <div className="grid grid-cols-3 gap-6">
              <div className="col-span-2 bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center">
                  <BarChart3 size={20} className="mr-2" />
                  Recent Scan Activity
                </h3>
                <div className="space-y-3">
                  {scans.slice(0, 4).map(scan => (
                    <div key={scan.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-blue-50 hover:shadow-md cursor-pointer transition-all">
                      <div className="flex items-center gap-3 flex-1">
                        {getStatusIcon(scan.status)}
                        <div>
                          <div className="font-medium">{scan.target}</div>
                          <div className="text-sm text-gray-500">{scan.project}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="text-sm text-gray-600">{scan.date}</div>
                        {scan.status === 'Running' && (
                          <div className="w-32 bg-gray-200 rounded-full h-2">
                            <div className="bg-blue-500 h-2 rounded-full transition-all duration-500" style={{width: `${scan.progress}%`}}></div>
                          </div>
                        )}
                        {scan.status === 'Completed' && (
                          <div className="px-3 py-1 bg-green-100 text-green-700 rounded-full text-sm font-medium">
                            {scan.vulns} found
                          </div>
                        )}
                        <ChevronRight size={20} className="text-gray-400" />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center">
                  <PieChart size={20} className="mr-2" />
                  Vulnerability Distribution
                </h3>
                <div className="space-y-4">
                  <div className="flex items-center justify-between hover:bg-gray-50 p-2 rounded transition cursor-pointer">
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 rounded-full bg-red-600"></div>
                      <span className="text-sm">Critical</span>
                    </div>
                    <span className="font-semibold text-red-600">{stats.critical}</span>
                  </div>
                  <div className="flex items-center justify-between hover:bg-gray-50 p-2 rounded transition cursor-pointer">
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 rounded-full bg-orange-500"></div>
                      <span className="text-sm">High</span>
                    </div>
                    <span className="font-semibold text-orange-500">{stats.high}</span>
                  </div>
                  <div className="flex items-center justify-between hover:bg-gray-50 p-2 rounded transition cursor-pointer">
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                      <span className="text-sm">Medium</span>
                    </div>
                    <span className="font-semibold text-yellow-600">{stats.medium}</span>
                  </div>
                  <div className="flex items-center justify-between hover:bg-gray-50 p-2 rounded transition cursor-pointer">
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 rounded-full bg-blue-500"></div>
                      <span className="text-sm">Low</span>
                    </div>
                    <span className="font-semibold text-blue-600">{stats.low}</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Projects</h3>
                <button className="bg-blue-600 text-white px-4 py-2 rounded-lg flex items-center gap-2 hover:bg-blue-700 transition text-sm">
                  <Plus size={16} />
                  New Project
                </button>
              </div>
              <div className="grid grid-cols-3 gap-4">
                {projects.map(project => (
                  <div key={project.id} className="border-2 rounded-lg p-4 hover:border-blue-500 hover:shadow-lg cursor-pointer transition-all transform hover:-translate-y-1">
                    <div className="font-semibold mb-3">{project.name}</div>
                    <div className="text-sm text-gray-600 space-y-2">
                      <div className="flex justify-between">
                        <span>Assets:</span>
                        <span className="font-medium">{project.assets}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Last Scan:</span>
                        <span className="font-medium">{project.lastScan}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span>Critical:</span>
                        <span className="px-2 py-1 bg-red-100 text-red-700 rounded text-xs font-bold">{project.criticalVulns}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'scans' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">Vulnerability Scans</h2>
              <button className="bg-blue-600 text-white px-4 py-2 rounded-lg flex items-center gap-2 hover:bg-blue-700 transition shadow-lg hover:shadow-xl">
                <Play size={18} />
                New Scan
              </button>
            </div>

            <div className="bg-white rounded-lg shadow">
              <div className="p-4 border-b">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={20} />
                    <input type="text" placeholder="Search targets..." className="w-full pl-10 pr-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
                  </div>
                  <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                    <option value="all">All Status</option>
                    <option value="Running">Running</option>
                    <option value="Completed">Completed</option>
                    <option value="Failed">Failed</option>
                  </select>
                </div>
              </div>
              <div className="divide-y">
                {filteredScans.map(scan => (
                  <div key={scan.id} className="p-4 hover:bg-blue-50 cursor-pointer transition-all">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {getStatusIcon(scan.status)}
                        <div>
                          <div className="font-semibold">{scan.target}</div>
                          <div className="text-sm text-gray-500">{scan.project} • {scan.date}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        {scan.status === 'Running' ? (
                          <div className="flex items-center gap-3">
                            <div className="w-40 bg-gray-200 rounded-full h-2.5">
                              <div className="bg-blue-500 h-2.5 rounded-full transition-all duration-500" style={{width: `${scan.progress}%`}}></div>
                            </div>
                            <span className="text-sm text-gray-600 font-medium w-12">{Math.round(scan.progress)}%</span>
                          </div>
                        ) : scan.status === 'Completed' ? (
                          <div className="text-sm font-medium text-gray-600">{scan.vulns} vulnerabilities</div>
                        ) : (
                          <div className="text-sm text-red-600 font-medium">Scan failed</div>
                        )}
                        <ChevronRight size={20} className="text-gray-400" />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'reports' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <div>
                <h2 className="text-2xl font-bold">Scan Report</h2>
                {selectedScan && <p className="text-gray-600">{selectedScan.target} • {selectedScan.date}</p>}
              </div>
              <div className="flex gap-2">
                <button className="px-4 py-2 border rounded-lg flex items-center gap-2 hover:bg-gray-50 transition shadow hover:shadow-md">
                  <Download size={18} />
                  Export PDF
                </button>
                <button className="px-4 py-2 border rounded-lg flex items-center gap-2 hover:bg-gray-50 transition shadow hover:shadow-md">
                  <Download size={18} />
                  Export CSV
                </button>
              </div>
            </div>

            <div className="grid grid-cols-4 gap-4">
              <div className="bg-red-50 border-2 border-red-200 rounded-lg p-4 hover:shadow-lg transition transform hover:-translate-y-1 cursor-pointer">
                <div className="text-3xl font-bold text-red-700">{stats.critical}</div>
                <div className="text-sm text-red-600 font-medium">Critical</div>
              </div>
              <div className="bg-orange-50 border-2 border-orange-200 rounded-lg p-4 hover:shadow-lg transition transform hover:-translate-y-1 cursor-pointer">
                <div className="text-3xl font-bold text-orange-700">{stats.high}</div>
                <div className="text-sm text-orange-600 font-medium">High</div>
              </div>
              <div className="bg-yellow-50 border-2 border-yellow-200 rounded-lg p-4 hover:shadow-lg transition transform hover:-translate-y-1 cursor-pointer">
                <div className="text-3xl font-bold text-yellow-700">{stats.medium}</div>
                <div className="text-sm text-yellow-600 font-medium">Medium</div>
              </div>
              <div className="bg-blue-50 border-2 border-blue-200 rounded-lg p-4 hover:shadow-lg transition transform hover:-translate-y-1 cursor-pointer">
                <div className="text-3xl font-bold text-blue-700">{stats.low}</div>
                <div className="text-sm text-blue-600 font-medium">Low</div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow">
              <div className="p-4 border-b bg-gray-50">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={20} />
                    <input 
                      type="text" 
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      placeholder="Search vulnerabilities..." 
                      className="w-full pl-10 pr-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent" 
                    />
                  </div>
                  <select 
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    className="px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    <option value="all">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-4 py-3 text-left text-sm font-semibold">CVE ID</th>
                      <th className="px-4 py-3 text-left text-sm font-semibold">Vulnerability</th>
                      <th className="px-4 py-3 text-left text-sm font-semibold">Component</th>
                      <th className="px-4 py-3 text-left text-sm font-semibold">CVSS</th>
                      <th className="px-4 py-3 text-left text-sm font-semibold">Severity</th>
                      <th className="px-4 py-3 text-left text-sm font-semibold">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {filteredVulnerabilities.map(vuln => (
                      <tr key={vuln.id} className="hover:bg-blue-50 transition">
                        <td className="px-4 py-3 text-sm font-mono text-blue-600">{vuln.cve}</td>
                        <td className="px-4 py-3 text-sm font-medium">{vuln.name}</td>
                        <td className="px-4 py-3 text-sm text-gray-600">{vuln.component}</td>
                        <td className="px-4 py-3 text-sm font-bold">{vuln.cvss}</td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium text-white ${getSeverityColor(vuln.severity)}`}>
                            {vuln.severity}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          {vuln.status === 'resolved' ? (
                            <span className="px-2 py-1 bg-green-100 text-green-700 rounded-full text-xs font-medium">Resolved</span>
                          ) : (
                            <span className="px-2 py-1 bg-red-100 text-red-700 rounded-full text-xs font-medium">Open</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}