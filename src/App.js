import React, { useState, useEffect, useRef } from 'react';
import { Shield, Search, AlertTriangle, TrendingUp, Play, Settings, Download, ChevronRight, BarChart3, PieChart, Activity, Plus, Clock, CheckCircle, XCircle, Loader, X, MessageCircle, Send, Terminal, Trash2, Eye, ChevronLeft, Calendar, Filter, FileText, User, LogOut, Bell, Pause, StopCircle, RefreshCw, AlertCircle, Info } from 'lucide-react';

export default function CyberSecurityDashboard() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedProject, setSelectedProject] = useState(null);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [isCreatingProject, setIsCreatingProject] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [showNewScanModal, setShowNewScanModal] = useState(false);
  const [showScanOutput, setShowScanOutput] = useState(false);
  const [scanOutput, setScanOutput] = useState([]);
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState([
    { role: 'assistant', content: 'Hello! I\'m your AI Security Assistant. Ask me anything about vulnerabilities, exploits, or remediation steps.' }
  ]);
  const [chatInput, setChatInput] = useState('');
  const chatMessagesEndRef = useRef(null);
  const [showScheduleScanModal, setShowScheduleScanModal] = useState(false);
  const [selectedScanForLogs, setSelectedScanForLogs] = useState(null);
  const [newTarget, setNewTarget] = useState('');
  const [toast, setToast] = useState({ show: false, message: '', type: 'success' });
  const [scheduleScanData, setScheduleScanData] = useState({
    target: '',
    frequency: 'daily',
    time: '00:00',
    timezone: 'Asia/Kolkata'
  });
  const [showSettings, setShowSettings] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [reportFormat, setReportFormat] = useState('pdf');
  const [notifications, setNotifications] = useState([
    { id: 1, message: 'Critical vulnerability found in Production Web Servers', time: '5m ago', read: false },
    { id: 2, message: 'Scan completed for api.example.com', time: '1h ago', read: false },
    { id: 3, message: 'New security update available', time: '3h ago', read: true }
  ]);
  const [showNotifications, setShowNotifications] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(25);
  const [sortField, setSortField] = useState('cvss');
  const [sortDirection, setSortDirection] = useState('desc');
  const [selectedVulns, setSelectedVulns] = useState(new Set());
  const [bulkAction, setBulkAction] = useState('');

  const [newScanData, setNewScanData] = useState({
    target: '',
    portRange: '1-1000',
    profile: 'standard',
    tools: { 
      nmap: true, 
      nikto: false, 
      sqlmap: false, 
      nuclei: true,
      openvas: false,
      nessus: false
    }
  });

  const [projects, setProjects] = useState([
    { id: 1, name: 'Production Web Servers', assets: 12, targets: ['192.168.1.10', 'web.example.com', '192.168.1.20'], lastScan: '2025-10-14', criticalVulns: 3, riskScore: 7.8 },
    { id: 2, name: 'Internal Network Scan', assets: 45, targets: ['10.0.0.0/24'], lastScan: '2025-10-13', criticalVulns: 7, riskScore: 8.5 },
    { id: 3, name: 'Cloud Infrastructure', assets: 28, targets: ['api.example.com', 'cdn.example.com'], lastScan: '2025-10-12', criticalVulns: 2, riskScore: 5.2 }
  ]);

  const [scans, setScans] = useState([
    { id: 1, project: 'Production Web Servers', target: '192.168.1.10', status: 'Completed', date: '2025-10-14 14:30', vulns: 15, progress: 100, duration: '12m 34s', profile: 'standard' },
    { id: 2, project: 'Internal Network Scan', target: '10.0.0.0/24', status: 'Running', date: '2025-10-15 09:15', progress: 65, profile: 'comprehensive' },
    { id: 3, project: 'Cloud Infrastructure', target: 'api.example.com', status: 'Completed', date: '2025-10-13 22:45', vulns: 8, progress: 100, duration: '8m 12s', profile: 'quick' },
    { id: 4, project: 'Production Web Servers', target: 'web.example.com', status: 'Failed', date: '2025-10-12 18:20', progress: 0, profile: 'standard' }
  ]);

  const [vulnerabilities, setVulnerabilities] = useState([
    {
      id: 1,
      cve: 'CVE-2023-12345',
      cvss: 9.8,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      severity: 'Critical',
      name: 'SQL Injection in Login Form',
      component: 'Web Application',
      affectedVersion: '2.1.0-3.4.5',
      status: 'new',
      discoveryDate: '2025-10-14',
      description: 'A critical SQL injection vulnerability exists in the login authentication mechanism. Attackers can bypass authentication and gain unauthorized access to the database.',
      remediation: 'Use parameterized queries or prepared statements. Implement input validation and sanitization. Apply principle of least privilege to database accounts.',
      references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-12345', 'https://www.exploit-db.com/exploits/51234'],
      proofOfConcept: 'Username: admin\' OR \'1\'=\'1',
      relatedCves: ['CVE-2023-12346', 'CVE-2022-54321']
    },
    {
      id: 2,
      cve: 'CVE-2023-23456',
      cvss: 8.1,
      cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
      severity: 'High',
      name: 'Remote Code Execution',
      component: 'Apache Server',
      affectedVersion: '2.4.49-2.4.57',
      status: 'in_progress',
      discoveryDate: '2025-10-13',
      description: 'A buffer overflow vulnerability in Apache HTTP Server allows remote attackers to execute arbitrary code on the target system.',
      remediation: 'Upgrade to Apache version 2.4.58 or later. Implement web application firewall rules to detect exploitation attempts.',
      references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-23456'],
      proofOfConcept: 'Available',
      relatedCves: ['CVE-2023-23457']
    },
    {
      id: 3,
      cve: 'CVE-2023-34567',
      cvss: 7.5,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      severity: 'High',
      name: 'Cross-Site Scripting (XSS)',
      component: 'Web Application',
      affectedVersion: '1.0.0-2.3.1',
      status: 'new',
      discoveryDate: '2025-10-12',
      description: 'Reflected XSS vulnerability allows attackers to inject malicious scripts that execute in victim browsers.',
      remediation: 'Implement Content Security Policy (CSP). Sanitize all user inputs. Use context-aware output encoding.',
      references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-34567', 'https://owasp.org/www-community/attacks/xss/'],
      proofOfConcept: '<script>alert("XSS")</script>',
      relatedCves: []
    },
    {
      id: 4,
      cve: 'CVE-2023-45678',
      cvss: 5.3,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
      severity: 'Medium',
      name: 'Information Disclosure',
      component: 'Nginx',
      affectedVersion: '1.18.0-1.20.2',
      status: 'resolved',
      discoveryDate: '2025-10-11',
      description: 'Server configuration allows directory listing, exposing sensitive file structure and potentially confidential files.',
      remediation: 'Disable directory listing in Nginx configuration. Remove or protect sensitive files. Implement proper access controls.',
      references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-45678'],
      proofOfConcept: 'N/A',
      relatedCves: []
    },
    {
      id: 5,
      cve: 'CVE-2023-56789',
      cvss: 3.7,
      cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
      severity: 'Low',
      name: 'Weak SSL/TLS Configuration',
      component: 'SSL Certificate',
      affectedVersion: 'TLS 1.0/1.1',
      status: 'new',
      discoveryDate: '2025-10-10',
      description: 'Server supports outdated TLS 1.0 and weak cipher suites, making it vulnerable to cryptographic attacks.',
      remediation: 'Disable TLS 1.0 and 1.1. Configure server to use only TLS 1.2 and 1.3 with strong cipher suites.',
      references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-56789', 'https://ssl-config.mozilla.org/'],
      proofOfConcept: 'N/A',
      relatedCves: []
    }
  ]);

  const scanProfiles = {
    quick: { duration: '5-10 minutes', description: 'Fast scan of common ports and services' },
    standard: { duration: '15-30 minutes', description: 'Comprehensive scan with vulnerability detection' },
    comprehensive: { duration: '45-90 minutes', description: 'Deep analysis with extensive testing' }
  };

  const mockNmapOutput = [
    'Starting Nmap 7.94 ( https://nmap.org ) at 2025-10-15 10:30 IST',
    'Nmap scan report for TARGET',
    'Host is up (0.012s latency).',
    'Not shown: 996 filtered ports',
    'PORT      STATE SERVICE       VERSION',
    '22/tcp    open  ssh           OpenSSH 8.2p1',
    '80/tcp    open  http          Apache httpd 2.4.41',
    '443/tcp   open  https         Apache httpd 2.4.41',
    '3306/tcp  open  mysql         MySQL 8.0.26',
    '',
    'Service detection performed. Please report any incorrect results.',
    'Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds'
  ];

  const suggestedQuestions = [
    'Show me all critical vulnerabilities',
    'How do I remediate the SQL injection?',
    'What are the attack paths for high severity issues?',
    'Explain CVE-2023-12345 in detail',
    'Generate executive summary of findings'
  ];

  useEffect(() => {
    chatMessagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatMessages]);

  useEffect(() => {
    const interval = setInterval(() => {
      setScans(prevScans => prevScans.map(scan => {
        if (scan.status === 'Running' && scan.progress < 100) {
          const newProgress = Math.min(scan.progress + Math.random() * 10, 100);
          if (newProgress >= 100) {
            showToast('Scan completed successfully!', 'success');
            return { ...scan, progress: 100, status: 'Completed', vulns: Math.floor(Math.random() * 20) + 5, duration: `${Math.floor(Math.random() * 30)}m ${Math.floor(Math.random() * 60)}s` };
          }
          return { ...scan, progress: newProgress };
        }
        return scan;
      }));
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const showToast = (message, type = 'success') => {
    setToast({ show: true, message, type });
    setTimeout(() => {
      setToast({ show: false, message: '', type: 'success' });
    }, 3000);
  };

  const handleCreateProject = () => {
    if (newProjectName.trim() !== '') {
      const newProject = {
        id: projects.length + 1,
        name: newProjectName,
        assets: 0,
        targets: [],
        lastScan: 'Never',
        criticalVulns: 0,
        riskScore: 0
      };
      setProjects([...projects, newProject]);
      setNewProjectName('');
      setIsCreatingProject(false);
      showToast(`Project "${newProjectName}" created successfully!`);
    }
  };

  const handleDeleteProject = (id) => {
    const projectName = projects.find(p => p.id === id)?.name || 'Project';
    setProjects(projects.filter(p => p.id !== id));
    if (selectedProject?.id === id) setSelectedProject(null);
    showToast(`${projectName} has been deleted.`);
  };

  const validateTarget = (target) => {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
    const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/\d{1,2}$/;
    
    return ipRegex.test(target) || domainRegex.test(target) || cidrRegex.test(target);
  };

  const handleStartScan = () => {
    if (!newScanData.target) {
      showToast("Error: Target cannot be empty.", 'error');
      return;
    }
    if (!validateTarget(newScanData.target)) {
      showToast("Error: Invalid target format.", 'error');
      return;
    }

    const selectedTools = Object.entries(newScanData.tools)
      .filter(([_, selected]) => selected)
      .map(([tool, _]) => tool);

    if (selectedTools.length === 0) {
      showToast("Error: Please select at least one scanning tool.", 'error');
      return;
    }

    const newScan = {
      id: scans.length + 1,
      project: selectedProject ? selectedProject.name : 'Quick Scan',
      target: newScanData.target,
      status: 'Running',
      date: new Date().toLocaleString('en-GB', {
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit'
      }).replace(',', ''),
      progress: 0,
      profile: newScanData.profile
    };
    setScans([newScan, ...scans]);
    setShowNewScanModal(false);
    setShowScanOutput(true);
    
    let output = [];
    mockNmapOutput.forEach((line, idx) => {
      setTimeout(() => {
        output.push(line.replace('TARGET', newScanData.target));
        setScanOutput([...output]);
      }, idx * 300);
    });
    
    setTimeout(() => setShowScanOutput(false), mockNmapOutput.length * 300 + 1000);
    setNewScanData({ 
      target: '', 
      portRange: '1-1000',
      profile: 'standard', 
      tools: { nmap: true, nikto: false, sqlmap: false, nuclei: true, openvas: false, nessus: false } 
    });
    showToast(`Scan started on ${newScan.target}`);
  };

  const handlePauseScan = (scanId) => {
    setScans(scans.map(s => s.id === scanId && s.status === 'Running' ? { ...s, status: 'Paused' } : s));
    showToast('Scan paused');
  };

  const handleResumeScan = (scanId) => {
    setScans(scans.map(s => s.id === scanId && s.status === 'Paused' ? { ...s, status: 'Running' } : s));
    showToast('Scan resumed');
  };

  const handleCancelScan = (scanId) => {
    setScans(scans.map(s => s.id === scanId ? { ...s, status: 'Cancelled', progress: 0 } : s));
    showToast('Scan cancelled');
  };

  const handleSendMessage = () => {
    if (!chatInput.trim()) return;
    
    const newMessages = [...chatMessages, { role: 'user', content: chatInput }];
    setChatMessages(newMessages);
    
    setTimeout(() => {
      let response = '';
      const input = chatInput.toLowerCase();
      
      if (input.includes('critical') || input.includes('show') && input.includes('vulnerabilities')) {
        const criticalVulns = vulnerabilities.filter(v => v.severity === 'Critical' && v.status !== 'resolved');
        response = `You currently have ${criticalVulns.length} critical vulnerabilities:\n\n${criticalVulns.map(v => `• ${v.cve}: ${v.name} (CVSS ${v.cvss})`).join('\n')}\n\nI recommend prioritizing ${criticalVulns[0]?.cve} for immediate remediation due to its ${criticalVulns[0]?.cvss} CVSS score.`;
      } else if (input.includes('sql') || input.includes('injection')) {
        response = 'SQL Injection (CVE-2023-12345) is critical. **Remediation Steps:**\n\n1. Use parameterized queries/prepared statements\n2. Implement input validation with allowlists\n3. Apply principle of least privilege to database accounts\n4. Enable WAF rules to detect SQL injection patterns\n5. Conduct code review of authentication module\n\n**Testing:** Use tools like SQLMap for validation after fixes.';
      } else if (input.includes('remediation') || input.includes('fix')) {
        response = '**Priority Remediation Plan:**\n\n**Immediate (24h):**\n• Patch CVE-2023-12345 (SQL Injection)\n• Implement WAF rules\n\n**Short-term (1 week):**\n• Upgrade Apache to 2.4.58+\n• Fix XSS vulnerabilities\n\n**Medium-term (1 month):**\n• Address information disclosure\n• Update SSL/TLS configuration\n\nWould you like detailed steps for any specific vulnerability?';
      } else if (input.includes('attack path') || input.includes('exploit chain')) {
        response = '**Attack Path Analysis:**\n\n1. **Initial Access:** SQL Injection (CVE-2023-12345) → Database compromise\n2. **Lateral Movement:** Weak credentials → Access to Apache server\n3. **Privilege Escalation:** Apache RCE (CVE-2023-23456) → Root access\n4. **Impact:** Full system compromise, data exfiltration\n\n**Risk Score:** 9.2/10 - Critical path requiring immediate attention.';
      } else if (input.includes('cve-2023-12345') || input.includes('explain')) {
        response = '**CVE-2023-12345 Analysis:**\n\n**Type:** SQL Injection\n**CVSS:** 9.8 (Critical)\n**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n\n**Exploitation:** Unauthenticated attackers can bypass login by injecting SQL commands in username/password fields.\n\n**Impact:** Complete database compromise, authentication bypass, data theft.\n\n**Remediation:** Implement parameterized queries immediately.';
      } else if (input.includes('executive') || input.includes('summary')) {
        response = '**Executive Security Summary**\n\n📊 **Overall Risk Score:** 7.8/10\n\n**Key Findings:**\n• 3 Critical vulnerabilities requiring immediate action\n• 2 High-severity issues in production systems\n• Primary risk: SQL Injection in authentication\n\n**Recommendations:**\n1. Emergency patching of critical vulnerabilities\n2. Implement WAF protection\n3. Security code review\n\n**Timeline:** 24-48 hours for critical remediation';
      } else {
        response = 'I can help you with:\n\n• Vulnerability analysis and explanations\n• Remediation guidance\n• Attack path visualization\n• CVSS score interpretation\n• Security best practices\n\nTry asking about specific CVEs or use one of the suggested questions below!';
      }
      
      setChatMessages([...newMessages, { 
        role: 'assistant', 
        content: response,
        citations: ['NVD Database', 'OWASP Top 10', 'Internal Scan Results']
      }]);
    }, 800);
    
    setChatInput('');
  };

  const handleAddTarget = () => {
    if (!newTarget.trim() || !selectedProject) return;
    
    if (!validateTarget(newTarget.trim())) {
      showToast("Invalid target format", 'error');
      return;
    }

    const updatedProjects = projects.map(p => {
      if (p.id === selectedProject.id) {
        const newTargets = [...p.targets, newTarget.trim()];
        return { ...p, targets: newTargets, assets: newTargets.length };
      }
      return p;
    });
    setProjects(updatedProjects);
    setSelectedProject(updatedProjects.find(p => p.id === selectedProject.id));
    showToast(`Target "${newTarget.trim()}" added to ${selectedProject.name}.`);
    setNewTarget('');
  };

  const handleScheduleScan = () => {
    if (!scheduleScanData.target || !validateTarget(scheduleScanData.target)) {
      showToast("Invalid target", 'error');
      return;
    }
    setShowScheduleScanModal(false);
    showToast(`Scan for "${scheduleScanData.target}" scheduled ${scheduleScanData.frequency} at ${scheduleScanData.time} ${scheduleScanData.timezone}.`);
    setScheduleScanData({ target: '', frequency: 'daily', time: '00:00', timezone: 'Asia/Kolkata' });
  };

  const handleExport = (format) => {
    showToast(`Exporting ${format.toUpperCase()} report... Download will start shortly.`);
    setTimeout(() => {
      showToast(`${format.toUpperCase()} report exported successfully!`, 'success');
    }, 2000);
  };

  const handleBulkAction = () => {
    if (!bulkAction || selectedVulns.size === 0) return;
    
    if (bulkAction === 'mark-resolved') {
      setVulnerabilities(vulnerabilities.map(v => 
        selectedVulns.has(v.id) ? { ...v, status: 'resolved' } : v
      ));
      showToast(`${selectedVulns.size} vulnerabilities marked as resolved`);
    } else if (bulkAction === 'mark-progress') {
      setVulnerabilities(vulnerabilities.map(v => 
        selectedVulns.has(v.id) ? { ...v, status: 'in_progress' } : v
      ));
      showToast(`${selectedVulns.size} vulnerabilities marked as in progress`);
    }
    
    setSelectedVulns(new Set());
    setBulkAction('');
  };

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'Critical': 'bg-red-600',
      'High': 'bg-orange-500',
      'Medium': 'bg-yellow-500',
      'Low': 'bg-blue-500',
      'Info': 'bg-gray-500'
    };
    return colors[severity] || 'bg-gray-500';
  };

  const getStatusIcon = (status) => {
    if (status === 'Completed') return <CheckCircle size={18} className="text-green-600" />;
    if (status === 'Running') return <Loader size={18} className="text-blue-600 animate-spin" />;
    if (status === 'Paused') return <Pause size={18} className="text-yellow-600" />;
    if (status === 'Failed' || status === 'Cancelled') return <XCircle size={18} className="text-red-600" />;
    return <Clock size={18} className="text-gray-600" />;
  };

  const filteredVulnerabilities = vulnerabilities
    .filter(v => {
      const matchesSearch = v.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                            v.cve.toLowerCase().includes(searchTerm.toLowerCase()) ||
                            v.component.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesSeverity = severityFilter === 'all' || v.severity === severityFilter;
      return matchesSearch && matchesSeverity;
    })
    .sort((a, b) => {
      let aVal = a[sortField];
      let bVal = b[sortField];
      if (sortField === 'cvss') {
        return sortDirection === 'asc' ? aVal - bVal : bVal - aVal;
      }
      if (typeof aVal === 'string') {
        return sortDirection === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
      }
      return 0;
    });

  const paginatedVulnerabilities = filteredVulnerabilities.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  const totalPages = Math.ceil(filteredVulnerabilities.length / itemsPerPage);

  const filteredScans = scans.filter(s => statusFilter === 'all' || s.status === statusFilter);

  const stats = {
    critical: vulnerabilities.filter(v => v.severity === 'Critical' && v.status !== 'resolved').length,
    high: vulnerabilities.filter(v => v.severity === 'High' && v.status !== 'resolved').length,
    medium: vulnerabilities.filter(v => v.severity === 'Medium' && v.status !== 'resolved').length,
    low: vulnerabilities.filter(v => v.severity === 'Low' && v.status !== 'resolved').length,
    total: vulnerabilities.filter(v => v.status !== 'resolved').length,
    activeScans: scans.filter(s => s.status === 'Running').length
  };

  const maxStat = Math.max(stats.critical, stats.high, stats.medium, stats.low, 1);
  const unreadNotifications = notifications.filter(n => !n.read).length;

  return (
    <div className="min-h-screen bg-gray-100">
      <nav className="bg-gradient-to-r from-indigo-600 to-blue-600 text-white shadow-lg">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield size={32} className="animate-pulse" />
              <div>
                <h1 className="text-xl font-bold">Cybersecurity Vulnerability Management</h1>
                <p className="text-xs opacity-90">AI-Powered Security Intelligence Platform</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="relative">
                <button 
                  onClick={() => setShowNotifications(!showNotifications)}
                  className="p-2 hover:bg-white/10 rounded-lg transition relative"
                >
                  <Bell size={20} />
                  {unreadNotifications > 0 && (
                    <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full w-5 h-5 flex items-center justify-center">
                    {unreadNotifications}
                  </span>
                )}
                </button>
                {showNotifications && (
                  <div className="absolute right-0 mt-2 w-80 bg-white text-gray-800 rounded-lg shadow-xl z-50">
                    <div className="p-4 border-b">
                      <h3 className="font-semibold">Notifications</h3>
                    </div>
                    <div className="max-h-96 overflow-y-auto">
                      {notifications.map(notif => (
                        <div key={notif.id} className={`p-4 border-b hover:bg-gray-50 cursor-pointer ${!notif.read ? 'bg-blue-50' : ''}`}>
                          <p className="text-sm">{notif.message}</p>
                          <p className="text-xs text-gray-500 mt-1">{notif.time}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              <button 
                onClick={() => setShowSettings(true)}
                className="p-2 hover:bg-white/10 rounded-lg transition"
              >
                <Settings size={20} />
              </button>
              <div className="relative">
                <button 
                  onClick={() => setShowUserMenu(!showUserMenu)}
                  className="w-10 h-10 bg-white/20 rounded-full flex items-center justify-center font-semibold hover:bg-white/30 transition cursor-pointer"
                >
                  SA
                </button>
                {showUserMenu && (
                  <div className="absolute right-0 mt-2 w-48 bg-white text-gray-800 rounded-lg shadow-xl z-50">
                    <div className="p-2">
                      <button className="w-full text-left px-4 py-2 hover:bg-gray-100 rounded flex items-center gap-2">
                        <User size={16} />
                        Profile
                      </button>
                      <button className="w-full text-left px-4 py-2 hover:bg-gray-100 rounded flex items-center gap-2">
                        <Settings size={16} />
                        Settings
                      </button>
                      <hr className="my-2" />
                      <button className="w-full text-left px-4 py-2 hover:bg-gray-100 rounded flex items-center gap-2 text-red-600">
                        <LogOut size={16} />
                        Logout
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-6 py-6">
        <div className="flex gap-4 mb-6">
          <button 
            onClick={() => { setActiveTab('dashboard'); setSelectedProject(null); }} 
            className={`px-6 py-2 rounded-lg font-medium transition-all ${activeTab === 'dashboard' ? 'bg-white shadow-lg text-blue-600' : 'bg-white/50 text-gray-600 hover:bg-white'}`}
          >
            Dashboard
          </button>
          <button 
            onClick={() => setActiveTab('scans')} 
            className={`px-6 py-2 rounded-lg font-medium transition-all ${activeTab === 'scans' ? 'bg-white shadow-lg text-blue-600' : 'bg-white/50 text-gray-600 hover:bg-white'}`}
          >
            Scans
          </button>
          <button 
            onClick={() => setActiveTab('reports')} 
            className={`px-6 py-2 rounded-lg font-medium transition-all ${activeTab === 'reports' ? 'bg-white shadow-lg text-blue-600' : 'bg-white/50 text-gray-600 hover:bg-white'}`}
          >
            Reports
          </button>
        </div>

        {activeTab === 'dashboard' && !selectedProject && (
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
                  <span className="text-3xl font-bold">{stats.activeScans}</span>
                </div>
                <div className="text-sm opacity-90">Active Scans</div>
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
                    <div 
                      key={scan.id} 
                      onClick={() => setSelectedScanForLogs(scan)} 
                      className="flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-blue-50 hover:shadow-md cursor-pointer transition-all"
                    >
                      <div className="flex items-center gap-3 flex-1">
                        {getStatusIcon(scan.status)}
                        <div>
                          <div className="font-medium">{scan.target}</div>
                          <div className="text-sm text-gray-500">{scan.project} • {scan.profile}</div>
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
                <div className="h-48 flex items-end justify-around gap-4 pt-4">
                  {[
                    { label: 'Crit', value: stats.critical, color: 'bg-red-500' },
                    { label: 'High', value: stats.high, color: 'bg-orange-500' },
                    { label: 'Med', value: stats.medium, color: 'bg-yellow-500' },
                    { label: 'Low', value: stats.low, color: 'bg-blue-500' }
                  ].map(item => (
                    <div key={item.label} className="flex flex-col items-center flex-1 h-full justify-end">
                      <div className="text-sm font-bold">{item.value}</div>
                      <div 
                        className={`w-full rounded-t-md hover:opacity-80 transition-all ${item.color}`}
                        style={{ height: `${(item.value / maxStat) * 100}%`, minHeight: '8px' }}
                        title={`${item.label}: ${item.value}`}
                      ></div>
                      <div className="text-xs text-gray-500 mt-1">{item.label}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Projects</h3>
                <button 
                  onClick={() => setIsCreatingProject(true)} 
                  className="bg-blue-600 text-white px-4 py-2 rounded-lg flex items-center gap-2 hover:bg-blue-700 transition text-sm"
                >
                  <Plus size={16} />
                  New Project
                </button>
              </div>
              {isCreatingProject && (
                <div className="mb-4 p-4 bg-gray-50 rounded-lg">
                  <input
                    type="text"
                    value={newProjectName}
                    onChange={(e) => setNewProjectName(e.target.value)}
                    placeholder="Enter project name"
                    className="border rounded-lg px-4 py-2 w-full mb-2"
                    onKeyPress={(e) => e.key === 'Enter' && handleCreateProject()}
                  />
                  <div className="flex gap-2">
                    <button 
                      onClick={handleCreateProject} 
                      className="bg-green-500 text-white px-4 py-2 rounded-lg hover:bg-green-600 transition"
                    >
                      Create
                    </button>
                    <button 
                      onClick={() => setIsCreatingProject(false)} 
                      className="bg-gray-300 px-4 py-2 rounded-lg hover:bg-gray-400 transition"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
              <div className="grid grid-cols-3 gap-4">
                {projects.map(project => (
                  <div 
                    key={project.id} 
                    className="border-2 rounded-lg p-4 hover:border-blue-500 hover:shadow-lg cursor-pointer transition-all transform hover:-translate-y-1"
                  >
                    <div className="flex justify-between items-start mb-3">
                      <div className="font-semibold flex-1">{project.name}</div>
                      <div className="flex gap-2">
                        <button 
                          onClick={() => setSelectedProject(project)} 
                          className="p-1 hover:bg-blue-100 rounded transition"
                        >
                          <Eye size={16} className="text-blue-600" />
                        </button>
                        <button 
                          onClick={(e) => { e.stopPropagation(); handleDeleteProject(project.id); }} 
                          className="p-1 hover:bg-red-100 rounded transition"
                        >
                          <Trash2 size={16} className="text-red-600" />
                        </button>
                      </div>
                    </div>
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
                        <span>Risk Score:</span>
                        <span className={`px-2 py-1 rounded text-xs font-bold ${project.riskScore >= 7 ? 'bg-red-100 text-red-700' : project.riskScore >= 5 ? 'bg-yellow-100 text-yellow-700' : 'bg-green-100 text-green-700'}`}>
                          {project.riskScore}/10
                        </span>
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

        {activeTab === 'dashboard' && selectedProject && (
          <div className="space-y-6">
            <div className="flex items-center gap-4 mb-6">
              <button 
                onClick={() => setSelectedProject(null)} 
                className="p-2 hover:bg-white rounded-lg transition"
              >
                <ChevronLeft size={20} />
              </button>
              <div>
                <h2 className="text-2xl font-bold">{selectedProject.name}</h2>
                <p className="text-gray-600">Project Details & Management</p>
              </div>
            </div>

            <div className="grid grid-cols-4 gap-4">
              <div className="bg-white rounded-lg shadow p-6">
                <div className="text-3xl font-bold text-blue-600 mb-2">{selectedProject.assets}</div>
                <div className="text-sm text-gray-600">Total Assets</div>
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <div className="text-3xl font-bold text-green-600 mb-2">{selectedProject.targets.length}</div>
                <div className="text-sm text-gray-600">Active Targets</div>
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <div className="text-3xl font-bold text-red-600 mb-2">{selectedProject.criticalVulns}</div>
                <div className="text-sm text-gray-600">Critical Vulns</div>
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <div className="text-3xl font-bold text-gray-600 mb-2">{selectedProject.riskScore}</div>
                <div className="text-sm text-gray-600">Risk Score /10</div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold mb-4">Targets</h3>
              <div className="flex gap-2 mb-4">
                <input 
                  type="text"
                  value={newTarget}
                  onChange={(e) => setNewTarget(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleAddTarget()}
                  placeholder="Add new target (e.g., example.com, 192.168.1.1)"
                  className="flex-grow border rounded-lg px-4 py-2"
                />
                <button 
                  onClick={handleAddTarget} 
                  className="bg-green-600 text-white px-4 py-2 rounded-lg flex items-center gap-2 hover:bg-green-700 transition"
                >
                  <Plus size={16} /> Add Target
                </button>
              </div>
              <div className="space-y-2">
                {selectedProject.targets.map((target, idx) => (
                  <div key={idx} className="p-3 bg-gray-50 rounded-lg flex justify-between items-center hover:bg-gray-100 transition">
                    <span className="font-mono text-sm">{target}</span>
                    <div className="flex gap-2">
                      <button className="text-blue-600 hover:text-blue-800 text-sm font-medium">Scan</button>
                      <button className="text-gray-600 hover:text-gray-800 text-sm font-medium">History</button>
                    </div>
                  </div>
                ))}
                {selectedProject.targets.length === 0 && (
                  <div className="text-center text-gray-500 py-4">No targets added yet.</div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'scans' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">Vulnerability Scans</h2>
              <div className="flex gap-2">
                <button 
                  onClick={() => setShowScheduleScanModal(true)} 
                  className="bg-gray-600 text-white px-4 py-2 rounded-lg flex items-center gap-2 hover:bg-gray-700 transition shadow-lg hover:shadow-xl"
                >
                  <Calendar size={18} />
                  Schedule Scan
                </button>
                <button 
                  onClick={() => setShowNewScanModal(true)} 
                  className="bg-blue-600 text-white px-4 py-2 rounded-lg flex items-center gap-2 hover:bg-blue-700 transition shadow-lg hover:shadow-xl"
                >
                  <Play size={18} />
                  New Scan
                </button>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow">
              <div className="p-4 border-b">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={20} />
                    <input 
                      type="text" 
                      placeholder="Search targets..." 
                      className="w-full pl-10 pr-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent" 
                    />
                  </div>
                  <select 
                    value={statusFilter} 
                    onChange={(e) => setStatusFilter(e.target.value)} 
                    className="px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white"
                  >
                    <option value="all">All Status</option>
                    <option value="Running">Running</option>
                    <option value="Completed">Completed</option>
                    <option value="Failed">Failed</option>
                    <option value="Paused">Paused</option>
                  </select>
                </div>
              </div>
              <div className="divide-y">
                {filteredScans.map(scan => (
                  <div key={scan.id} className="p-4 hover:bg-blue-50 transition-all">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {getStatusIcon(scan.status)}
                        <div>
                          <div className="font-semibold">{scan.target}</div>
                          <div className="text-sm text-gray-500">
                            {scan.project} • {scan.profile} • {scan.date}
                            {scan.duration && ` • ${scan.duration}`}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        {scan.status === 'Running' ? (
                          <>
                            <div className="flex items-center gap-3">
                              <div className="w-40 bg-gray-200 rounded-full h-2.5">
                                <div className="bg-blue-500 h-2.5 rounded-full transition-all duration-500" style={{width: `${scan.progress}%`}}></div>
                              </div>
                              <span className="text-sm text-gray-600 font-medium w-12">{Math.round(scan.progress)}%</span>
                            </div>
                            <button 
                              onClick={() => handlePauseScan(scan.id)}
                              className="p-2 hover:bg-yellow-100 rounded transition"
                              title="Pause"
                            >
                              <Pause size={18} className="text-yellow-600" />
                            </button>
                            <button 
                              onClick={() => handleCancelScan(scan.id)}
                              className="p-2 hover:bg-red-100 rounded transition"
                              title="Cancel"
                            >
                              <StopCircle size={18} className="text-red-600" />
                            </button>
                          </>
                        ) : scan.status === 'Paused' ? (
                          <>
                            <span className="text-sm text-yellow-600 font-medium">Paused at {Math.round(scan.progress)}%</span>
                            <button 
                              onClick={() => handleResumeScan(scan.id)}
                              className="p-2 hover:bg-green-100 rounded transition"
                              title="Resume"
                            >
                              <Play size={18} className="text-green-600" />
                            </button>
                            <button 
                              onClick={() => handleCancelScan(scan.id)}
                              className="p-2 hover:bg-red-100 rounded transition"
                              title="Cancel"
                            >
                              <StopCircle size={18} className="text-red-600" />
                            </button>
                          </>
                        ) : scan.status === 'Completed' ? (
                          <div className="text-sm font-medium text-gray-600">{scan.vulns} vulnerabilities</div>
                        ) : (
                          <div className="text-sm text-red-600 font-medium">Scan {scan.status.toLowerCase()}</div>
                        )}
                        <button
                          onClick={() => setSelectedScanForLogs(scan)}
                          className="p-2 hover:bg-gray-100 rounded transition"
                          title="View Logs"
                        >
                          <Terminal size={18} className="text-gray-600" />
                        </button>
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
                <h2 className="text-2xl font-bold">Vulnerability Reports</h2>
                <p className="text-gray-600 text-sm mt-1">
                  Showing {filteredVulnerabilities.length} vulnerabilities
                </p>
              </div>
              <div className="flex gap-2">
                <select 
                  value={reportFormat}
                  onChange={(e) => setReportFormat(e.target.value)}
                  className="px-4 py-2 border rounded-lg bg-white"
                >
                  <option value="pdf">PDF</option>
                  <option value="csv">CSV</option>
                  <option value="json">JSON</option>
                  <option value="html">HTML</option>
                </select>
                <button 
                  onClick={() => handleExport(reportFormat)} 
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg flex items-center gap-2 hover:bg-blue-700 transition shadow hover:shadow-md"
                >
                  <Download size={18} />
                  Export {reportFormat.toUpperCase()}
                </button>
              </div>
            </div>

            <div className="grid grid-cols-5 gap-4">
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
              <div className="bg-gray-50 border-2 border-gray-200 rounded-lg p-4 hover:shadow-lg transition transform hover:-translate-y-1 cursor-pointer">
                <div className="text-3xl font-bold text-gray-700">{stats.total}</div>
                <div className="text-sm text-gray-600 font-medium">Total Open</div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow">
              <div className="p-4 border-b bg-gray-50">
                <div className="flex gap-4 mb-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={20} />
                    <input
                      type="text"
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      placeholder="Search vulnerabilities by CVE, name, or component..."
                      className="w-full pl-10 pr-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    className="px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white"
                  >
                    <option value="all">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                  <button className="px-4 py-2 border rounded-lg hover:bg-gray-50 transition flex items-center gap-2">
                    <Filter size={18} />
                    More Filters
                  </button>
                </div>
                {selectedVulns.size > 0 && (
                  <div className="flex items-center gap-4">
                    <span className="text-sm text-gray-600">{selectedVulns.size} selected</span>
                    <select
                      value={bulkAction}
                      onChange={(e) => setBulkAction(e.target.value)}
                      className="px-3 py-1 border rounded text-sm bg-white"
                    >
                      <option value="">Bulk Actions</option>
                      <option value="mark-resolved">Mark as Resolved</option>
                      <option value="mark-progress">Mark as In Progress</option>
                    </select>
                    <button 
                      onClick={handleBulkAction}
                      className="px-3 py-1 bg-blue-600 text-white rounded text-sm hover:bg-blue-700 transition"
                    >
                      Apply
                    </button>
                    <button 
                      onClick={() => setSelectedVulns(new Set())}
                      className="text-sm text-gray-600 hover:text-gray-800"
                    >
                      Clear
                    </button>
                  </div>
                )}
              </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-4 py-3 text-left">
                        <input 
                          type="checkbox"
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedVulns(new Set(paginatedVulnerabilities.map(v => v.id)));
                            } else {
                              setSelectedVulns(new Set());
                            }
                          }}
                          checked={selectedVulns.size === paginatedVulnerabilities.length && paginatedVulnerabilities.length > 0}
                          className="h-4 w-4 text-blue-600 border-gray-300 rounded"
                        />
                      </th>
                      <th className="px-4 py-3 text-left text-sm font-semibold cursor-pointer hover:bg-gray-100" onClick={() => handleSort('cve')}>
                        CVE ID {sortField === 'cve' && (sortDirection === 'asc' ? '↑' : '↓')}
                      </th>
                      <th className="px-4 py-3 text-left text-sm font-semibold cursor-pointer hover:bg-gray-100" onClick={() => handleSort('name')}>
                        Vulnerability {sortField === 'name' && (sortDirection === 'asc' ? '↑' : '↓')}
                      </th>
                      <th className="px-4 py-3 text-left text-sm font-semibold cursor-pointer hover:bg-gray-100" onClick={() => handleSort('component')}>
                        Component {sortField === 'component' && (sortDirection === 'asc' ? '↑' : '↓')}
                      </th>
                      <th className="px-4 py-3 text-left text-sm font-semibold cursor-pointer hover:bg-gray-100" onClick={() => handleSort('cvss')}>
                        CVSS {sortField === 'cvss' && (sortDirection === 'asc' ? '↑' : '↓')}
                      </th>
                      <th className="px-4 py-3 text-left text-sm font-semibold cursor-pointer hover:bg-gray-100" onClick={() => handleSort('severity')}>
                        Severity {sortField === 'severity' && (sortDirection === 'asc' ? '↑' : '↓')}
                      </th>
                      <th className="px-4 py-3 text-left text-sm font-semibold cursor-pointer hover:bg-gray-100" onClick={() => handleSort('status')}>
                        Status {sortField === 'status' && (sortDirection === 'asc' ? '↑' : '↓')}
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {paginatedVulnerabilities.map(vuln => (
                      <tr key={vuln.id} className="hover:bg-blue-50 transition">
                        <td className="px-4 py-3">
                          <input 
                            type="checkbox"
                            checked={selectedVulns.has(vuln.id)}
                            onChange={(e) => {
                              const newSelected = new Set(selectedVulns);
                              if (e.target.checked) {
                                newSelected.add(vuln.id);
                              } else {
                                newSelected.delete(vuln.id);
                              }
                              setSelectedVulns(newSelected);
                            }}
                            className="h-4 w-4 text-blue-600 border-gray-300 rounded"
                          />
                        </td>
                        <td 
                          onClick={() => setSelectedVuln(vuln)}
                          className="px-4 py-3 text-sm font-mono text-blue-600 cursor-pointer hover:underline"
                        >
                          {vuln.cve}
                        </td>
                        <td 
                          onClick={() => setSelectedVuln(vuln)}
                          className="px-4 py-3 text-sm font-medium cursor-pointer"
                        >
                          {vuln.name}
                        </td>
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
                          ) : vuln.status === 'in_progress' ? (
                            <span className="px-2 py-1 bg-yellow-100 text-yellow-700 rounded-full text-xs font-medium">In Progress</span>
                          ) : (
                            <span className="px-2 py-1 bg-red-100 text-red-700 rounded-full text-xs font-medium">New</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="p-4 border-t flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <span className="text-sm text-gray-600">
                    Showing {((currentPage - 1) * itemsPerPage) + 1} to {Math.min(currentPage * itemsPerPage, filteredVulnerabilities.length)} of {filteredVulnerabilities.length}
                  </span>
                  <select
                    value={itemsPerPage}
                    onChange={(e) => {
                      setItemsPerPage(Number(e.target.value));
                      setCurrentPage(1);
                    }}
                    className="px-3 py-1 border rounded text-sm bg-white"
                  >
                    <option value={25}>25 per page</option>
                    <option value={50}>50 per page</option>
                    <option value={100}>100 per page</option>
                  </select>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                    disabled={currentPage === 1}
                    className="px-3 py-1 border rounded hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Previous
                  </button>
                  {[...Array(Math.min(5, totalPages))].map((_, i) => {
                    const pageNum = i + 1;
                    return (
                      <button
                        key={pageNum}
                        onClick={() => setCurrentPage(pageNum)}
                        className={`px-3 py-1 border rounded ${currentPage === pageNum ? 'bg-blue-600 text-white' : 'hover:bg-gray-50'}`}
                      >
                        {pageNum}
                      </button>
                    );
                  })}
                  {totalPages > 5 && <span className="px-3 py-1">...</span>}
                  <button
                    onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                    disabled={currentPage === totalPages}
                    className="px-3 py-1 border rounded hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Next
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {toast.show && (
        <div className={`fixed top-6 right-6 px-6 py-3 rounded-lg shadow-lg z-[100] flex items-center gap-2 ${
          toast.type === 'success' ? 'bg-green-600 text-white' : 
          toast.type === 'error' ? 'bg-red-600 text-white' : 
          'bg-blue-600 text-white'
        }`}>
          {toast.type === 'success' && <CheckCircle size={20} />}
          {toast.type === 'error' && <AlertCircle size={20} />}
          {toast.type === 'info' && <Info size={20} />}
          {toast.message}
        </div>
      )}

      {showNewScanModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white p-6 rounded-lg shadow-xl w-1/2 max-w-2xl">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-semibold">Configure New Scan</h3>
              <button onClick={() => setShowNewScanModal(false)}>
                <X size={24} className="text-gray-500 hover:text-gray-800" />
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="font-medium block mb-1">Target *</label>
                <input 
                  type="text" 
                  value={newScanData.target}
                  onChange={(e) => setNewScanData({...newScanData, target: e.target.value})}
                  placeholder="e.g., 192.168.1.1, example.com, 10.0.0.0/24"
                  className="w-full border rounded-lg px-3 py-2"
                />
                <p className="text-xs text-gray-500 mt-1">Enter a valid IP address, domain name, or CIDR range</p>
              </div>
              <div>
                <label className="font-medium block mb-1">Port Range</label>
                <input 
                  type="text" 
                  value={newScanData.portRange}
                  onChange={(e) => setNewScanData({...newScanData, portRange: e.target.value})}
                  placeholder="e.g., 1-1000, 80,443,8080"
                  className="w-full border rounded-lg px-3 py-2"
                />
              </div>
              <div>
                <label className="font-medium block mb-1">Scan Profile</label>
                <select 
                  value={newScanData.profile} 
                  onChange={(e) => setNewScanData({...newScanData, profile: e.target.value})} 
                  className="w-full border rounded-lg px-3 py-2 bg-white"
                >
                  <option value="quick">Quick Scan ({scanProfiles.quick.duration})</option>
                  <option value="standard">Standard Scan ({scanProfiles.standard.duration})</option>
                  <option value="comprehensive">Comprehensive Scan ({scanProfiles.comprehensive.duration})</option>
                </select>
                <p className="text-xs text-gray-500 mt-1">{scanProfiles[newScanData.profile].description}</p>
              </div>
              <div>
                <label className="font-medium block mb-2">Scanning Tools *</label>
                <div className="grid grid-cols-2 gap-2">
                  {Object.keys(newScanData.tools).map(tool => (
                    <label key={tool} className="flex items-center gap-2 p-2 bg-gray-50 rounded-lg hover:bg-gray-100 cursor-pointer">
                      <input 
                        type="checkbox"
                        checked={newScanData.tools[tool]}
                        onChange={(e) => setNewScanData({...newScanData, tools: {...newScanData.tools, [tool]: e.target.checked }})}
                        className="h-4 w-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                      />
                      <span className="text-sm capitalize font-medium">{tool}</span>
                    </label>
                  ))}
                </div>
              </div>
            </div>
            <div className="mt-6 flex justify-end gap-2">
              <button 
                onClick={() => setShowNewScanModal(false)}
                className="px-6 py-2 border rounded-lg hover:bg-gray-50 transition"
              >
                Cancel
              </button>
              <button 
                onClick={handleStartScan} 
                className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition shadow flex items-center gap-2"
              >
                <Play size={18} />
                Start Scan
              </button>
            </div>
          </div>
        </div>
      )}

      {showScheduleScanModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white p-6 rounded-lg shadow-xl w-1/2 max-w-lg">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-semibold">Schedule Recurring Scan</h3>
              <button onClick={() => setShowScheduleScanModal(false)}>
                <X size={24} className="text-gray-500 hover:text-gray-800" />
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="font-medium block mb-1">Target *</label>
                <input
                  type="text"
                  value={scheduleScanData.target}
                  onChange={(e) => setScheduleScanData({ ...scheduleScanData, target: e.target.value })}
                  placeholder="e.g., 192.168.1.1, example.com"
                  className="w-full border rounded-lg px-3 py-2"
                />
              </div>
              <div>
                <label className="font-medium block mb-1">Frequency</label>
                <select
                  value={scheduleScanData.frequency}
                  onChange={(e) => setScheduleScanData({ ...scheduleScanData, frequency: e.target.value })}
                  className="w-full border rounded-lg px-3 py-2 bg-white"
                >
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                </select>
              </div>
              <div>
                <label className="font-medium block mb-1">Time</label>
                <input
                  type="time"
                  value={scheduleScanData.time}
                  onChange={(e) => setScheduleScanData({ ...scheduleScanData, time: e.target.value })}
                  className="w-full border rounded-lg px-3 py-2"
                />
              </div>
              <div>
                <label className="font-medium block mb-1">Timezone</label>
                <select
                  value={scheduleScanData.timezone}
                  onChange={(e) => setScheduleScanData({ ...scheduleScanData, timezone: e.target.value })}
                  className="w-full border rounded-lg px-3 py-2 bg-white"
                >
                  <option value="Asia/Kolkata">Asia/Kolkata (IST)</option>
                  <option value="America/New_York">America/New_York (EST)</option>
                  <option value="Europe/London">Europe/London (GMT)</option>
                  <option value="Asia/Tokyo">Asia/Tokyo (JST)</option>
                </select>
              </div>
            </div>
            <div className="mt-6 flex justify-end gap-2">
              <button 
                onClick={() => setShowScheduleScanModal(false)}
                className="px-6 py-2 border rounded-lg hover:bg-gray-50 transition"
              >
                Cancel
              </button>
              <button 
                onClick={handleScheduleScan} 
                className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition shadow"
              >
                Schedule
              </button>
            </div>
          </div>
        </div>
      )}

      {selectedScanForLogs && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white p-6 rounded-lg shadow-xl w-1/2 max-w-3xl">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-semibold flex items-center gap-2">
                <Terminal size={20} />
                Scan Details: {selectedScanForLogs.target}
              </h3>
              <button onClick={() => setSelectedScanForLogs(null)}>
                <X size={24} className="text-gray-500 hover:text-gray-800" />
              </button>
            </div>
            <div className="space-y-3 mb-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div><strong>Status:</strong> {selectedScanForLogs.status}</div>
                <div><strong>Profile:</strong> {selectedScanForLogs.profile}</div>
                <div><strong>Started:</strong> {selectedScanForLogs.date}</div>
                <div><strong>Duration:</strong> {selectedScanForLogs.duration || 'In progress'}</div>
              </div>
            </div>
            <div className="bg-gray-900 text-green-400 font-mono text-sm rounded-lg p-4 h-96 overflow-y-auto">
              {mockNmapOutput.map((line, i) => (
                <div key={i}>{`> ${line.replace('TARGET', selectedScanForLogs.target)}`}</div>
              ))}
              {selectedScanForLogs.status === 'Running' && (
                <div className="text-yellow-400 mt-2 animate-pulse">{`> Scanning in progress... ${Math.round(selectedScanForLogs.progress)}% complete`}</div>
              )}
              {selectedScanForLogs.status === 'Completed' && (
                <div className="text-green-400 mt-2">{`> Scan completed successfully at ${selectedScanForLogs.date}`}</div>
              )}
            </div>
          </div>
        </div>
      )}

      {showScanOutput && (
        <div className="fixed bottom-4 right-4 w-1/3 bg-black text-green-400 font-mono text-sm rounded-lg shadow-2xl p-4 z-50">
          <div className="flex justify-between items-center mb-2">
            <div className="flex items-center gap-2">
              <Terminal size={16} />
              <span>Live Scan Output</span>
            </div>
            <button onClick={() => setShowScanOutput(false)}>
              <X size={18} className="text-gray-400 hover:text-white" />
            </button>
          </div>
          <div className="h-64 overflow-y-auto">
            {scanOutput.map((line, i) => <div key={i}>{`> ${line}`}</div>)}
            <div className="animate-pulse">_</div>
          </div>
        </div>
      )}

      {selectedVuln && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white p-8 rounded-lg shadow-xl w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-start mb-4">
              <div>
                <h3 className="text-xl font-bold flex items-center gap-2 mb-2">
                  <span className={`px-3 py-1 rounded text-white text-base ${getSeverityColor(selectedVuln.severity)}`}>
                    {selectedVuln.severity}
                  </span>
                  {selectedVuln.name}
                </h3>
                <div className="font-mono text-blue-700 bg-blue-50 px-3 py-1 rounded inline-block">{selectedVuln.cve}</div>
              </div>
              <button onClick={() => setSelectedVuln(null)}>
                <X size={24} className="text-gray-500 hover:text-gray-800" />
              </button>
            </div>
            
            <div className="space-y-4 text-sm">
              <div className="grid grid-cols-2 gap-4 p-4 bg-gray-50 rounded-lg">
                <div>
                  <strong className="text-gray-600">CVSS Score:</strong> 
                  <span className="font-bold text-lg ml-2">{selectedVuln.cvss}</span>
                </div>
                <div>
                  <strong className="text-gray-600">Component:</strong> 
                  <span className="ml-2">{selectedVuln.component}</span>
                </div>
                <div>
                  <strong className="text-gray-600">Affected Version:</strong> 
                  <span className="ml-2">{selectedVuln.affectedVersion}</span>
                </div>
                <div>
                  <strong className="text-gray-600">Discovery Date:</strong> 
                  <span className="ml-2">{selectedVuln.discoveryDate}</span>
                </div>
              </div>

              <div>
                <h4 className="font-semibold text-base mb-2 flex items-center gap-2">
                  <FileText size={18} />
                  CVSS Vector
                </h4>
                <code className="text-xs bg-gray-100 p-2 rounded block overflow-x-auto">
                  {selectedVuln.cvssVector}
                </code>
              </div>

              <div>
                <h4 className="font-semibold text-base mb-2">Description</h4>
                <p className="text-gray-700 leading-relaxed">{selectedVuln.description}</p>
              </div>

              <div className="bg-green-50 border-l-4 border-green-500 p-4 rounded">
                <h4 className="font-semibold text-base mb-2 text-green-800">Remediation Steps</h4>
                <p className="text-gray-700 leading-relaxed">{selectedVuln.remediation}</p>
              </div>

              {selectedVuln.proofOfConcept && selectedVuln.proofOfConcept !== 'N/A' && (
                <div className="bg-yellow-50 border-l-4 border-yellow-500 p-4 rounded">
                  <h4 className="font-semibold text-base mb-2 text-yellow-800">Proof of Concept</h4>
                  <code className="text-sm bg-white p-2 rounded block">{selectedVuln.proofOfConcept}</code>
                </div>
              )}

              <div>
                <h4 className="font-semibold text-base mb-2">References</h4>
                <ul className="space-y-1">
                  {selectedVuln.references.map((ref, i) => (
                    <li key={i}>
                      <a 
                        href={ref} 
                        target="_blank" 
                        rel="noopener noreferrer" 
                        className="text-blue-600 hover:underline text-sm flex items-center gap-1"
                      >
                        <ChevronRight size={14} />
                        {ref}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>

              {selectedVuln.relatedCves && selectedVuln.relatedCves.length > 0 && (
                <div>
                  <h4 className="font-semibold text-base mb-2">Related Vulnerabilities</h4>
                  <div className="flex gap-2 flex-wrap">
                    {selectedVuln.relatedCves.map(cve => (
                      <span key={cve} className="px-2 py-1 bg-blue-100 text-blue-700 rounded text-xs font-mono">
                        {cve}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="p-4 bg-yellow-50 border-l-4 border-yellow-400 text-yellow-800">
                <p className="text-sm">
                  <strong className="font-bold">⚠️ Security Notice:</strong> Information provided is for educational and defensive purposes only. 
                  Do not attempt to exploit vulnerabilities on systems you do not own or have explicit permission to test.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {showSettings && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white p-6 rounded-lg shadow-xl w-1/2 max-w-2xl">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-semibold">Settings</h3>
              <button onClick={() => setShowSettings(false)}>
                <X size={24} className="text-gray-500 hover:text-gray-800" />
              </button>
            </div>
            <div className="space-y-6">
              <div>
                <h4 className="font-semibold mb-3">User Profile</h4>
                <div className="space-y-3">
                  <div>
                    <label className="text-sm font-medium">Email</label>
                    <input type="email" value="analyst@security.com" className="w-full border rounded-lg px-3 py-2 mt-1" disabled />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Role</label>
                    <input type="text" value="Security Analyst" className="w-full border rounded-lg px-3 py-2 mt-1" disabled />
                  </div>
                </div>
              </div>
              <div>
                <h4 className="font-semibold mb-3">Notification Preferences</h4>
                <div className="space-y-2">
                  <label className="flex items-center gap-2">
                    <input type="checkbox" defaultChecked className="h-4 w-4" />
                    <span className="text-sm">Email notifications for critical vulnerabilities</span>
                  </label>
                  <label className="flex items-center gap-2">
                    <input type="checkbox" defaultChecked className="h-4 w-4" />
                    <span className="text-sm">Scan completion notifications</span>
                  </label>
                  <label className="flex items-center gap-2">
                    <input type="checkbox" className="h-4 w-4" />
                    <span className="text-sm">Weekly security reports</span>
                  </label>
                </div>
              </div>
              <div>
                <h4 className="font-semibold mb-3">Security</h4>
                <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition text-sm">
                  Change Password
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="fixed bottom-4 right-4 z-40">
        {!chatOpen && (
          <button 
            onClick={() => setChatOpen(true)} 
            className="bg-blue-600 text-white rounded-full p-4 shadow-lg hover:bg-blue-700 transition transform hover:scale-110"
          >
            <MessageCircle size={24} />
          </button>
        )}
        {chatOpen && (
          <div className="w-96 h-[32rem] bg-white rounded-lg shadow-2xl flex flex-col">
            <div className="bg-blue-600 text-white p-4 rounded-t-lg flex justify-between items-center">
              <div>
                <h3 className="font-semibold">AI Security Assistant</h3>
                <p className="text-xs opacity-90">Llama 3.3</p>
              </div>
              <button onClick={() => setChatOpen(false)}>
                <X size={20} />
              </button>
            </div>
            <div className="flex-1 p-4 overflow-y-auto bg-gray-50 space-y-4">
              {chatMessages.map((msg, i) => (
                <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={`p-3 rounded-lg max-w-xs ${msg.role === 'user' ? 'bg-blue-500 text-white' : 'bg-white text-gray-800 shadow'}`}>
                    <div className="whitespace-pre-wrap">{msg.content}</div>
                    {msg.citations && (
                      <div className="mt-2 pt-2 border-t border-gray-200 text-xs opacity-75">
                        Sources: {msg.citations.join(', ')}
                      </div>
                    )}
                  </div>
                </div>
              ))}
              <div ref={chatMessagesEndRef} />
            </div>
            <div className="p-4 border-t bg-white">
              <div className="mb-2 flex flex-wrap gap-1">
                {suggestedQuestions.slice(0, 3).map((q, i) => (
                  <button
                    key={i}
                    onClick={() => {
                      setChatInput(q);
                      handleSendMessage();
                    }}
                    className="text-xs px-2 py-1 bg-gray-100 hover:bg-gray-200 rounded transition"
                  >
                    {q}
                  </button>
                ))}
              </div>
              <div className="relative">
                <input 
                  type="text" 
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
                  placeholder="Ask about vulnerabilities, exploits, or remediation..."
                  className="w-full border rounded-l-lg px-4 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
                <button 
                  onClick={handleSendMessage}
                  className="bg-blue-600 text-white px-4 py-2 rounded-r-lg hover:bg-blue-700 transition"
                >
                  <Send size={18} />
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}