"use client";

import { Shield, Globe, Search, AlertTriangle, Lock, Book, Map, Wrench, Eye, Zap, User, Newspaper, Plus, LogOut, LogIn } from "lucide-react"
import { useState, useEffect } from 'react'

export default function Home() {
  const [activeTab, setActiveTab] = useState('osint')
  const [openAccordion, setOpenAccordion] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [showLoginForm, setShowLoginForm] = useState(false)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [userInfo, setUserInfo] = useState<{name: string, role: string} | null>(null)

  // Sample news data
  const [news] = useState([
    {
      id: 1,
      title: "New Ransomware Variant Targeting Pacific Region",
      date: "2025-09-20",
      summary: "CERT-PNG issues alert on emerging ransomware specifically targeting government networks in the Pacific Islands.",
      priority: "high"
    },
    {
      id: 2,
      title: "MITRE ATT&CK Framework Update v15.1",
      date: "2025-09-18",
      summary: "Latest update includes new techniques observed in APT campaigns targeting Southeast Asian governments.",
      priority: "medium"
    },
    {
      id: 3,
      title: "Critical Vulnerability in Widely Used Network Equipment",
      date: "2025-09-15",
      summary: "CVE-2025-12345 affects routers commonly deployed in PNG government networks. Patches available.",
      priority: "high"
    }
  ])

  const tabs = [
    { id: 'osint', label: 'OSINT', icon: Search },
    { id: 'threat-intel', label: 'Threat Intel', icon: AlertTriangle },
    { id: 'dfir', label: 'DFIR', icon: Eye },
    { id: 'pentest', label: 'Pentest', icon: Zap },
    { id: 'defense', label: 'Defense', icon: Shield },
    { id: 'grc', label: 'GRC', icon: Lock },
    { id: 'training', label: 'Training', icon: Book },
    { id: 'regional', label: 'Regional', icon: Map },
    { id: 'utilities', label: 'Utilities', icon: Wrench },
    { id: 'news', label: 'News', icon: Newspaper },
    { id: 'submit', label: 'Submit', icon: Plus },
    { id: 'about', label: 'About', icon: Globe },
  ]

  // All resources for search functionality
  const allResources = [
    // OSINT Tools
    { name: "OSINT Framework", category: "OSINT", description: "Comprehensive directory of OSINT tools organized by category", url: "https://osintframework.com/" },
    { name: "Maltego CE", category: "OSINT", description: "Graph-based OSINT and link analysis tool", url: "https://www.maltego.com/" },
    { name: "Shodan", category: "OSINT", description: "Search engine for connected devices and exposed infrastructure", url: "https://www.shodan.io/" },
    { name: "Censys", category: "OSINT", description: "Internet-wide scanning and device discovery platform", url: "https://censys.com/" },
    { name: "theHarvester", category: "OSINT", description: "Email, subdomain, and host discovery tool", url: "https://www.edge-security.com/" },
    { name: "Recon-ng", category: "OSINT", description: "Web reconnaissance framework for penetration testers", url: "https://github.com/lanmaster53/recon-ng" },
    { name: "Google Dorks Database", category: "OSINT", description: "Search engine query strings for OSINT discovery", url: "https://www.exploit-db.com/google-hacking-database" },

    // Threat Intelligence
    { name: "MISP", category: "Threat Intel", description: "Open-source threat intelligence platform for sharing IoCs", url: "https://www.misp-project.org/" },
    { name: "AlienVault OTX", category: "Threat Intel", description: "Free community threat intelligence feed", url: "https://otx.alienvault.com/" },
    { name: "Abuse.ch", category: "Threat Intel", description: "Malware and botnet tracking", url: "https://abuse.ch/" },
    { name: "VirusTotal", category: "Threat Intel", description: "Free file and URL scanning against multiple antivirus engines", url: "https://www.virustotal.com/" },
    { name: "GreyNoise", category: "Threat Intel", description: "Distinguishes between background internet scanning and targeted threats", url: "https://greynoise.io/" },

    // DFIR
    { name: "Autopsy", category: "DFIR", description: "Digital forensics platform for analyzing disks and files", url: "https://www.sleuthkit.org/autopsy/" },
    { name: "Volatility", category: "DFIR", description: "Memory forensics framework", url: "https://www.volatilityfoundation.org/" },
    { name: "KAPE", category: "DFIR", description: "Evidence collection and analysis tool", url: "https://www.kroll.com/en/services/cyber-risk/digital-forensics/kroll-artifact-parser-extractor-kape" },
    { name: "Wireshark", category: "DFIR", description: "Packet capture and network protocol analysis", url: "https://www.wireshark.org/" },
    { name: "NetworkMiner", category: "DFIR", description: "Network forensic analysis tool", url: "https://www.netresec.com/?page=NetworkMiner" },

    // Penetration Testing
    { name: "Kali Linux", category: "Pentest", description: "Penetration testing Linux distribution", url: "https://www.kali.org/" },
    { name: "Parrot OS", category: "Pentest", description: "Security-focused operating system for penetration testing", url: "https://www.parrotsec.org/" },
    { name: "Metasploit Framework", category: "Pentest", description: "Exploitation and testing framework", url: "https://www.metasploit.com/" },
    { name: "Burp Suite Community Edition", category: "Pentest", description: "Web application security testing", url: "https://portswigger.net/burp/communitydownload" },
    { name: "Nmap", category: "Pentest", description: "Network discovery and security scanner", url: "https://nmap.org/" },
    { name: "OWASP ZAP", category: "Pentest", description: "Free web application security scanner", url: "https://www.zaproxy.org/" },

    // Defense
    { name: "Zeek", category: "Defense", description: "Network security monitoring framework", url: "https://zeek.org/" },
    { name: "Snort", category: "Defense", description: "Open-source intrusion detection and prevention system", url: "https://www.snort.org/" },
    { name: "Suricata", category: "Defense", description: "High-performance IDS/IPS engine", url: "https://suricata.io/" },
    { name: "Wazuh", category: "Defense", description: "Open-source SIEM and security monitoring platform", url: "https://wazuh.com/" },
    { name: "Security Onion", category: "Defense", description: "Free Linux distro for intrusion detection, log management, and threat hunting", url: "https://securityonion.net/" },
  ]

  const filteredResources = allResources.filter(resource =>
    resource.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    resource.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
    resource.category.toLowerCase().includes(searchQuery.toLowerCase())
  )

  const toggleAccordion = (value: string) => {
    setOpenAccordion(openAccordion === value ? null : value)
  }

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault()
    // Simple authentication check (in production, this would be secured)
    if (username && password) {
      setIsAuthenticated(true)
      setUserInfo({ name: username, role: "Cybersecurity Analyst" })
      setShowLoginForm(false)
      setUsername('')
      setPassword('')
    }
  }

  const handleLogout = () => {
    setIsAuthenticated(false)
    setUserInfo(null)
  }

  // Form state for resource submission
  const [submissionForm, setSubmissionForm] = useState({
    toolName: '',
    category: '',
    description: '',
    url: '',
    submitterName: '',
    justification: ''
  })

  const handleSubmissionChange = (field: string, value: string) => {
    setSubmissionForm(prev => ({ ...prev, [field]: value }))
  }

  const handleSubmissionSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    // In production, this would send to a backend API
    alert('Resource submission received! Thank you for contributing to the PNG Cybersecurity Resource Hub.')
    setSubmissionForm({
      toolName: '',
      category: '',
      description: '',
      url: '',
      submitterName: '',
      justification: ''
    })
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
      {/* Header Section */}
      <header className="bg-gradient-to-r from-slate-800 to-slate-900 text-white">
        <div className="container mx-auto px-4 py-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <Shield className="h-12 w-12 text-emerald-400" />
              <div>
                <h1 className="text-3xl font-bold">PNG Cybersecurity Resource Hub</h1>
                <p className="text-slate-300 mt-1">Department of Information & Communication Technology</p>
                <p className="text-emerald-400 font-medium">Papua New Guinea Government</p>
              </div>
            </div>
            <div className="text-right">
              <div className="flex items-center space-x-4 mb-2">
                <div className="inline-block px-3 py-1 border border-emerald-400 text-emerald-400 rounded text-sm">
                  Authorized Personnel Only
                </div>
                {isAuthenticated ? (
                  <div className="flex items-center space-x-2">
                    <User className="h-4 w-4 text-emerald-400" />
                    <span className="text-sm text-emerald-400">{userInfo?.name}</span>
                    <button
                      onClick={handleLogout}
                      className="text-slate-300 hover:text-white text-sm"
                    >
                      <LogOut className="h-4 w-4" />
                    </button>
                  </div>
                ) : (
                  <button
                    onClick={() => setShowLoginForm(true)}
                    className="flex items-center space-x-1 text-emerald-400 hover:text-emerald-300 text-sm"
                  >
                    <LogIn className="h-4 w-4" />
                    <span>Login</span>
                  </button>
                )}
              </div>
              <p className="text-sm text-slate-400">Last Updated: September 2025</p>
            </div>
          </div>
          <p className="mt-4 text-lg text-slate-200 max-w-4xl">
            Curated references to cybersecurity tools, frameworks, and resources for research, investigations,
            policy development, and incident response. Most resources are free and open-source.
          </p>

          {/* Search Bar */}
          <div className="mt-6">
            <div className="relative max-w-md">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400 h-4 w-4" />
              <input
                type="text"
                placeholder="Search tools and resources..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-slate-700 text-white placeholder-slate-400 rounded-lg border border-slate-600 focus:outline-none focus:border-emerald-400"
              />
            </div>
          </div>
        </div>
      </header>

      {/* Login Modal */}
      {showLoginForm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-96">
            <h3 className="text-lg font-bold mb-4">Authorized Personnel Login</h3>
            <form onSubmit={handleLogin}>
              <div className="mb-4">
                <label className="block text-sm font-medium mb-2">Username</label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:border-emerald-400"
                  required
                />
              </div>
              <div className="mb-4">
                <label className="block text-sm font-medium mb-2">Password</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:border-emerald-400"
                  required
                />
              </div>
              <div className="flex space-x-2">
                <button
                  type="submit"
                  className="flex-1 bg-emerald-600 text-white py-2 rounded-lg hover:bg-emerald-700"
                >
                  Login
                </button>
                <button
                  type="button"
                  onClick={() => setShowLoginForm(false)}
                  className="flex-1 bg-slate-300 text-slate-700 py-2 rounded-lg hover:bg-slate-400"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Search Results */}
      {searchQuery && (
        <div className="container mx-auto px-4 py-4">
          <div className="bg-white rounded-lg shadow-sm p-6">
            <h2 className="text-xl font-bold mb-4">Search Results ({filteredResources.length})</h2>
            {filteredResources.length > 0 ? (
              <div className="space-y-3">
                {filteredResources.map((resource, index) => (
                  <div key={index} className="p-3 border rounded-lg hover:bg-slate-50">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <h4 className="font-semibold text-blue-600">{resource.name}</h4>
                        <p className="text-sm text-slate-600 mb-1">{resource.description}</p>
                        <span className="inline-block px-2 py-1 text-xs bg-slate-100 text-slate-600 rounded">
                          {resource.category}
                        </span>
                      </div>
                      <a
                        href={resource.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-600 hover:underline text-sm ml-4"
                      >
                        Visit →
                      </a>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-slate-600">No resources found matching your search.</p>
            )}
          </div>
        </div>
      )}

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        {/* Navigation Tabs */}
        <div className="grid grid-cols-4 lg:grid-cols-12 gap-1 mb-8 bg-white rounded-lg p-1 shadow-sm">
          {tabs.map((tab) => {
            const Icon = tab.icon
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center justify-center space-x-1 px-2 py-3 rounded text-xs font-medium transition-colors ${
                  activeTab === tab.id
                    ? 'bg-slate-900 text-white'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span className="hidden md:inline">{tab.label}</span>
              </button>
            )
          })}
        </div>

        {/* News Tab */}
        {activeTab === 'news' && (
          <div className="bg-white rounded-lg shadow-sm">
            <div className="p-6 border-b">
              <div className="flex items-center">
                <Newspaper className="h-6 w-6 mr-2 text-blue-600" />
                <h2 className="text-2xl font-bold">Cybersecurity News & Updates</h2>
              </div>
              <p className="text-slate-600 mt-2">
                Latest cybersecurity threats, advisories, and updates relevant to Papua New Guinea
              </p>
            </div>
            <div className="p-6">
              <div className="space-y-4">
                {news.map((article) => (
                  <div key={article.id} className="p-4 border rounded-lg">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          <h4 className="font-semibold text-slate-800">{article.title}</h4>
                          <span className={`px-2 py-1 text-xs rounded ${
                            article.priority === 'high'
                              ? 'bg-red-100 text-red-600'
                              : 'bg-yellow-100 text-yellow-600'
                          }`}>
                            {article.priority.toUpperCase()}
                          </span>
                        </div>
                        <p className="text-sm text-slate-600 mb-2">{article.summary}</p>
                        <p className="text-xs text-slate-400">{article.date}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Resource Submission Tab */}
        {activeTab === 'submit' && (
          <div className="bg-white rounded-lg shadow-sm">
            <div className="p-6 border-b">
              <div className="flex items-center">
                <Plus className="h-6 w-6 mr-2 text-green-600" />
                <h2 className="text-2xl font-bold">Submit New Resource</h2>
              </div>
              <p className="text-slate-600 mt-2">
                Suggest new cybersecurity tools and resources for the PNG Cybersecurity Hub
              </p>
            </div>
            <div className="p-6">
              {isAuthenticated ? (
                <form onSubmit={handleSubmissionSubmit} className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium mb-2">Tool/Resource Name *</label>
                      <input
                        type="text"
                        value={submissionForm.toolName}
                        onChange={(e) => handleSubmissionChange('toolName', e.target.value)}
                        className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:border-emerald-400"
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium mb-2">Category *</label>
                      <select
                        value={submissionForm.category}
                        onChange={(e) => handleSubmissionChange('category', e.target.value)}
                        className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:border-emerald-400"
                        required
                      >
                        <option value="">Select Category</option>
                        <option value="OSINT">OSINT</option>
                        <option value="Threat Intel">Threat Intelligence</option>
                        <option value="DFIR">Digital Forensics & IR</option>
                        <option value="Pentest">Penetration Testing</option>
                        <option value="Defense">Defense & Monitoring</option>
                        <option value="GRC">Governance, Risk & Compliance</option>
                        <option value="Training">Training & Education</option>
                        <option value="Utilities">Utilities</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-2">Description *</label>
                    <textarea
                      value={submissionForm.description}
                      onChange={(e) => handleSubmissionChange('description', e.target.value)}
                      rows={3}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:border-emerald-400"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-2">URL/Website</label>
                    <input
                      type="url"
                      value={submissionForm.url}
                      onChange={(e) => handleSubmissionChange('url', e.target.value)}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:border-emerald-400"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-2">Your Name *</label>
                    <input
                      type="text"
                      value={submissionForm.submitterName}
                      onChange={(e) => handleSubmissionChange('submitterName', e.target.value)}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:border-emerald-400"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-2">Justification/Use Case *</label>
                    <textarea
                      value={submissionForm.justification}
                      onChange={(e) => handleSubmissionChange('justification', e.target.value)}
                      rows={3}
                      placeholder="Explain why this tool would be valuable for PNG cybersecurity operations..."
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:border-emerald-400"
                      required
                    />
                  </div>

                  <button
                    type="submit"
                    className="bg-emerald-600 text-white px-6 py-2 rounded-lg hover:bg-emerald-700"
                  >
                    Submit Resource
                  </button>
                </form>
              ) : (
                <div className="text-center py-8">
                  <p className="text-slate-600 mb-4">Please log in to submit new resources.</p>
                  <button
                    onClick={() => setShowLoginForm(true)}
                    className="bg-emerald-600 text-white px-6 py-2 rounded-lg hover:bg-emerald-700"
                  >
                    Login to Submit
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* OSINT Tab */}
        {activeTab === 'osint' && (
          <div className="bg-white rounded-lg shadow-sm">
            <div className="p-6 border-b">
              <div className="flex items-center">
                <Search className="h-6 w-6 mr-2 text-blue-600" />
                <h2 className="text-2xl font-bold">Open-Source Intelligence (OSINT) Frameworks & Tools</h2>
              </div>
              <p className="text-slate-600 mt-2">
                Comprehensive tools for gathering and analyzing publicly available information
              </p>
            </div>
            <div className="p-6">
              {/* OSINT Frameworks Accordion */}
              <div className="border rounded-lg mb-4">
                <button
                  onClick={() => toggleAccordion('frameworks')}
                  className="w-full flex items-center justify-between p-4 text-left hover:bg-gray-50"
                >
                  <span className="font-medium">OSINT Frameworks</span>
                  <span>{openAccordion === 'frameworks' ? '−' : '+'}</span>
                </button>
                {openAccordion === 'frameworks' && (
                  <div className="border-t p-4 space-y-4">
                    <div className="p-4 border rounded-lg">
                      <h4 className="font-semibold text-blue-600">OSINT Framework</h4>
                      <p className="text-sm text-slate-600 mb-2">Comprehensive directory of OSINT tools organized by category</p>
                      <a href="https://osintframework.com/" target="_blank" rel="noopener noreferrer"
                         className="text-blue-600 hover:underline text-sm">https://osintframework.com/</a>
                    </div>
                    <div className="p-4 border rounded-lg">
                      <h4 className="font-semibold text-blue-600">Maltego CE</h4>
                      <p className="text-sm text-slate-600 mb-2">Graph-based OSINT and link analysis tool</p>
                      <a href="https://www.maltego.com/" target="_blank" rel="noopener noreferrer"
                         className="text-blue-600 hover:underline text-sm">https://www.maltego.com/</a>
                    </div>
                  </div>
                )}
              </div>

              {/* Discovery Tools Accordion */}
              <div className="border rounded-lg mb-4">
                <button
                  onClick={() => toggleAccordion('discovery')}
                  className="w-full flex items-center justify-between p-4 text-left hover:bg-gray-50"
                >
                  <span className="font-medium">Discovery Tools</span>
                  <span>{openAccordion === 'discovery' ? '−' : '+'}</span>
                </button>
                {openAccordion === 'discovery' && (
                  <div className="border-t p-4 space-y-4">
                    <div className="p-4 border rounded-lg">
                      <h4 className="font-semibold text-blue-600">Shodan</h4>
                      <p className="text-sm text-slate-600 mb-2">Search engine for connected devices and exposed infrastructure</p>
                      <a href="https://www.shodan.io/" target="_blank" rel="noopener noreferrer"
                         className="text-blue-600 hover:underline text-sm">https://www.shodan.io/</a>
                    </div>
                    <div className="p-4 border rounded-lg">
                      <h4 className="font-semibold text-blue-600">Censys</h4>
                      <p className="text-sm text-slate-600 mb-2">Internet-wide scanning and device discovery platform</p>
                      <a href="https://censys.com/" target="_blank" rel="noopener noreferrer"
                         className="text-blue-600 hover:underline text-sm">https://censys.com/</a>
                    </div>
                    <div className="p-4 border rounded-lg">
                      <h4 className="font-semibold text-blue-600">theHarvester</h4>
                      <p className="text-sm text-slate-600 mb-2">Email, subdomain, and host discovery tool</p>
                      <a href="https://www.edge-security.com/" target="_blank" rel="noopener noreferrer"
                         className="text-blue-600 hover:underline text-sm">https://www.edge-security.com/</a>
                    </div>
                  </div>
                )}
              </div>

              {/* Reconnaissance Tools Accordion */}
              <div className="border rounded-lg">
                <button
                  onClick={() => toggleAccordion('recon')}
                  className="w-full flex items-center justify-between p-4 text-left hover:bg-gray-50"
                >
                  <span className="font-medium">Reconnaissance Tools</span>
                  <span>{openAccordion === 'recon' ? '−' : '+'}</span>
                </button>
                {openAccordion === 'recon' && (
                  <div className="border-t p-4 space-y-4">
                    <div className="p-4 border rounded-lg">
                      <h4 className="font-semibold text-blue-600">Recon-ng</h4>
                      <p className="text-sm text-slate-600 mb-2">Web reconnaissance framework for penetration testers</p>
                      <a href="https://github.com/lanmaster53/recon-ng" target="_blank" rel="noopener noreferrer"
                         className="text-blue-600 hover:underline text-sm">https://github.com/lanmaster53/recon-ng</a>
                    </div>
                    <div className="p-4 border rounded-lg">
                      <h4 className="font-semibold text-blue-600">Google Dorks Database</h4>
                      <p className="text-sm text-slate-600 mb-2">Search engine query strings for OSINT discovery</p>
                      <a href="https://www.exploit-db.com/google-hacking-database" target="_blank" rel="noopener noreferrer"
                         className="text-blue-600 hover:underline text-sm">https://www.exploit-db.com/google-hacking-database</a>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Threat Intelligence Tab */}
        {activeTab === 'threat-intel' && (
          <div className="bg-white rounded-lg shadow-sm">
            <div className="p-6 border-b">
              <div className="flex items-center">
                <AlertTriangle className="h-6 w-6 mr-2 text-red-600" />
                <h2 className="text-2xl font-bold">Threat Intelligence Platforms</h2>
              </div>
              <p className="text-slate-600 mt-2">
                Platforms for sharing and analyzing threat intelligence and indicators of compromise
              </p>
            </div>
            <div className="p-6 space-y-4">
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-red-600">MISP</h4>
                <p className="text-sm text-slate-600 mb-2">Open-source threat intelligence platform for sharing IoCs</p>
                <a href="https://www.misp-project.org/" target="_blank" rel="noopener noreferrer"
                   className="text-red-600 hover:underline text-sm">https://www.misp-project.org/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-red-600">AlienVault OTX</h4>
                <p className="text-sm text-slate-600 mb-2">Free community threat intelligence feed</p>
                <a href="https://otx.alienvault.com/" target="_blank" rel="noopener noreferrer"
                   className="text-red-600 hover:underline text-sm">https://otx.alienvault.com/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-red-600">Abuse.ch</h4>
                <p className="text-sm text-slate-600 mb-2">Malware and botnet tracking (includes SSL Blacklists, URLhaus, MalwareBazaar)</p>
                <a href="https://abuse.ch/" target="_blank" rel="noopener noreferrer"
                   className="text-red-600 hover:underline text-sm">https://abuse.ch/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-red-600">VirusTotal</h4>
                <p className="text-sm text-slate-600 mb-2">Free file and URL scanning against multiple antivirus engines</p>
                <a href="https://www.virustotal.com/" target="_blank" rel="noopener noreferrer"
                   className="text-red-600 hover:underline text-sm">https://www.virustotal.com/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-red-600">GreyNoise</h4>
                <p className="text-sm text-slate-600 mb-2">Distinguishes between background internet scanning and targeted threats</p>
                <a href="https://greynoise.io/" target="_blank" rel="noopener noreferrer"
                   className="text-red-600 hover:underline text-sm">https://greynoise.io/</a>
              </div>
            </div>
          </div>
        )}

        {/* DFIR Tab */}
        {activeTab === 'dfir' && (
          <div className="bg-white rounded-lg shadow-sm">
            <div className="p-6 border-b">
              <div className="flex items-center">
                <Eye className="h-6 w-6 mr-2 text-purple-600" />
                <h2 className="text-2xl font-bold">Digital Forensics & Incident Response (DFIR)</h2>
              </div>
              <p className="text-slate-600 mt-2">
                Tools for digital forensics analysis and incident response investigations
              </p>
            </div>
            <div className="p-6 space-y-4">
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-purple-600">Autopsy</h4>
                <p className="text-sm text-slate-600 mb-2">Digital forensics platform for analyzing disks and files</p>
                <a href="https://www.sleuthkit.org/autopsy/" target="_blank" rel="noopener noreferrer"
                   className="text-purple-600 hover:underline text-sm">https://www.sleuthkit.org/autopsy/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-purple-600">Volatility</h4>
                <p className="text-sm text-slate-600 mb-2">Memory forensics framework</p>
                <a href="https://www.volatilityfoundation.org/" target="_blank" rel="noopener noreferrer"
                   className="text-purple-600 hover:underline text-sm">https://www.volatilityfoundation.org/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-purple-600">KAPE</h4>
                <p className="text-sm text-slate-600 mb-2">Evidence collection and analysis tool</p>
                <a href="https://www.kroll.com/en/services/cyber-risk/digital-forensics/kroll-artifact-parser-extractor-kape" target="_blank" rel="noopener noreferrer"
                   className="text-purple-600 hover:underline text-sm">Kroll KAPE Tool</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-purple-600">Wireshark</h4>
                <p className="text-sm text-slate-600 mb-2">Packet capture and network protocol analysis</p>
                <a href="https://www.wireshark.org/" target="_blank" rel="noopener noreferrer"
                   className="text-purple-600 hover:underline text-sm">https://www.wireshark.org/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-purple-600">NetworkMiner</h4>
                <p className="text-sm text-slate-600 mb-2">Network forensic analysis tool</p>
                <a href="https://www.netresec.com/?page=NetworkMiner" target="_blank" rel="noopener noreferrer"
                   className="text-purple-600 hover:underline text-sm">https://www.netresec.com/?page=NetworkMiner</a>
              </div>
            </div>
          </div>
        )}

        {/* Penetration Testing Tab */}
        {activeTab === 'pentest' && (
          <div className="bg-white rounded-lg shadow-sm">
            <div className="p-6 border-b">
              <div className="flex items-center">
                <Zap className="h-6 w-6 mr-2 text-orange-600" />
                <h2 className="text-2xl font-bold">Penetration Testing & Red Team Tools</h2>
              </div>
              <p className="text-slate-600 mt-2">
                Tools for security testing, vulnerability assessment, and red team operations
              </p>
            </div>
            <div className="p-6 space-y-4">
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-orange-600">Kali Linux</h4>
                <p className="text-sm text-slate-600 mb-2">Penetration testing Linux distribution</p>
                <a href="https://www.kali.org/" target="_blank" rel="noopener noreferrer"
                   className="text-orange-600 hover:underline text-sm">https://www.kali.org/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-orange-600">Parrot OS</h4>
                <p className="text-sm text-slate-600 mb-2">Security-focused operating system for penetration testing</p>
                <a href="https://www.parrotsec.org/" target="_blank" rel="noopener noreferrer"
                   className="text-orange-600 hover:underline text-sm">https://www.parrotsec.org/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-orange-600">Metasploit Framework</h4>
                <p className="text-sm text-slate-600 mb-2">Exploitation and testing framework</p>
                <a href="https://www.metasploit.com/" target="_blank" rel="noopener noreferrer"
                   className="text-orange-600 hover:underline text-sm">https://www.metasploit.com/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-orange-600">Burp Suite Community Edition</h4>
                <p className="text-sm text-slate-600 mb-2">Web application security testing</p>
                <a href="https://portswigger.net/burp/communitydownload" target="_blank" rel="noopener noreferrer"
                   className="text-orange-600 hover:underline text-sm">https://portswigger.net/burp/communitydownload</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-orange-600">Nmap</h4>
                <p className="text-sm text-slate-600 mb-2">Network discovery and security scanner</p>
                <a href="https://nmap.org/" target="_blank" rel="noopener noreferrer"
                   className="text-orange-600 hover:underline text-sm">https://nmap.org/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-orange-600">OWASP ZAP</h4>
                <p className="text-sm text-slate-600 mb-2">Free web application security scanner</p>
                <a href="https://www.zaproxy.org/" target="_blank" rel="noopener noreferrer"
                   className="text-orange-600 hover:underline text-sm">https://www.zaproxy.org/</a>
              </div>
            </div>
          </div>
        )}

        {/* Defense Tab */}
        {activeTab === 'defense' && (
          <div className="bg-white rounded-lg shadow-sm">
            <div className="p-6 border-b">
              <div className="flex items-center">
                <Shield className="h-6 w-6 mr-2 text-green-600" />
                <h2 className="text-2xl font-bold">Monitoring, Detection & Defense</h2>
              </div>
              <p className="text-slate-600 mt-2">
                Tools for network monitoring, intrusion detection, and security defense
              </p>
            </div>
            <div className="p-6 space-y-4">
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-green-600">Zeek</h4>
                <p className="text-sm text-slate-600 mb-2">Network security monitoring framework</p>
                <a href="https://zeek.org/" target="_blank" rel="noopener noreferrer"
                   className="text-green-600 hover:underline text-sm">https://zeek.org/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-green-600">Snort</h4>
                <p className="text-sm text-slate-600 mb-2">Open-source intrusion detection and prevention system</p>
                <a href="https://www.snort.org/" target="_blank" rel="noopener noreferrer"
                   className="text-green-600 hover:underline text-sm">https://www.snort.org/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-green-600">Suricata</h4>
                <p className="text-sm text-slate-600 mb-2">High-performance IDS/IPS engine</p>
                <a href="https://suricata.io/" target="_blank" rel="noopener noreferrer"
                   className="text-green-600 hover:underline text-sm">https://suricata.io/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-green-600">Wazuh</h4>
                <p className="text-sm text-slate-600 mb-2">Open-source SIEM and security monitoring platform</p>
                <a href="https://wazuh.com/" target="_blank" rel="noopener noreferrer"
                   className="text-green-600 hover:underline text-sm">https://wazuh.com/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-green-600">Security Onion</h4>
                <p className="text-sm text-slate-600 mb-2">Free Linux distro for intrusion detection, log management, and threat hunting</p>
                <a href="https://securityonion.net/" target="_blank" rel="noopener noreferrer"
                   className="text-green-600 hover:underline text-sm">https://securityonion.net/</a>
              </div>
            </div>
          </div>
        )}

        {/* GRC Tab */}
        {activeTab === 'grc' && (
          <div className="bg-white rounded-lg shadow-sm">
            <div className="p-6 border-b">
              <div className="flex items-center">
                <Lock className="h-6 w-6 mr-2 text-indigo-600" />
                <h2 className="text-2xl font-bold">Governance, Risk & Compliance (GRC)</h2>
              </div>
              <p className="text-slate-600 mt-2">
                Frameworks and standards for cybersecurity governance and compliance
              </p>
            </div>
            <div className="p-6 space-y-4">
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-indigo-600">CIS Benchmarks</h4>
                <p className="text-sm text-slate-600 mb-2">Security configuration standards</p>
                <a href="https://www.cisecurity.org/cis-benchmarks/" target="_blank" rel="noopener noreferrer"
                   className="text-indigo-600 hover:underline text-sm">https://www.cisecurity.org/cis-benchmarks/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-indigo-600">MITRE ATT&CK</h4>
                <p className="text-sm text-slate-600 mb-2">Adversary tactics, techniques, and procedures (TTPs) framework</p>
                <a href="https://attack.mitre.org/" target="_blank" rel="noopener noreferrer"
                   className="text-indigo-600 hover:underline text-sm">https://attack.mitre.org/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-indigo-600">NIST Cybersecurity Framework</h4>
                <p className="text-sm text-slate-600 mb-2">U.S. best practice framework for cybersecurity</p>
                <a href="https://www.nist.gov/cyberframework" target="_blank" rel="noopener noreferrer"
                   className="text-indigo-600 hover:underline text-sm">https://www.nist.gov/cyberframework</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-indigo-600">ISO/IEC 27001</h4>
                <p className="text-sm text-slate-600 mb-2">International standard for information security management</p>
                <a href="https://www.iso.org/isoiec-27001-information-security.html" target="_blank" rel="noopener noreferrer"
                   className="text-indigo-600 hover:underline text-sm">https://www.iso.org/isoiec-27001-information-security.html</a>
              </div>
            </div>
          </div>
        )}

        {/* Training Tab */}
        {activeTab === 'training' && (
          <div className="bg-white rounded-lg shadow-sm">
            <div className="p-6 border-b">
              <div className="flex items-center">
                <Book className="h-6 w-6 mr-2 text-teal-600" />
                <h2 className="text-2xl font-bold">Training & Knowledge Resources</h2>
              </div>
              <p className="text-slate-600 mt-2">
                Educational platforms and resources for cybersecurity skill development
              </p>
            </div>
            <div className="p-6 space-y-4">
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-teal-600">Cybrary</h4>
                <p className="text-sm text-slate-600 mb-2">Free and paid cybersecurity training courses</p>
                <a href="https://www.cybrary.it/" target="_blank" rel="noopener noreferrer"
                   className="text-teal-600 hover:underline text-sm">https://www.cybrary.it/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-teal-600">TryHackMe</h4>
                <p className="text-sm text-slate-600 mb-2">Guided practical cybersecurity labs</p>
                <a href="https://tryhackme.com/" target="_blank" rel="noopener noreferrer"
                   className="text-teal-600 hover:underline text-sm">https://tryhackme.com/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-teal-600">Hack The Box</h4>
                <p className="text-sm text-slate-600 mb-2">Hands-on ethical hacking training</p>
                <a href="https://www.hackthebox.com/" target="_blank" rel="noopener noreferrer"
                   className="text-teal-600 hover:underline text-sm">https://www.hackthebox.com/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-teal-600">OWASP Top 10</h4>
                <p className="text-sm text-slate-600 mb-2">Most critical web application security risks</p>
                <a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener noreferrer"
                   className="text-teal-600 hover:underline text-sm">https://owasp.org/www-project-top-ten/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-teal-600">SANS Reading Room</h4>
                <p className="text-sm text-slate-600 mb-2">Whitepapers on cybersecurity and DFIR</p>
                <a href="https://www.sans.org/white-papers/" target="_blank" rel="noopener noreferrer"
                   className="text-teal-600 hover:underline text-sm">https://www.sans.org/white-papers/</a>
              </div>
            </div>
          </div>
        )}

        {/* Regional Tab */}
        {activeTab === 'regional' && (
          <div className="bg-white rounded-lg shadow-sm">
            <div className="p-6 border-b">
              <div className="flex items-center">
                <Map className="h-6 w-6 mr-2 text-emerald-600" />
                <h2 className="text-2xl font-bold">Papua New Guinea & Regional Context</h2>
              </div>
              <p className="text-slate-600 mt-2">
                Regional cybersecurity frameworks and PNG-specific resources
              </p>
            </div>
            <div className="p-6 space-y-4">
              <div className="p-4 border rounded-lg bg-emerald-50">
                <h4 className="font-semibold text-emerald-600">National Cybersecurity Strategy (DICT PNG)</h4>
                <p className="text-sm text-slate-600 mb-2">Alignment with government digital policies and national cybersecurity framework</p>
                <span className="inline-block px-2 py-1 text-xs border border-emerald-600 text-emerald-600 rounded">PNG Government</span>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-emerald-600">Pacific Cyber Security Operational Network (PaCSON)</h4>
                <p className="text-sm text-slate-600 mb-2">Regional collaboration framework for Pacific Island nations</p>
                <span className="inline-block px-2 py-1 text-xs border border-emerald-600 text-emerald-600 rounded">Regional</span>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-emerald-600">APNIC Security Resources</h4>
                <p className="text-sm text-slate-600 mb-2">Best practices for network security in Asia-Pacific region</p>
                <a href="https://www.apnic.net/" target="_blank" rel="noopener noreferrer"
                   className="text-emerald-600 hover:underline text-sm">https://www.apnic.net/</a>
              </div>
            </div>
          </div>
        )}

        {/* Utilities Tab */}
        {activeTab === 'utilities' && (
          <div className="bg-white rounded-lg shadow-sm">
            <div className="p-6 border-b">
              <div className="flex items-center">
                <Wrench className="h-6 w-6 mr-2 text-amber-600" />
                <h2 className="text-2xl font-bold">Additional Free Utility Tools</h2>
              </div>
              <p className="text-slate-600 mt-2">
                Useful utilities for cybersecurity analysis and testing
              </p>
            </div>
            <div className="p-6 space-y-4">
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-amber-600">Have I Been Pwned</h4>
                <p className="text-sm text-slate-600 mb-2">Email breach checking service</p>
                <a href="https://haveibeenpwned.com/" target="_blank" rel="noopener noreferrer"
                   className="text-amber-600 hover:underline text-sm">https://haveibeenpwned.com/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-amber-600">DNSDumpster</h4>
                <p className="text-sm text-slate-600 mb-2">Domain and DNS intelligence gathering</p>
                <a href="https://dnsdumpster.com/" target="_blank" rel="noopener noreferrer"
                   className="text-amber-600 hover:underline text-sm">https://dnsdumpster.com/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-amber-600">Regex101</h4>
                <p className="text-sm text-slate-600 mb-2">Tool for testing and debugging regular expressions</p>
                <a href="https://regex101.com/" target="_blank" rel="noopener noreferrer"
                   className="text-amber-600 hover:underline text-sm">https://regex101.com/</a>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-amber-600">SSL Labs</h4>
                <p className="text-sm text-slate-600 mb-2">SSL/TLS server configuration testing</p>
                <a href="https://www.ssllabs.com/ssltest/" target="_blank" rel="noopener noreferrer"
                   className="text-amber-600 hover:underline text-sm">https://www.ssllabs.com/ssltest/</a>
              </div>
            </div>
          </div>
        )}

        {/* About Tab */}
        {activeTab === 'about' && (
          <div className="bg-white rounded-lg shadow-sm">
            <div className="p-6 border-b">
              <div className="flex items-center">
                <Globe className="h-6 w-6 mr-2 text-slate-600" />
                <h2 className="text-2xl font-bold">About This Resource Hub</h2>
              </div>
              <p className="text-slate-600 mt-2">
                Information about the structure and usage of this cybersecurity resource website
              </p>
            </div>
            <div className="p-6 space-y-6">
              <div className="p-4 border rounded-lg bg-slate-50">
                <h4 className="font-semibold text-slate-700 mb-2">Purpose</h4>
                <p className="text-sm text-slate-600">
                  This resource hub serves as a centralized reference for cybersecurity professionals in the
                  Papua New Guinea Department of Information Technology. It provides curated access to essential
                  tools, frameworks, and knowledge resources for various cybersecurity functions.
                </p>
              </div>

              <div className="p-4 border rounded-lg bg-yellow-50">
                <h4 className="font-semibold text-yellow-700 mb-2">Important Disclaimer</h4>
                <p className="text-sm text-yellow-700">
                  <strong>Authorization Required:</strong> All tools and resources listed on this site are intended
                  for use by authorized cybersecurity professionals only. Unauthorized use of these tools may violate
                  laws and regulations. Users are responsible for ensuring compliance with all applicable legal and
                  ethical guidelines.
                </p>
              </div>

              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-slate-700 mb-2">Structure</h4>
                <ul className="text-sm text-slate-600 space-y-1">
                  <li>• <strong>OSINT:</strong> Open-source intelligence gathering tools</li>
                  <li>• <strong>Threat Intel:</strong> Threat intelligence platforms and feeds</li>
                  <li>• <strong>DFIR:</strong> Digital forensics and incident response tools</li>
                  <li>• <strong>Pentest:</strong> Penetration testing and red team utilities</li>
                  <li>• <strong>Defense:</strong> Monitoring, detection, and defensive tools</li>
                  <li>• <strong>GRC:</strong> Governance, risk, and compliance frameworks</li>
                  <li>• <strong>Training:</strong> Educational and skill development resources</li>
                  <li>• <strong>Regional:</strong> PNG and Pacific region specific resources</li>
                  <li>• <strong>Utilities:</strong> General cybersecurity utility tools</li>
                  <li>• <strong>News:</strong> Latest cybersecurity threats and advisories</li>
                  <li>• <strong>Submit:</strong> Resource submission form for authorized users</li>
                </ul>
              </div>

              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-slate-700 mb-2">New Features</h4>
                <ul className="text-sm text-slate-600 space-y-1">
                  <li>• <strong>Search:</strong> Find tools across all categories instantly</li>
                  <li>• <strong>Authentication:</strong> Secure login for authorized personnel</li>
                  <li>• <strong>News Updates:</strong> Latest threat intelligence and advisories</li>
                  <li>• <strong>Resource Submission:</strong> Submit new tools for review</li>
                </ul>
              </div>

              <div className="p-4 border rounded-lg">
                <h4 className="font-semibold text-slate-700 mb-2">Maintenance</h4>
                <p className="text-sm text-slate-600">
                  This resource hub is reviewed and updated quarterly to ensure accuracy and relevance.
                  For suggestions or additions, please contact the Cybersecurity Center administration or use the Submit feature.
                </p>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="bg-slate-800 text-white py-6 mt-12">
        <div className="container mx-auto px-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-300">
                © 2025 Department of Information & Communication Technology, Papua New Guinea Government
              </p>
              <p className="text-xs text-slate-400 mt-1">
                For authorized personnel use only. Enhanced with search, authentication, news, and submission features.
              </p>
            </div>
            <div className="text-right">
              <span className="inline-block px-3 py-1 border border-emerald-400 text-emerald-400 rounded text-sm">
                Version 2.0
              </span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
