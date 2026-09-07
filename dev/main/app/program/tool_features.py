"""Per-tool feature lists for the Pentest Tools catalog.

Maps each tool name to a list of capability / usage feature strings. These
enrich every catalog record (API + CLI + Website) under a ``features`` key so
users see not only *what* a tool is, but *what it does*.

Bulk data lives here (not inline in tools_catalog.py) to keep the catalog
parser readable.
"""

from __future__ import annotations

TOOL_FEATURES: dict[str, list[str]] = {
    # ------------------------------------------------------------------
    # recon
    # ------------------------------------------------------------------
    "whois": [
        "Query WHOIS registration records for a domain, IP, or ASN",
        "Show registrar, registrant org, name servers, and status codes",
        "Determine domain creation / updated / expiry dates",
    ],
    "DNSrecon-gui": [
        "Graphical front-end for the DNSrecon enumeration tool",
        "Run standard, brute-force, and zone-transfer DNS checks from a GUI",
        "View A/AAAA/MX/NS/TXT/SRV records per target",
    ],
    "Dnsx": [
        "Fast, multi-purpose DNS toolkit (projectdiscovery)",
        "Resolve hosts to A/AAAA/CNAME across custom resolvers",
        "Enumerate MX/NS/TXT/SOA/PTR and wildcard detection",
        "Input via stdin or file lists with JSON/CSV output",
    ],
    "subDomainsBrute": [
        "Fast subdomain brute forcer with built-in wordlists",
        "Multi-threaded brute force against a target domain",
        "Reports valid subdomains with resolved IPs",
    ],
    "ksubdomain": [
        "Asynchronous subdomain enumeration using raw DNS packets (pcap)",
        "Scans ~1,600,000 subdomains per second",
        "Handles wildcard filtering and live host output",
    ],
    "Sublist3r": [
        "Fast subdomain enumeration for penetration testers",
        "Combines search engines (Google, Baidu, Yahoo) with DNS",
        "Passive approach with low footprint on the target",
    ],
    "OneForAll": [
        "Powerful subdomain integration / collection tool",
        "Aggregates many passive + active sources with deduplication",
        "Exports clean host lists with resolving data",
    ],
    "LayerDomainFinder": [
        "Layer-brand GUI subdomain enumeration tool",
        "Scan a domain for valid subdomains from a dictionary",
        "Export findings for follow-up scanning",
    ],
    "ct": [
        "Collect certificate-transparency info about a target domain",
        "Harvest related domains from crt.sh / CT logs",
        "Map subdomain and sibling-domain relationships",
    ],
    "Subfinder": [
        "Passive subdomain discovery framework (projectdiscovery)",
        "Queries many passive sources with zero footprint",
        "Fast, safe for bug bounties; JSON/CSV output",
    ],
    "Probable_subdomains": [
        "Subdomain analysis and generation (wordlist + mutation)",
        "Reveals hidden subdomains from a wordlist",
        "Wordlist generation for later brute forcing",
    ],
    "domains": [
        "Online subdomain + wordlist generator",
        "Generate domain mutations and targeted wordlists",
        "Useful companion for subdomain brute forcing",
    ],
    "MassDNS": [
        "High-performance DNS stub resolver (millions of records)",
        "Resolves massive host lists extremely fast over UDP/TCP",
        "Ideal companion for subdomain brute forcing",
    ],
    "altdns": [
        "Subdomain permutation / alteration generator",
        "Mutates known subdomains (dev, staging, test, ...)",
        "Feed mutations back into a resolver for new hosts",
    ],
    "dnscan": [
        "Fast, lightweight DNS brute forcer with built-in wordlist",
        "Zone-transfer check against authoritative servers",
        "Simple CNAME/A/AAAA resolution output",
    ],
    "GHDB": [
        "Google Hacking Database — searchable dork archive",
        "Find files, login portals, and exposed assets via dorks",
        "Browse by category (vulnerable files, sensitive dirs, ...)",
    ],
    "SearchDiggity": [
        "Google Hacking Diggity Project attack tool",
        "Runs Google/Bing/Shodan dork searches automatically",
        "Scans three vectors: files, pages, and open ports",
    ],
    "Katana": [
        "Python tool for automated Google hacking (dorks)",
        "Build and execute targeted dork queries",
        "Collect matching URLs/domains for follow-up",
    ],
    "GooFuzz": [
        "OSINT-style fuzzing via Google dorks, no target traffic",
        "Enumerate directories, files, subdomains, parameters passively",
        "Searches the indexed web instead of hitting the target",
    ],
    "Pagodo": [
        "Passive Google Dork — automate GHDB scraping + dork search",
        "Download the GHDB and run dork queries headlessly",
        "Gather indexed URLs without touching the target",
    ],
    "Google-Dorks": [
        "Curated collection of useful Google dorks",
        "Dorks for web security and bug bounty recon",
        "Quick-start examples for hunters and pentesters",
    ],
    "GitHacker": [
        "GIT source-leak exploit / recovery tool",
        "Restores the full Git repo from an exposed .git dir",
        "Recovers stashed, dangling, and deleted objects",
    ],
    "GitGraber": [
        "Monitors GitHub for sensitive data and credentials",
        "Searches public repos for API keys, tokens, secrets",
        "Real-time monitoring of selected orgs/users",
    ],
    "GitHound": [
        "GitHub Code Search API secret hunting",
        "Finds exposed API keys across all of GitHub",
        "Web dashboard to filter and track results",
    ],
    "GitMiner": [
        "Advanced GitHub content mining",
        "Regex/keyword scanning across repos and commits",
        "Custom rule sets for secrets and tokens",
    ],
    "Gitrob": [
        "GitHub organization reconnaissance",
        "Fingerprint orgs and repos for leaked secrets",
        "Prioritized list of compromised-looking files",
    ],
    "GitGot": [
        "Semi-automated GitHub secret search (feedback-driven)",
        "Rapid targeted searches with token support",
        "Iterative refinement to reduce noise",
    ],
    "GitDump": [
        "Dumps source code from .git even with traversal disabled",
        "Recovers objects and reconstructs files",
        "Works on misconfigured git-deployed web roots",
    ],
    "svnExploit": [
        "SVN source-code disclosure exploit",
        "Dumps the full working copy from an exposed .svn",
        "Supports both password-less and authenticated retrieval",
    ],
    "SvnHack": [
        "SVN folder disclosure exploit",
        "Enumerates .svn directories on web servers",
        "Harvests leaked source and config files",
    ],
    "Nmap | Zenmap": [
        "Industry-standard network discovery / security auditing",
        "Port scanning with service + version detection (-sV)",
        "Script engine (NSE) for vuln and exploit checks",
        "Zenmap GUI with topology and profiling",
    ],
    "Masscan": [
        "Asynchronous TCP port scanner (SYN flood speed)",
        "Scans the whole internet in minutes",
        "Banner grab and target randomization options",
    ],
    "Ports": [
        "Reference list of common service ports and their exploitation",
        "Quick lookup of port → service → common attack vectors",
    ],
    "Goby": [
        "Attack-surface mapping / red-team asset discovery",
        "NAGBI-style topology mapping and visual analysis",
        "Predefined security scan flows",
    ],
    "Gobyu-POC": [
        "Community POC collection for Goby",
        "Download/import POCs for Goby scan flows",
        "Extend Goby coverage with community templates",
    ],
    "Goscan": [
        "Interactive network scanner (Go)",
        "Fast port discovery with banner grabbing",
        "Colors and live progress for large ranges",
    ],
    "NimScan": [
        "Very fast TCP port scanner written in Nim",
        "Parallel scanning with service/version detection",
        "Chainable with other recon tools",
    ],
    "RustScan": [
        "Modern, ultra-fast port scanner (Rust)",
        "Adaptive port detection then integration with Nmap",
        "Aggressive speed with smart defaults",
    ],
    "TXPortMap": [
        "TianXiang port scanner + banner identifier",
        "Fast SYN/full-connect scanning with fingerprinting",
        "Service and banner identification for open ports",
    ],
    "Scaninfo": [
        "Fast red-team network scanner",
        "Combines port, service, and vulnerability probing",
        "Lightweight and concurrency-oriented",
    ],
    "SX": [
        "Fast, modern, easy-to-use network scanner",
        "SYN scan with configurable range and concurrency",
        "Right-click friendly CLI output",
    ],
    "Yujianportscan": [
        "VB.NET + IOCP fast port-scan GUI",
        "High-concurrency scanning with visual results",
        "Save/export scan summaries",
    ],
    "Naabu": [
        "Fast port scanner (projectdiscovery), reliability-focused",
        "SYN/CONNECT scanning with host discovery",
        "Integrates with nmap/Host header and JSON output",
    ],
    "ServerScan": [
        "High-concurrency network scanning + service detection (Go)",
        "Auto-detect common services and banners",
        "Configurable port ranges and threading",
    ],
    "Netspy": [
        "Detect reachable network segments on the intranet",
        "Probe egress/blind segments for pivot paths",
        "Accelerates lateral movement planning",
    ],
    "Cube": [
        "Intranet penetration toolkit",
        "Weak-password blasting and service brute force",
        "Information collection and vulnerability scanning",
    ],
    "Sn1per": [
        "Automated pentest reconnaissance scanner",
        "One-shot recon: port, web, vuln, and exploit checks",
        "Building-block framework for pentesters",
    ],
    "wayparam": [
        "Discovers hidden / undocumented parameters and endpoints",
        "Normalizes and mutates request inputs",
        "Highlights input-handling and behavior differences",
    ],
    # ------------------------------------------------------------------
    # osint
    # ------------------------------------------------------------------
    "theHarvester": [
        "Search engines + PGP + SHODAN for emails and subdomains",
        "Harvest employee names, hosts, and virtual hosts",
        "Export results to HTML/JSON/XML/CSV",
        "Passive recon for the first stage of an engagement",
    ],
    "SpiderFoot": [
        "Multi-source OSINT automation engine",
        "200+ modules: DNS, subdomains, emails, IPs, breach data",
        "Web UI, correlation rules, and report visualization",
        "Entity graph + timeline view of collected intelligence",
    ],
    "Recon-ng": [
        "Full-featured web reconnaissance framework (Python)",
        "Modular: API key management, workspaces, marketplaces",
        "Harvest hosts, contacts, credentials, and profiles",
        "Resemble Metasploit for the recon phase",
    ],
    "FOCA": [
        "Metadata / hidden info extraction from documents",
        "Scan Office/PDF files for author, PRINTER, GPS metadata",
        "Discover network info, users, and software from documents",
    ],
    "Amass": [
        "In-depth attack-surface mapping and asset discovery",
        "OWASP project; active + passive subdomain enumeration",
        "DNS brute force, cert-transparency, reverse whois",
        "Track domain ownership and infrastructure over time",
    ],
    "Censys-subdomain-finder": [
        "Subdomain enumeration from Censys certificate-transparency logs",
        "Passive, no traffic to the target",
        "Fast and reliable for asset discovery",
    ],
    "EmailHarvester": [
        "Harvest email addresses from search engines",
        "Passive recon for phishing and OSINT",
        "Export found addresses to a file",
    ],
    "Finalrecon": [
        "All-in-one last web recon tool",
        "Header analysis, WHOIS, DNS, SSL, and wordpress checks",
        "CLI with optional Tor support",
    ],
    "LittleBrother": [
        "OSINT on a person (EU-focused)",
        "Gather social profiles, mail, and public records",
        "Aggregates passive info for background checks",
    ],
    "Octosuite": [
        "Advanced GitHub OSINT framework",
        "Recon on repositories, orgs, users, and commits",
        "Great for tracking developers and code exposure",
    ],
    "octosuite (bellingcat)": [
        "Bellingcat fork of the Octosuite GitHub OSINT framework",
        "GitHub OSINT on users, repos and organizations",
        "Companion advanced GitHub research toolkit",
    ],
    "Kunyu": [
        "Corporate asset collection (ZoomEye-based)",
        "Efficient discovery of an organization's public assets",
        "CLI + web interface for asset mapping",
    ],
    "Glass": [
        "OSINT framework with Fofa/ZoomEye/Shodan/360 API",
        "Asset + fingerprint searching across Chinese datasets",
        "Multi-API aggregation for asset discovery",
    ],
    "BBOT": [
        "OSINT automation for hackers",
        "Modular, curated scans with hundreds of modules",
        "Great output formats: JSON, graph, nexial",
        "Fast and memory-efficient recon runs",
    ],
    "GHunt": [
        "Offensive Google framework (OSINT)",
        "Extract info from Google accounts and Photos",
        "Enumerate GAIA IDs and public profile data",
    ],
    "DataSploit": [
        "OSINT visualizer with Shodan/Censys/Clearbit backends",
        "Automated passive recon for domains, emails, IPs",
        "Visual graph and report generation",
    ],
    "Depix": [
        "Recover passwords from pixelized (pixelated) screenshots",
        "De-pixelate text using character libraries",
        "Efficient for CAPTCHA-like obscured credentials",
    ],
    "Intrigue": [
        "Automated OSINT & attack-surface discovery framework",
        "REST API + web UI + CLI for asset enumeration",
        "Detects services, entities, secrets, and exposed data",
    ],
    "Maltego": [
        "Graph-based OSINT & forensics analysis",
        "Visual link analysis of people, domains, infrastructure",
        "Huge transform library from community / commercial",
        "Proprietary, widely used by investigators",
    ],
    "PacketTotal": [
        "Free packet capture analysis in the browser",
        "Upload PCAPs for instant Zeek + Suricata inspection",
        "Detects network-borne malware and C2 beaconing",
    ],
    "Skiptracer": [
        "OSINT scraping framework (BeautifulSoup)",
        "Scrape PII paywall sites for passive intel",
        "Budget-friendly ramen-noodle recon",
    ],
    "creepy": [
        "Geolocation OSINT tool",
        "Plot social-media location data on a map",
        "Aggregate GPS metadata from photos/posts",
    ],
    "gOSINT": [
        "OSINT tool with multiple modules and Telegram scraper",
        "Fetch, index, and search public data",
        "Extensible with custom modules",
    ],
    "image-match": [
        "Search over billions of images by similarity",
        "Perceptual hashing + high-speed matching",
        "Used for reverse-image and duplicate detection",
    ],
    "sn0int": [
        "Semi-automatic OSINT framework + package manager",
        "Run recon with community-registry modules",
        "SQLite storage, JSON output, C API",
    ],
    "Facebook Friend List Scraper": [
        "Scrape Facebook friend lists without rate-limit blocks",
        "Extract names and usernames passively",
        "For lateral OSINT on social graphs",
    ],
    # ------------------------------------------------------------------
    # vuln-scan
    # ------------------------------------------------------------------
    "httpX": [
        "Fast multi-purpose HTTP probe (projectdiscovery)",
        "Probe live hosts, tech, status, title, favicon",
        "Bulk URL/domain checking with TLS and CDN detection",
        "JSON / CSV output for pipelines",
    ],
    "Struts-Scan": [
        "Struts2 vulnerability detection and exploitation utility",
        "Detect known Struts RCE flaws (S2-xxx)",
        "Verification + exploit helpers for confirming issues",
    ],
    "Nikto": [
        "Open-source web server scanner (GPL)",
        "Tests hundreds of server items: vulnerable files, misconfig",
        "Detects outdated software and dangerous files/paths",
    ],
    "W3af": [
        "Web application attack and audit framework",
        "Discovers + exploits web vulns via plugins",
        "SQLi, XSS, file include, RCE detection",
        "GUI and console interfaces",
    ],
    "Openvas": [
        "Advanced open-source vulnerability scanner + manager",
        "Network vulnerability tests with plugin feeds (NVT)",
        "Scheduling, reports, and remediation tracking",
    ],
    "Openvas Docker": [
        "Containerised OpenVAS vulnerability scanner",
        "Runs the full Greenbone stack in Docker",
        "Reports + scheduling via the GVM web interface",
    ],
    "Archery": [
        "Open-source vulnerability assessment and management",
        "Combines multiple scanners into one dashboard",
        "Prioritization, tracking, and reporting platform",
    ],
    "Taipan": [
        "Web application vulnerability scanner",
        "Passive and active checks for web flaws",
        "Cross-platform with color output",
    ],
    "Arachni": [
        "Web application security scanner framework",
        "High-speed, coverage-oriented crawl + audit",
        "Detects SQLi, XSS, CSRF, path traversal, and more",
        "REST API + web UI for distributed scans",
    ],
    "Nuclei": [
        "Fast vulnerability scanner with YAML templates (projectdiscovery)",
        "Massive community template library (CVEs, exposures)",
        "Custom template DSL for specific checks",
        "Batch scanning thousands of hosts",
    ],
    "Xray": [
        "Passive vulnerability scanner (chaitin)",
        "Upstream/proxy-based detection of web flaws",
        "SQLi, XSS, RCE, file-read detection via traffic",
    ],
    "Super-Xray": [
        "GUI starter for the Xray scanner",
        "One-click run of passive scanning",
        "Pre-built cross-platform distribution",
    ],
    "SiteScan": [
        "All-in-one website information gathering tool",
        "Fingerprint, port, and web-info collection for pentest",
    ],
    "Banli": [
        "High-risk asset identification and high-risk vulnerability scanner",
        "Focuses on critical assets and CVE matches",
    ],
    "vscan": [
        "Open-source vulnerability scanner",
        "Fingerprint + CVE + web path scanning",
        "Runs common web vuln checks on targets",
    ],
    "Wapiti": [
        "Web vulnerability scanner (Python3)",
        "Active crawler + vulnerability audit module",
        "Detects SQLi, XSS, file disclosure, XXE, command injection",
    ],
    "osv-scanner": [
        "Go vulnerability scanner using OSV.dev data",
        "Scan lockfiles / SBOMs for known vulns",
        "CI-friendly, high signal-to-noise",
    ],
    "Afrog": [
        "Vulnerability scanning tool for penetration testing",
        "YAML-POC based, fast and easy to extend",
        "Covers many web vulnerabilities and CMS flaws",
    ],
    "OpalOPC": [
        "Vulnerability and misconfiguration scanner for OPC UA",
        "Audit industrial control / ICS endpoints",
        "CVE matching for OPC UA servers",
    ],
    "ZeroThreat": [
        "AI-powered web app & API vulnerability scanner",
        "Auto pentesting with attack-path validation",
        "Continuous monitoring for apps and APIs",
    ],
    "operant-mcp": [
        "MCP server: 51 security testing tools in 19 modules",
        "Modules: SQLi, XSS, CMDi, SSRF, path traversal, PCAP",
        "Includes memory forensics and malware analysis",
        "Install via npx operant-mcp",
    ],
    "Fuxi-Scanner": [
        "Open-source network security vulnerability scanner",
        "Port scan, service detection, and vuln detection modules",
        "Scheduled scans across a Docker deployment",
    ],
    "Xunfeng": [
        "Rapid emergency-response and cruise scanning system",
        "Enterprise intranet asset + vuln discovery",
        "Distributed agents for large networks",
    ],
    "WebMap": [
        "Nmap Web Dashboard and reporting",
        "Scan results visualized in a web UI",
        "Scheduling + report generation from Nmap data",
    ],
    "Pentest-Collaboration-Framework": [
        "Opensource cross-platform pentest automation toolkit",
        "Automate routine scanning processes",
        "Collect evidence and generate reports",
    ],
    # ------------------------------------------------------------------
    # webapp-cms
    # ------------------------------------------------------------------
    "AngelSword": [
        "CMS vulnerability detection framework",
        "Regex-based CMS fingerprinting",
        "Detect known CMS exploit signatures",
    ],
    "WhatWeb": [
        "Next-generation web scanner (fingerprinting)",
        "Identify CMS, framework, server, and plugins",
        "900+ plugins with passive/active heuristics",
        "Built-in logging and recursive scanning",
    ],
    "Wappalyzer": [
        "Cross-platform technology detection (browser + API)",
        "Identify CMS, frameworks, libraries, and analytics",
        "Browser extension for instant tech lookup",
    ],
    "Whatruns": [
        "Browser extension detecting technologies used on any site",
        "Identify frameworks, CMS, and libraries in one click",
        "Similar to Wappalyzer with a different database",
    ],
    "WhatCMS": [
        "CMS detection + exploit kit via Whatcms.org API",
        "Identify the CMS of a target URL",
        "Check exploit-db for known CMS vulnerabilities",
    ],
    "WhatCMS online": [
        "Online CMS detection (Whatcms.org)",
        "Identify CMS via URL in the browser",
        "Free public fingerprint lookup",
    ],
    "Yunsee": [
        "Online CMS footprint finder",
        "Identify the CMS/tech stack of a URL in the browser",
        "Supplementary online fingerprinting source",
    ],
    "Bugscaner": [
        "Online web fingerprint identification service",
        "Recognizes hundreds of CMS source codes",
        "Quick browser-based tech-stack lookup",
    ],
    "TideFinger": [
        "TideSec online fingerprint identification",
        "Web-based tech/CMS fingerprint lookup",
        "Community fingerprint database",
    ],
    "360finger-p": [
        "360 Team online fingerprint identification",
        "Web-based technology fingerprint lookup",
        "Fast, browser-friendly tech-stack checks",
    ],
    "CMSeeK": [
        "CMS detection and exploitation suite",
        "Detect WordPress, Joomla, Drupal and 180+ other CMS",
        "Extract version + run exploit checks on detected CMS",
    ],
    "EHole": [
        "CMS detection oriented for Red Team",
        "Fast fingerprinting with a large CMS signature DB",
        "Auto-match target to known CMS vulnerabilities",
    ],
    "ObserverWard": [
        "Cross-platform community web fingerprinting",
        "Fingerprint detection with a shared FingerprintHub database",
        "Identify web technologies with a single command",
    ],
    "FingerprintHub": [
        "Database powering ObserverWard fingerprints",
        "Community-maintained fingerprint signatures",
        "Plan/propose new fingerprints for the hub",
    ],
    # ------------------------------------------------------------------
    # webapp-proxy
    # ------------------------------------------------------------------
    "Burpsuite": [
        "Graphical tool for testing web application security",
        "Intercepting proxy for HTTP/HTTPS traffic",
        "Repeater, Intruder, Scanner, and Decoder modules",
        "Extensible via BApp extensions (community)",
    ],
    "ZAP": [
        "One of the world's most popular free security tools",
        "Intercepting proxy with active + passive scanning",
        "Automated attack modes and scripting (Zest)",
        "REST API for CI/CD integration",
    ],
    "Mitmproxy": [
        "Interactive TLS-capable intercepting HTTP proxy",
        "Scriptable traffic interception (Python addons)",
        "Capture, modify, and replay HTTP/2/WebSocket",
    ],
    "Broxy": [
        "HTTP/HTTPS intercept proxy written in Go",
        "Simple interactive UI for traffic inspection",
        "Modify and replay requests with ease",
    ],
    "Hetty": [
        "HTTP toolkit for security research",
        "Interception, replay, and XSS/injection testing",
        "GraphQL-powered UI, tcpdump-style capture",
    ],
    "Proxify": [
        "Swiss-army-knife proxy for HTTP/HTTPS capture",
        "Traffic capture, manipulation, and replay on the go",
        "projectdiscovery ecosystem integration",
    ],
    # ------------------------------------------------------------------
    # webapp-browser
    # ------------------------------------------------------------------
    "Hack-Tools": [
        "All-in-one Red Team browser extension",
        "Quick payloads, encoders, and recon helpers",
        "XSS, SQLi, SSTI, and SSRF utilities in the browser",
    ],
    # ------------------------------------------------------------------
    # webapp-crawler
    # ------------------------------------------------------------------
    "Dirbrute": [
        "Multi-thread WEB directory blasting tool",
        "Built-in directories dictionary",
        "Fast brute force of web paths",
    ],
    "Dirb": [
        "Web content scanner / dictionary attack on directories",
        "Find hidden/live web objects and pages",
        "Extensible via custom wordlists",
    ],
    "ffuf": [
        "Fast web fuzzer written in Go",
        "Fuzz directories, parameters, headers, and vhosts",
        "Blazing performance with flexible wordlists",
        "Highlight/ignore match filters for precise results",
    ],
    "Dirbuster": [
        "Multi-threaded Java directory/file brute-forcer",
        "GUI + CLI interface for path discovery",
        "Customizable wordlists and recursion depth",
    ],
    "Dirsearch": [
        "Web path scanner (directory brute-forcing)",
        "High-performance recursive scanning",
        "Filter by status/extension and many dictionaries",
    ],
    "Gobuster": [
        "Directory/File, DNS, and VHost busting tool (Go)",
        "Fast brute force of web paths and virtual hosts",
        "Supports multiple modes: dir, dns, vhost, fuzz",
    ],
    "WebPathBrute": [
        "Web path brute forcer (7kbscan)",
        "High-concurrency path discovery",
        "GUI with result filtering and export",
    ],
    "wfuzz": [
        "Web application fuzzer",
        "Fuzz parameters, headers, cookies, and paths",
        "Extensible payload generation and encoders",
    ],
    "Dirmap": [
        "Advanced web directory & file scanning tool",
        "More powerful than DirBuster/Dirsearch alternatives",
        "Multi-engine crawling + brute forces unification",
    ],
    "YJdirscan": [
        "Fast all-in-one directory scanner (GUI Pro)",
        "Directory/file brute force with session support",
        "Visual progress and export",
    ],
    # ------------------------------------------------------------------
    # database
    # ------------------------------------------------------------------
    "Enumdb": [
        "Relational database brute force + post-exploitation",
        "Enumerate MySQL and MSSQL schemas and data",
        "Dump tables and columns from weak credentials",
    ],
    "MDUT": [
        "Multiple Database Utilization Tools",
        "Connect to many DB types for post-exploitation",
        "SQL injection session reuse and file read/write",
    ],
    "Sylas": [
        "Multiple Database Exploitation Tools",
        "Exploit database endpoints (mssql, oracle, mysql focus)",
        "Command execution and data exfiltration",
    ],
    "ODAT": [
        "Oracle Database Attacking Tool",
        "Enumerate, exploit, and escalate Oracle Databases",
        "SQL injection, file access, and command execution",
    ],
    "MSDAT": [
        "Microsoft SQL Database Attacking Tool",
        "Enumerate and exploit MSSQL databases",
        "Command execution and data extraction",
    ],
    # ------------------------------------------------------------------
    # password
    # ------------------------------------------------------------------
    "Hydra": [
        "Parallelized login cracker over many protocols",
        "Brute force RDP, SSH, HTTP, FTP, SMB, and more",
        "Huge protocol list with attack dictionaries",
    ],
    "Medusa": [
        "Speedy, massively parallel, modular login brute-forcer",
        "Brute force network services quickly",
        "Modular target support and parallel hosts",
    ],
    "Sparta": [
        "Network infrastructure penetration testing tool",
        "Brute force SMB, SNMP, and web auth",
        "Port scan + scan result management",
    ],
    "Hashcat": [
        "World's fastest password recovery utility",
        "Supports 300+ hash types using CPU/GPU",
        "Mask attacks, rule-based attacks, wordlist combos",
    ],
    "Patator": [
        "Multi-purpose brute-forcer with modular design",
        "Protocol plugins (HTTP, SSH, FTP, LDAP, ...)",
        "Flexible and scriptable with parallel workers",
    ],
    "HackBrowserDat": [
        "Decrypt browser passwords/cookies/history/bookmarks",
        "Cross-browser support (Chrome, Edge, Firefox, ...)",
        "Export stolen browser data for post-exploitation",
    ],
    "John": [
        "John the Ripper jumbo — advanced offline password cracker",
        "Hundreds of hash and cipher types",
        "GPU + CPU cracking with wordlist and rules",
    ],
    "crowbar": [
        "Brute forcing tool for specific protocols",
        "OpenVPN, RDP (with NLA), SSH, VNC",
        "Supports key-based and key-only attacks",
    ],
    "wordlists": [
        "Real-world infosec wordlists, updated regularly",
        "Common usernames, passwords, subdomains, and paths",
        "Frequent community contributions",
    ],
    "psudohash": [
        "Password list generator from keywords mutated by patterns",
        "Case mutations, numbers, symbols, years, separators",
        "Ideal for targeted password spraying",
    ],
    "wister": [
        "Wordlist generator from a set of words",
        "Craft multiple variations from given words",
        "Creation of tailored wordlists for a specific target",
    ],
    "Rockyou": [
        "The classic leaked password wordlist packaged for Kali",
        "14M real passwords for faster cracking",
        "Debug/training dataset from a social network leak",
    ],
    "Weakpass": [
        "Wordlist search engine for bruteforce",
        "Find the right dictionary for any target",
        "Huge community-driven wordlist collection",
    ],
    # ------------------------------------------------------------------
    # wireless
    # ------------------------------------------------------------------
    "Fern Wifi cracker": [
        "GUI WEP/WPA/WPS cracking tool",
        "Attack with dictionaries and WPS PIN",
        "Find and crack wireless networks from a friendly UI",
    ],
    "EAPHammer": [
        "Targeted evil twin attacks for WPA2-Enterprise",
        "Rogue AP with malicious captive portal",
        "Credential harvesting from EAP users",
    ],
    "Wifite2": [
        "Wireless attack tool using all known methods",
        "Auto-detect + crack WEP/WPA/WPS",
        "Aggregates aircrack-ng, reaver, and hashcat",
    ],
    "JackIt": [
        "Implementation of Bastille's MouseJack exploit",
        "Inject keystrokes into wireless keyboards/mice",
        "Red team entry point via radio attacks",
    ],
    # ------------------------------------------------------------------
    # reverse-engineering
    # ------------------------------------------------------------------
    "Ollydbg": [
        "32-bit assembler-level analysis debugger (Windows)",
        "Disassemble and debug binaries at the assembly level",
        "Plugin support for unpacking and analysis",
    ],
    # ------------------------------------------------------------------
    # exploit-search
    # ------------------------------------------------------------------
    "SPLOITUS": [
        "Central place for identifying the newest exploits",
        "Search exploit blobs and find attacks for known vulns",
        "Aggregates from ExploitDB, GitHub, NVD, PacketStorm",
    ],
    "SearchSploit": [
        "The official Exploit-DB command-line search",
        "Search the offline exploit archive by keyword/module",
        "Copy exploits directly to your working dir",
    ],
    "Getsploit": [
        "Command-line utility for searching exploits (Vulners)",
        "Download exploit code for a target CVE/service",
        "Integrates with Vulners API",
    ],
    "Houndsploit": [
        "Advanced graphical search engine for Exploit-DB",
        "Filter by platform, exploit type, author, and date",
        "Provides exploit preview and download",
    ],
    "OSV": [
        "Open-source vulnerability DB and triage service",
        "Query vulnerabilities by ID, commit, or range",
        "API + SBOM integration",
    ],
    # ------------------------------------------------------------------
    # xss
    # ------------------------------------------------------------------
    "BeeF": [
        "Browser Exploitation Framework",
        "Craft interactive XSS payloads for hooked browsers",
        "Range of browser modules (keylogger, exfil, recon)",
    ],
    "BlueLotus_XSSReceiver": [
        "XSS receiver platform without SQL",
        "Host JS hooks to capture XSS callbacks",
        "Log and manage XSS victims/requests",
    ],
    "XSStrike": [
        "Advanced XSS detection / exploitation scanner",
        "Payload generator + fuzzy analysis",
        "Detect reflected, stored, and DOM XSS contexts",
        "Context-aware evasions and polymorphism",
    ],
    "xssor2": [
        "XSS'OR — hack with JavaScript",
        "Generate XSS payloads with keyloggers and beacons",
        "Evasion-focused payload craft",
    ],
    "Xsser-Varbaek": [
        "From XSS to RCE toolkit (2.75)",
        "Craft XSS payloads that escalate to RCE",
        "Exploit kits for XSS-to-RCE scenarios",
    ],
    "Xsser-Epsylon": [
        "Cross Site Scripter automated framework",
        "Detect, exploit, and report XSS vulnerabilities",
        "On-the-fly payload generation",
    ],
    "Xenotix": [
        "Advanced XSS vulnerability detection + exploitation framework",
        "Payload database for XSS contexts",
        "OWASP-related scanner for web apps",
    ],
    "PwnXSS": [
        "XSS vulnerability scanner / exploit",
        "Fuzz injection points for XSS",
        "Generate and report exploitable payloads",
    ],
    "dalfox": [
        "Powerful open-source XSS scanner + parameter analyzer",
        "CLI, pipeline-friendly, with great output formats",
        "Detect DOM, reflected, and blind XSS",
    ],
    "ezXSS": [
        "Easy way to test (blind) cross-site scripting",
        "Host a blind XSS callback dashboard",
        "Capture and manage XSS hits for hunters",
    ],
    # ------------------------------------------------------------------
    # sqli
    # ------------------------------------------------------------------
    "Sqlmap": [
        "Automatic SQL injection and database takeover tool",
        "Detect + exploit classic, blind, and out-of-band SQLi",
        "Enumerate data, dump tables, read files, run commands",
        "Supports MySQL, Oracle, PostgreSQL, MSSQL, SQLite, and more",
    ],
    "SSQLInjection": [
        "SQL injection tool supporting multiple databases",
        "Access/MySQL/SQLServer/Oracle/PostgreSQL/DB2/SQLite/Informix",
        "GUI session management and exploitation",
    ],
    "Jsql-injection": [
        "Java application for automatic SQL database injection",
        "Detect + exploit SQLi via an intuitive GUI",
        "Dump data and access the shell when possible",
    ],
    "NoSQLMap": [
        "Automated NoSQL database enumeration and exploitation",
        "Exploit MongoDB, CouchDB, and more",
        "Web app + NoSQL buffer for injection testing",
    ],
    "Sqlmate": [
        "Friend of SQLmap — automate what you expected from SQLmap",
        "Large payload and injection-point library",
        "Run alongside SQLmap for enhanced coverage",
    ],
    "SQLiScanner": [
        "Automatic SQL injection with Charles + sqlmap API",
        "Crawl + inject detection pipeline",
        "Automated scanning across sites",
    ],
    "sql-injection-payload-list": [
        "Cheat-sheet collection of SQL injection payloads",
        "Test SQLi with a standard payload suite",
        "Reference for different DB engines",
    ],
    "Advanced-SQL-Injection-Cheatsheet": [
        "Cheat sheet with advanced SQLi queries for all types",
        "Cover error-based, union, blind boolean, and time-based",
        "DB-specific payload references",
    ],
    # ------------------------------------------------------------------
    # command-injection
    # ------------------------------------------------------------------
    "Commix": [
        "Automated all-in-one OS command injection tool",
        "Detect + exploit command injection flaws",
        "Supports multiple injection vectors/traversal tricks",
        "Auto-generation of various exploit payloads",
    ],
    # ------------------------------------------------------------------
    # file-include
    # ------------------------------------------------------------------
    "LFIsuite": [
        "Totally automatic LFI exploiter + reverse shell",
        "Scanner and file-extraction engine",
        "Auto reverse-shell spawner on vuln",
    ],
    "Lfi-Space": [
        "LFI scan tool with directory-style results",
        "Enumerate readable files via LFI",
        "Simple payload sets for traversal",
    ],
    "Kadimus": [
        "LFI detection + exploitation tool",
        "Check sites for LFI vulns and exploit them",
        "File disclosure and remote file access",
    ],
    "Shellfire": [
        "Exploitation shell for LFI, RFI, and CMD injection",
        "Attempt reverse shells through include chains",
        "Interactive handler for shells",
    ],
    "LFIter2": [
        "Local File Include tool with auto-exfil",
        "Auto file extractor + username brute-forcer",
        "Gathers sensitive configs through include paths",
    ],
    "FDsploit": [
        "File inclusion & directory-traversal fuzzing tool",
        "Enumerate + exploit LFI/Path traversal",
        "Extract files and map writable dirs",
    ],
    "Fuxploider": [
        "File upload vulnerability scanner + exploiter",
        "Detect upload-handler flaws",
        "Confirm exploitable upload with stub/polyglot payload",
    ],
    # ------------------------------------------------------------------
    # xxe
    # ------------------------------------------------------------------
    "XXEinjector": [
        "Automatic XXE exploitation tool",
        "Direct + out-of-band (OOB) exfiltration",
        "Retrieve files and internal host info",
    ],
    "Oxml_xxe": [
        "Embed XXE/XML exploits into different filetypes",
        "Create malicious .docx/.xlsx/.odt payloads",
        "Trigger XXE via malformed OOXML",
    ],
    # ------------------------------------------------------------------
    # csrf
    # ------------------------------------------------------------------
    "Deemon": [
        "CSRF detection scanner",
        "Crawl pages and detect state-changing forms",
        "Automated identification of CSRF-prone actions",
    ],
    # ------------------------------------------------------------------
    # exploit-framework
    # ------------------------------------------------------------------
    "Ysomap": [
        "Java deserialization exploit framework",
        "Find + exploit unsafe deserialization chains",
        "Payload + gadget builder for Java apps",
    ],
    "POC-T": [
        "Pentest Over Concurrent Toolkit",
        "Massive parallel exploit/POC runner",
        "Aggregates PoCs for quick scanning",
    ],
    "Pocsuite3": [
        "Open-source remote vulnerability testing framework",
        "By Knownsec 404 Team — supports POC plugins",
        "CLI + web + API modes for POC execution",
    ],
    "Metasploit": [
        "The world's most used penetration testing framework",
        "Exploit development + execution with payloads",
        "Post-exploitation modules, aux, and encoders",
        "Integration with databases and reporting",
    ],
    "Venom": [
        "(r00t-3xp10it) Shellcode generator/compiler/handler",
        "Generate staged Metasploit shellcode",
        "Modern wrapper for msfvenom workflows",
    ],
    "Empire": [
        "PowerShell and Python post-exploitation agent",
        "C2 framework with many stagers/modules",
        "REST API for scripting + automation",
    ],
    "Starkiller": [
        "Frontend for PowerShell Empire",
        "Graphical C2 control for Empire agents",
        "View agents, run modules, and execute commands",
    ],
    "Koadic": [
        "Koadic C3 COM Command & Control - JScript RAT",
        "Post-exploitation with Windows scripting hosts",
        "Execute in-memory payloads via COM",
    ],
    "Viper": [
        "Metasploit-framework UI manager",
        "Web UI control for Metasploit work",
        "Session management and module handling",
    ],
    "MYExploit": [
        "GUI tool for scanning OA vulnerabilities",
        "Automate detection against office-automation apps",
        "CVE-oriented scanning with GUI",
    ],
    "MSFvenom-gui": [
        "GUI wrapper to create payloads with msfvenom",
        "Point-and-click payload generation",
        "Simplify common msfvenom commands",
    ],
    "ronin-exploits": [
        "Ruby micro-framework for writing and running exploits",
        "Payloads and exploits as Ruby libraries",
        "Extensible for rubyists in the security community",
    ],
    "DeepExploit": [
        "Fully automatic penetration test tool using ML",
        "Autonomous exploitation via reinforcement learning",
        "Enhance security testing with ML-driven decisopns",
    ],
    "GyoiThon": [
        "Intelligence gathering tool using machine learning",
        "ML-assisted asset classification and recon",
        "Grow your pentest knowledge base",
    ],
    "Generator": [
        "Automatically generate numerous injection codes",
        "For web application assessment",
        "Produce payloads for multiple attack classes",
    ],
    "AutoSploit": [
        "Automated mass exploiter",
        "Automatically launch exploits against many targets",
        "High-speed exploitation workflow",
    ],
    "WinPwn": [
        "Automation for internal Windows Pentest / AD-Security",
        "One-shot AD enum + attack automation",
        "Discover misconfigurations and attack paths",
    ],
    # ------------------------------------------------------------------
    # sniffing
    # ------------------------------------------------------------------
    "WireShark": [
        "Network traffic analyzer / packet sniffer",
        "Deep packet inspection with a rich filter language",
        "Decode 2000+ protocols, stream follow and export",
        "De-facto standard for network forensics",
    ],
    "Cain & abel": [
        "Password recovery tool for Microsoft OS",
        "Sniff passwords, ARP poisoning, and dictionary attacks",
        "Legacy tool for Windows (MX4L archive)",
    ],
    "Responder": [
        "LLMNR, NBT-NS, and MDNS poisoner",
        "Auto-capture credentials over poisoned name resolution",
        "Feed into cracking and relay attacks",
    ],
    "bettercap": [
        "ARP, DNS, NDP, DHCPv6 spoofers for MITM",
        "Full network recon + sniffing with modules",
        "HTTP/HTTPS proxy and credential capture",
    ],
    "EvilFOCA": [
        "Security pentesting for IPv4/IPv6 networks",
        "Man-in-the-middle with network spoofing",
        "Credential and traffic interception",
    ],
    # ------------------------------------------------------------------
    # shell
    # ------------------------------------------------------------------
    "Goshell": [
        "Generate reverse shells in command line with Go",
        "Quick reference-style payload generation",
        "Outputs ready-to-run shell commands",
    ],
    "Print-My-Shell": [
        "Automate generation of various reverse shells",
        "Produce Python/bilingual payloads",
        "Useful for CTF and post-exploitation",
    ],
    "Reverse-shell-generator": [
        "Hosted reverse shell generator with lots of functionality",
        "Web UI to copy-paste payloads",
        "Great for CTFs and target interaction",
    ],
    "Girsh": [
        "Automatically spawn a fully interactive reverse shell",
        "For Linux or Windows victims",
        "Wraps pty and configuring an interactive session",
    ],
    "Blueshell": [
        "Generate reverse shells for Red Team",
        "Multiple payload formats and encodings",
        "Designed for red-team engagements",
    ],
    "Clink": [
        "Powerful Bash-style command line editing for cmd.exe",
        "Adds tab-completion and a bash-like experience to Windows CMD",
        "Enhances comfort when working in a Windows shell",
    ],
    "Natpass": [
        "New RAT tool supporting Web VNC and Webshell",
        "Easy remote desktop + terminal over HTTP",
        "Pivot-friendly administration",
    ],
    "Platypus": [
        "Modern multiple reverse-shell sessions manager (Go)",
        "Manage many reverse shells at once",
        "HTTP/HTTPS bind and session commands",
    ],
    "shells": [
        "Script for generating reverse shells",
        "Provides shellcode/payload variants",
        "Quick-reference for pentesting",
    ],
    "Reverse_ssh": [
        "SSH-based reverse shell",
        "Pivot through standard SSH protocol",
        "Lightweight and stealthy access",
    ],
    "Hoaxshell": [
        "Windows reverse-shell payload generator and handler",
        "Uses http(s) to establish a beacon-like shell",
        "Evasions against common AV/EDR",
    ],
    "Reverse Shell as a Service": [
        "Easy-to-remember reverse shell that works on most Unix-like systems",
        "Meaningful, memorable payload",
        "Simple drop-in for remote interaction",
    ],
    "Netcat": [
        "Featured networking utility (TCP/UDP read-write)",
        "Classic listener / connect for reverse shells",
        "Runs on almost any Unix system",
    ],
    "Rustcat": [
        "Modern port listener and reverse-shell handler (Rust)",
        "Lightweight replacement for netcat use cases",
        "Colorful, easy output",
    ],
    "Rlwrap": [
        "Readline wrapper (line editing + history)",
        "Adds readline to non-interactive commands",
        "Improves handling of interactive shells",
    ],
    "Pwncat": [
        "Fancy reverse and bind shell handler",
        "Automatic stabilization + privilege-escalation helpers",
        "Persistent channel without a terminal",
    ],
    "Powercat": [
        "PowerShell version of netcat features",
        "TCP client/server and reverse shell in PS",
        "Useful in Windows AD engagements",
    ],
    "Socat": [
        "Flexible multi-purpose relay tool",
        "Port forwarding, SSL wrapping, pipe relaying",
        "Swiss-army knife for networking",
    ],
    # ------------------------------------------------------------------
    # webshell
    # ------------------------------------------------------------------
    "AntSword": [
        "Cross-platform website management toolkit",
        "Interact with web shells with a familiar UI",
        "Supports many script languages and plugins",
    ],
    "CKnife": [
        "Cross-platform webshell tool (Java)",
        "Lightweight alternative to AntSword",
        "Connect to common webshell scripts",
    ],
    "Behinder": [
        "Dynamic binary-encrypted webshell management client",
        "AES-encrypted communications to evade WAF",
        "Memory/assembly-level execution options",
    ],
    "Godzilla": [
        "Java tool to encrypt network traffic",
        "Two-way encrypted webshells",
        "Bypass WAF/IDS with dynamic encoding",
    ],
    "Skyscorpion": [
        "Modified version of Behinder",
        "Enhanced compatibility and evasion",
        "Dynamic binary webshell communication",
    ],
    "PyShell": [
        "Multiplatform Python web shell",
        "Simple cross-OS interaction",
        "Drop-in webshell in Python",
    ],
    "Weevely3": [
        "Weaponized web shell",
        "Stealthier connections, obfuscation, and modules",
        "Post-exploitation over PHP CGI",
    ],
    "Bantam": [
        "PHP backdoor management/generation tool / C2",
        "End-to-end encrypted payload streaming",
        "Designed to bypass WAF/IDS/SIEM",
    ],
    "Awsome-Webshells": [
        "Collection of reverse shells",
        "Multiple languages & encoder variants",
        "Handy reference for pen testing",
    ],
    "php-reverse-shell": [
        "Simple PHP reverse shell implemented using binary",
        "Drop-in file for PHP environments",
        "Standard pentest shell",
    ],
    "Webshell_Generate": [
        "Generate kinds of webshells bypassing AV",
        "Produces obfuscated shellcode and payloads",
        "Helps bypass detection",
    ],
    # ------------------------------------------------------------------
    # privesc
    # ------------------------------------------------------------------
    "windows-exploit-suggester": [
        "Compare target patch to MS vulnerability database",
        "Suggest missing patches / potential exploits",
        "Great for Windows privilege escalation",
    ],
    "Windows-kernel-exploits": [
        "Collection of Windows kernel exploits",
        "Prebuilt binaries + source",
        "For privilege escalation on old Windows",
    ],
    "linux-exploit-suggester-2": [
        "Next-generation Linux kernel exploit suggester",
        "Aggregate CVEs to suggest Local Privilege Escalation",
        "Faster and cleaner than v1",
    ],
    "Linux-kernel-exploits": [
        "Collection of Linux kernel exploits / PoCs",
        "Organized by kernel version",
        "Used in environment-specific LPE",
    ],
    "BeRoot": [
        "Privilege escalation helper for Windows / Linux / Mac",
        "Check common misconfigurations",
        "Offer practical escalation techs",
    ],
    "PE-Linux": [
        "Linux privilege escalation tool",
        "Enumerate user, sudo, SUID, and cron misconfigs",
        "Quick LPE surface mapping",
    ],
    "Portia": [
        "Automate post-exploitation on internal networks",
        "Active directory and network pivoting helpers",
        "Designed for low-priv attack paths",
    ],
    "PEASS-ng": [
        "Privilege Escalation Awesome Scripts SUITE (with colors)",
        "linpeas / winpeas / macpeas",
        "Massive check matrix for LPE vectors",
    ],
    "GTFOBins": [
        "Curated list of Unix binaries for bypassing restrictions",
        "Escape shells, escalate privileges, exfiltrate",
        "Searchable by known behavior",
    ],
    "LOLBAS": [
        "Living Off The Land Binaries, Scripts, Libraries",
        "Windows binary reuse for privilege escalation",
        "Standardized metadata for each binary",
    ],
    "WADComs": [
        "Interactive cheat sheet for Windows/AD offensive tools",
        "Curated tool/command combos",
        "For Windows/AD engagements",
    ],
    "HijackLibs": [
        "DLL Hijacking lookup — find legitimate DLL hijack candidates",
        "Trick trusted app into loading an arbitrary DLL",
        "For persistence / evasion",
    ],
    "GTFOBLookup": [
        "Offline command-line lookup for GTFOBins/LOLBAS/WADComs",
        "Search offline data for binary behavior",
        "No network needed on target",
    ],
    "PrintNotifyPotato": [
        "PrintNotifyPotato Local Privilege Exploit",
        "Abuse Print Notify service to escalate",
        "Potato-style LPE for Windows",
    ],
    # ------------------------------------------------------------------
    # c2
    # ------------------------------------------------------------------
    "DeimosC2": [
        "Golang C2 framework for post-exploitation",
        "Generates cargo you can deploy",
        "Web GUI + operator console",
    ],
    "Sliver": [
        "Implant framework (Bishop Fox)",
        "Cross-platform implants with C2 channels",
        "MTLS/HTTP/DNS/Wireguard transport",
    ],
    "PHPSploit": [
        "Full-featured C2 framework for a webserver",
        "Persistent evil PHP one-liner",
        "Robust interactions with remote server",
    ],
    "Shad0w": [
        "Post-exploitation framework for monitored environments",
        "Covert operation on Windows 8/10",
        "Memory-resident / evasive agent",
    ],
    "Covenant": [
        "Collaborative .NET C2 framework for red teams",
        "HTTP/S listeners + encrypted comms",
        "Multi-operator web UI",
    ],
    "Emp3r0r": [
        "Linux post-exploitation framework",
        "Console, privileges, and multi-channel",
        "Made by and for Linux users",
    ],
    "C3": [
        "Custom Command and Control framework (FSecure)",
        "Prototype custom C2 channels quickly",
        "Integrate existing offensive tooling",
    ],
    "byob": [
        "Open-source post-exploitation framework",
        "Student/developer friendly C2 server + bots",
        "RAT-ish experience in Python",
    ],
    "Havoc": [
        "Modern and malleable post-exploitation C2",
        "Branded, configurable agent",
        "Robust command-line + UI",
    ],
    "Villain": [
        "Windows & Linux backdoor generator/multi-session handler",
        "Connect sibling servers for team work",
        "Handy backdoor serving",
    ],
    # ------------------------------------------------------------------
    # bypass-av
    # ------------------------------------------------------------------
    "Shellcodeloader": [
        "Windows shellcode loader that can bypass AV",
        "Multiple execution techniques",
        "Fits into red-team tooling",
    ],
    "AV_Evasion_Tool": [
        "AntiVirus shellcode generation tool",
        "Generate evasion payloads quickly",
        "Improves success against AV",
    ],
    "BypassAntiVirus": [
        "Remote-control anti-kill series and tooling",
        "Method collection + companion tools",
        "For AV evasion research",
    ],
    "MateuszEx": [
        "Bypass AV generation tool",
        "Generate + compile evasive executables",
        "Good for red-team labs",
    ],
    "FourEye": [
        "AV evasion tool for red-team ops",
        "Four-eye compiled alterations",
        "Designed for red-team deployments",
    ],
    "Phantom-Evasion": [
        "Python antivirus evasion tool",
        "Generate polymorphic/coded payloads",
        "Many techniques for AV bypass",
    ],
    "Terminator": [
        "Terminate all EDR/XDR/AV by abusing zam64.sys driver",
        "Kills vendor agents via kernel driver",
        "Red-team defensive gap",
    ],
    "foolavc": [
        "Obscure executable for checks, executes in memory",
        "AV evasion via obfuscation",
        "Keep file clean then run in-memory",
    ],
    # ------------------------------------------------------------------
    # tunnel
    # ------------------------------------------------------------------
    "EarthWorm": [
        "Tool for tunnel (SocksCap / DMZ pivoting)",
        "Create SOCKS5 proxies through a compromised host",
        "Legacy standard for pivoting",
    ],
    "Termite": [
        "Tool for tunnel (Version 2)",
        "Successor to EarthWorm with better features",
        "HTTP + socks tunnel capabilities",
    ],
    "Frp": [
        "Fast reverse proxy to expose a local server behind a NAT/firewall",
        "TCP/UDP/HTTP/HTTPS/mux tunnels",
        "Dashboard + token-based auth",
    ],
    "Nps": [
        "Lightweight intranet penetration proxy server",
        "Powerful web management terminal",
        "For exposing internal services",
    ],
    "Goproxy": [
        "High-performance full-featured cross-platform proxy server",
        "HTTP, HTTPS, SOCKS5, transparent proxies",
        "Lots of plugins and config",
    ],
    "ReGeorg": [
        "Successor to reDuh — pwn a bastion webserver",
        "Create SOCKS proxies through the DMZ",
        "Pivot and pwn through web servers",
    ],
    "Neo-reGeorg": [
        "Aggressively refactored reGeorg",
        "Improves speed + evasions",
        "HTTP tunnel through web servers",
    ],
    "Stowaway": [
        "Multi-hop proxy tool for pentesters",
        "Chain nodes to pivot through multiple hosts",
        "Socks / port forwarding on the chain",
    ],
    "rport": [
        "Manage remote systems with ease",
        "Reverse tunnel + remote command",
        "Open-source alternative to commercial RMM",
    ],
    "PortForward": [
        "Port forwarding tool developed in Golang",
        "Solve internal/external network communication",
        "Simple config-driven tunnel",
    ],
    "Suo5": [
        "High-performance HTTP proxy tunneling tool",
        "Tunneling over HTTP/HTTPS",
        "Fast for heavy traffic",
    ],
    # ------------------------------------------------------------------
    # reporting
    # ------------------------------------------------------------------
    "Vulnreport": [
        "Open-source pentesting management & automation platform",
        "By Salesforce Product Security",
        "Manage scopes, findings, and CSV",
    ],
    "CervantesSec": [
        "Open-source collaborative platform for pentesters / red teams",
        "Manage projects, clients, vulnerabilities, reports in one place",
        "Multi-operator interface",
    ],
    "Hexway Hive": [
        "Self-hosted pentest collaboration + reporting framework",
        "Multi-source data aggregation",
        "Customizable templates and methodologies",
    ],
    # ------------------------------------------------------------------
    # social-engineering
    # ------------------------------------------------------------------
    "gophish": [
        "Open-source phishing toolkit",
        "Campaign management + landing pages",
        "Email templates and results dashboard",
    ],
    "AdvPhishing": [
        "Advance phishing tool with OTP phishing",
        "Realtime-data fraud capture",
        "Based on zphisher + custom additions",
    ],
    "SocialFish": [
        "Educational phishing tool & info collector",
        "Custom login portals and lures",
        "Educational usage only",
    ],
    "Zphisher": [
        "Automated phishing tool with 30+ templates",
        "One-command deploy to public URL",
        "Educational usage only",
    ],
    "Nexphisher": [
        "Advanced phishing tool for Linux & Termux",
        "Custom site templates and hosts",
        "Educational usage only",
    ],
    "Social-Engineer-Toolkit": [
        "SET — social engineering attack framework (TrustedSec)",
        "Spear-phishing, credential harvest, and payloads",
        "Integrates with Metasploit",
    ],
    # ------------------------------------------------------------------
    # code-audit
    # ------------------------------------------------------------------
    "Cloc": [
        "Count blank lines, comment lines, and physical lines",
        "Many programming languages",
        "Report LOC metrics for projects",
    ],
    "Cobra": [
        "Source code security audit",
        "Static analysis for common web vulns",
        "Audit multiple languages",
    ],
    "Cobra-W": [
        "Cobra for white hat (extended)",
        "Rule engine + more language support",
        "Community maintained",
    ],
    "Graudit": [
        "Grep rough audit — source code auditing tool",
        "Pattern-based audit across languages",
        "Quick scan for common flaws",
    ],
    "Rips": [
        "Static source code analyzer for PHP vulnerabilities",
        "Detect XSS, SQLi, and file inclusion paths",
        "Web-based result explorer",
    ],
    "Kunlun-M": [
        "Static code analysis system for vulnerabilities",
        "Automate detecting CWE-based issues in source",
        "Fast + modular architecture",
    ],
    "Semgrep": [
        "Fast open-source static analysis engine",
        "Pattern-based rules for bugs and vulns",
        "Enforce code standards across repos",
    ],
    "DevAudit": [
        "Open-source cross-platform multi-purpose security auditing",
        "Audit dependencies (vulns) and configs",
        "The heal check for ecosystem packages",
    ],
    # ------------------------------------------------------------------
    # devsecops
    # ------------------------------------------------------------------
    "Gitleaks": [
        "Scan git repos for secrets with regex/entropy",
        "Find hardcoded passwords and API keys",
        "CI-friendly with GitHub Action",
    ],
    "Trivy": [
        "Comprehensive fast vulnerability scanner for containers",
        "Scan images, SBOMs, and configs",
        "OS + language ecosystem coverage",
    ],
    # ------------------------------------------------------------------
    # rootkit
    # ------------------------------------------------------------------
    "Beurk": [
        "BEURK Experimental Unix RootKit",
        "LD_PRELOAD-based userland rootkit",
        "Covert persistence + logging",
    ],
    "Bedevil": [
        "LD_PRELOAD Linux rootkit (x86 & ARM)",
        "Stealth file/hiding + process hiding",
        "Embeddable in test labs",
    ],
    # ------------------------------------------------------------------
    # distribution
    # ------------------------------------------------------------------
    "Backbox Linux": [
        "Penetration testing and security assessment distribution",
        "Optimized Ubuntu-based security stack",
        "Great for audits",
    ],
    "Kali Linux": [
        "Debian-based professional pentesting distribution",
        "600+ preinstalled tools",
        "Rolling release with active community",
    ],
    "BlackArch Linux": [
        "Arch Linux-based pentesting distribution",
        "2300+ tools in a rolling repo",
        "Highly customizable for power users",
    ],
    "Parrot Security": [
        "The ultimate framework for your Cyber Security operations",
        "Security, privacy, and development tools",
        "Lightweight desktop (MATE)",
    ],
    "ArchStrike": [
        "Arch Linux repository for security professionals",
        "Tools added to a standard Arch installation",
        "Complement Arch for zero-bloat",
    ],
    "NullSec Linux": [
        "Security distribution with 135+ tools",
        "Cloud, AI/ML, hardware, automotive pentesting",
        "4 architectures (amd/arm64/riscv/...)",
    ],
    # ------------------------------------------------------------------
    # cyber-range
    # ------------------------------------------------------------------
    "DVWA": [
        "Damn Vulnerable Web Application",
        "Deliberately vulnerable PHP web app for training",
        "Exercises for OWASP Top 10",
    ],
    "WebGoat": [
        "Deliberately insecure web app by OWASP",
        "Lessons for web app security",
        "Hands-on labs for learners",
    ],
    "DSVW": [
        "Deliberately vulnerable web app in <100 lines of code",
        "Educational examples of common vulns",
        "Tiny, easy to reason about",
    ],
    "DVWS": [
        "Damn Vulnerable Web Services",
        "Insecure Web Services with components",
        "Learn real-world web-service weaknesses",
    ],
    "XVWA": [
        "Badly coded web app (PHP/MySQL) for learning",
        "Helps security enthusiasts learn app security",
        "Intentionally vulnerable",
    ],
    "BWAPP": [
        "Buggy web application with 100+ vulnerabilities",
        "Layered challenges for testing",
        "Great for training scanners & hunters",
    ],
    "Sqli-lab": [
        "SQLI labs for error-based, blind boolean, time based",
        "Structured set of SQLi challenges",
        "Educational exploit practice",
    ],
    "HackMe-SQL-Injection-Challenges": [
        "Hack your friend's online MMORPG",
        "SQL injection opportunities in-game",
        "Practice SQLi safely",
    ],
    "XSS-labs": [
        "Small script set to practice XSS and CSRF",
        "Filter evasion + payload crafting",
        "Exercises for web app training",
    ],
    "SSRF-lab": [
        "Lab for exploring SSRF vulnerabilities",
        "Hands-on SSRF exercises",
        "Understand request forgery",
    ],
    "SSRF_Vulnerable_Lab": [
        "Sample codes vulnerable to SSRF",
        "Test SSRF detection and exploitation",
        "Hands-on lab for SSRF",
    ],
    "LFI-labs": [
        "Small PHP scripts practicing LFI, RFI, and command injection",
        "Hands-on file inclusion exercises",
        "For web pentesting training",
    ],
    "Commix-testbed": [
        "Collection of command-injection vulnerable pages",
        "Test command injection detection",
        "Educational exploit practice",
    ],
    "File-Upload-Lab": [
        "Damn Vulnerable File Upload V 1.1",
        "Practice upload exploitation",
        "For upload bypass labs",
    ],
    "Upload-labs": [
        "Summary of all types of uploading vulnerabilities",
        "Practice file-upload bypasss",
        "Great for penetration training",
    ],
    "XXE-Lab": [
        "XXE vulnerability demo (PHP/Java/Python/C#)",
        "Multi-language XXE exercise",
        "Understand XXE attacks",
    ],
    "Vulnerable-Flask-App": [
        "Erlik2 Vulnerable-Flask-App",
        "Python / Flask intentionally vulnerable",
        "Test Python-specific web vulns",
    ],
    "Fopnp": [
        "Network Playground for Python Network Programming",
        "Simulation / network lab",
        "Educational tool",
    ],
    "CyberRange": [
        "Open-Source AWS Cyber Range",
        "Spin up cloud-based attack/defend ranges",
        "Lab as code",
    ],
    "Pentest-Ground": [
        "Free playground with deliberately vulnerable web apps",
        "Pre-built network services to attack",
        "For learning + demo",
    ],
    "DecoyMini": [
        "Highly-scalable enterprise honeypot",
        "Safe, free, easily deployable",
        "Trap intruders and observe attacks",
    ],
    "Vulnhub": [
        "Vulnerable VM downloads for practice",
        "Real-world-ish targets for testing",
        "Huge library for pentesters",
    ],
    "TryHackMe": [
        "Free online platform for cyber security learning",
        "Guided rooms, CTFs, and courses",
        "Browser-based labs",
    ],
    "Hackthebox": [
        "Online cybersecurity training platform",
        "Huge machine library + retired machines",
        "CTF competitions and active labs",
    ],
    "Root Me": [
        "Test and improve your knowledge in security",
        "Challenges in many categories",
        "Great for practice",
    ],
    "Pentestit": [
        "Penetration testing laboratories emulating real companies",
        "Legal pen-test lab simulators",
        "Improve pentesting skills",
    ],
    "Pentesterlab": [
        "Learn web pen testing the right way",
        "Structured courses + labs",
        "Step-by-step exercises",
    ],
    "Cyberseclabs": [
        "Secure, high-quality training services",
        "Safely learn + practice penetration testing",
        "Server hosting for labs",
    ],
    "Web Security Academy": [
        "Free online web security training from Burp Suite team",
        "Guided labs + challenges",
        "Covers OWASP Top 10",
    ],
    "Vulnmachines": [
        "A place to learn and improve pentesting/ethical hacking FREE",
        "Vulnerable machines to attack",
        "Beginner-friendly",
    ],
    "LabEx": [
        "Free online platform for learning cybersecurity, Linux, devops",
        "Hands-on labs with AI",
        "Cloud-powered environment",
    ],
    # ------------------------------------------------------------------
    # collections
    # ------------------------------------------------------------------
    "Rawsec's CyberSecurity Inventory": [
        "An inventory of tools and resources about CyberSecurity",
        "Searchable/paginated tool list",
        "Community-maintained",
    ],
    "All-Defense-Tool": [
        "A List for Defense Tools",
        "Curate defensive tools and guidance",
        "For blue-team research",
    ],
    "Awesome-POC": [
        "A POC knowledge base of various vulnerabilities",
        "Categorized exploit/detection PoCs",
        "Reference for research",
    ],
    # ------------------------------------------------------------------
    # secret
    # ------------------------------------------------------------------
    "Keyscope": [
        "Extensible key & secret validation",
        "Audit active secrets against many SaaS vendors",
        "Detect dead/revoked high-value keys",
    ],
}
