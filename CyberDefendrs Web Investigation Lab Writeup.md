# CyberDefenders Web Investigation Lab Writeup

## Overview
This repository documents my approach to solving the CyberDefenders Web Investigation Lab, a blue team challenge focused on analyzing a PCAP file to investigate a web application breach. The lab covers SQL injection (SQLi), credential compromise, and malicious file uploads, aligning with my certifications: CompTIA Security+, CySA+, CASP+, and GIAC GFACT, GSEC, GCIH. Answers are redacted to respect the challenge’s integrity.

- **Skills Demonstrated**:
  - Packet analysis with Wireshark and Network Miner
  - SQL injection detection and mitigation
  - Credential and malware analysis
  - Incident response and breach assessment
- **Tools Used**:
  - Wireshark: Packet filtering and HTTP stream analysis
  - Network Miner: Parameter and file extraction
- **Environment**:
  - Web application: Bookstore website
  - Attacker IP: [REDACTED]
  - Server IP: [REDACTED]
  - PCAP file: Unzipped with password [REDACTED]

## Methodology
### Q1: Attacker’s IP
- **Objective**: Identify the IP responsible for malicious activities.
- **Technique**: Filtered HTTP traffic from the attacker using `http and ip.src == [REDACTED]`. Confirmed via patterns in SQLi and POST requests.
- **Skills**: Network traffic analysis (CySA+, GSEC).

### Q2: Attacker’s Origin City
- **Objective**: Determine the geographical origin of the attacker’s IP.
- **Technique**: Used IP geolocation (simulated via lab data) to trace the city.
- **Skills**: Threat intelligence (GCIH).

### Q3: Vulnerable PHP Script
- **Objective**: Identify the PHP script exploited by the attacker.
- **Technique**: Filtered for `.php` requests: `http.request.uri contains ".php" and ip.src == [REDACTED]`. Identified SQLi payloads in requests.
- **Skills**: Vulnerability assessment (Security+, CASP+).

### Q4: First SQLi Attempt
- **Objective**: Extract the initial SQLi request URI (decoded).
- **Technique**: Filtered for SQLi indicators: `http contains "--" and ip.src == [REDACTED]`. Decoded URL-encoded characters to read the payload.
- **Skills**: SQLi detection (GCIH, CySA+).

### Q5: Database Enumeration URI
- **Objective**: Identify the URI to list databases (decoded).
- **Technique**: Filtered for database metadata queries: `http contains "SCHEMATA"`. Decoded hex and URL-encoded values to reveal the SQLi query.
- **Skills**: Database security (GSEC).

### Q6: User Data Table
- **Objective**: Find the table containing user data (format: `c********`).
- **Technique**: Filtered server responses: `http.response and ip.src == [REDACTED] and http contains "zvgjck"`. Identified a 9-character table name starting with 'c'.
- **Skills**: Data breach analysis (GFACT, GCIH).

### Q7: Hidden Directory
- **Objective**: Identify the directory discovered by the attacker (format: `/*****/`).
- **Technique**: Filtered for non-public directory requests: `http.request.uri contains "/[REDACTED]/"`. Confirmed via admin access attempts.
- **Skills**: Web reconnaissance (CASP+).

### Q8: Login Credentials
- **Objective**: Extract credentials used for login (format: `*****:*********`).
- **Technique**: Filtered POST requests: `http.request.method == POST and http.request.uri contains "[REDACTED]"`. Decoded payload and confirmed success via `302 Found` redirect.
- **Skills**: Credential analysis (GCIH, CySA+).

### Q9: Malicious Script
- **Objective**: Identify the malicious script uploaded by the attacker.
- **Technique**: Filtered for file uploads: `http contains "multipart/form-data"`. Extracted filename from `Content-Disposition` in the payload.
- **Skills**: Malware detection (GFACT, GCIH).

## Key Findings
- **Vulnerability**: Unfiltered input field enabled SQL injection.
- **Attack Flow**: Reconnaissance, database/table enumeration, credential extraction, admin access, and malicious file upload.
- **Impact**: Unauthorized data access and potential server control.

## Tools and Techniques
- **Wireshark**:
  - Filters: `http.request.uri contains ".php"`, `http contains "UNION"`, `http.request.method == POST`, `http.response.code == 302`.
  - Used `Follow > HTTP Stream` for request/response analysis.
  - Searched Packet Bytes for keywords (e.g., table names, delimiters).
- **Network Miner**:
  - `Parameters` tab: Extracted form data (e.g., username, password).
  - `Files` tab: Retrieved HTML responses and uploaded files.
  - `Hosts` tab: Confirmed IP interactions.
- **SQLi Analysis**:
  - Decoded URL-encoded payloads and hex delimiters.
- **Incident Response**:
  - Reconstructed attack timeline to assess breach scope.

## Lessons Learned
- Identified SQLi vulnerabilities and mitigation strategies.
- Traced credentials and malicious files for incident response.
- Applied blue team skills for SOC and IR roles (CySA+, GCIH).
- Developed portfolio documentation for career advancement.

## Portfolio
- **GitHub**: https://github.com/ehoku/CyberDefenders-WebInvestigation-Writeup
- **LinkedIn**: https://www.linkedin.com/in/jose-enrique-carmona-serrano-b8048586

## Certifications
- CompTIA Security+, CySA+, CASP+
- GIAC GFACT, GSEC, GCIH
