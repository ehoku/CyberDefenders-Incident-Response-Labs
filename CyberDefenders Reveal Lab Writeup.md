markdown# CyberDefenders Reveal Lab Writeup

## Overview
This repository documents my approach to solving the **CyberDefenders Reveal Lab**, a blue team challenge focused on analyzing a Windows memory dump (`192-Reveal.dmp`) to reconstruct a multi-stage malware attack. The lab covers operating system identification, malicious process analysis, command-line extraction, and network activity correlation, aligning with my certifications: CompTIA Security+, CySA+, CASP+, and GIAC GFACT, GSEC, GCIH. Answers are redacted (e.g., `[REDACTED]`) to respect the challenge’s integrity for GitHub sharing.

- **Skills Demonstrated**:
  - Memory forensics with Volatility 3
  - Malware process and payload analysis
  - Command-line argument extraction
  - Network forensics and threat intelligence
- **Tools Used**:
  - Volatility 3: Memory dump analysis (`windows.info`, `windows.cmdline`, `windows.malfind`)
  - Wireshark: Packet filtering for HTTP, SMB, DNS
  - Strings: Artifact extraction from dumped processes
- **Environment**:
  - Memory dump: `192-Reveal.dmp` (Windows, likely 10 x64)
  - Malicious process: `[REDACTED].exe` (PID `[REDACTED]`)
  - Working directory: `~/Downloads/lab/temp_extract_dir`

## Methodology

### 1: Operating System Version
- **Objective**: Identify the operating system version of the memory dump.
- **Technique**: Used `windows.info` to extract OS details.
  
  vol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.info > info_output.txt

Analyzed info_output.txt for Windows version and architecture.
Skills: Memory forensics (CySA+, GFACT).

### 2: Malicious Process Name

- **Objective**: Identify the process executing malicious activity.
- **Technique**: Analyzed process list with windows.pslist and command-line arguments with windows.cmdline to identify suspicious activity.
bashvol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.pslist > pslist_output.txt
vol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.cmdline > cmdline_output.txt

Identified process with suspicious command-line arguments indicating malicious execution.


Skills: Memory forensics (CySA+, GCIH), process analysis (GSEC).

### 3: Parent PID of Malicious Process

- **Objective**: Determine the parent PID of the malicious process.
- **Technique**: Used windows.pslist to list processes and their PIDs.
bashvol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.pslist > pslist_output.txt

Located PID [REDACTED] and noted its parent PID.


Skills: Process enumeration (Security+, GFACT).

### 4: Second-Stage Payload File Name

- **Objective**: Identify the file name of the second-stage payload (format [REDACTED].dll, not smss.exe).
- **Technique**: Extracted command-line arguments with windows.cmdline and verified files with windows.filescan.
bashvol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.cmdline > cmdline_output.txt
vol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.filescan | grep ".dll" > filescan_output.txt

Checked PID [REDACTED] for arguments invoking a DLL (e.g., rundll32.exe C:\Temp/[REDACTED].dll,EntryPoint). Confirmed DLL in filescan_output.txt.


- **Skills**: Malware analysis (GCIH), file system forensics (CySA+).
- **Wireshark Correlation**: Filtered for DLL downloads:
wiresharktcp.port == 80 || tcp.port == 443 && http.request.method == GET && http.request.uri contains ".dll"
tcp.port == 445 && smb.file contains ".dll"


### 5: Shared Directory on Remote Server

- **Objective**: Identify the remote SMB share name.
- **Technique**: Enumerated network connections with windows.netscan.
bashvol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.netscan > netscan_output.txt

Identified SMB connections (port 445) for PID [REDACTED] or related processes, noting share names like \\192.168.x.x\[REDACTED].


- **Skills**: Network forensics (CySA+, GCIH).
- **Wireshark Correlation**: Filtered for SMB traffic:
wiresharktcp.port == 445 && smb2


### 6: MITRE ATT&CK Sub-Technique ID

- **Objective**: Identify the sub-technique for DLL execution via a Windows utility (format T1218.011, not T1059.001).
- **Technique**: Analyzed command-line arguments with windows.cmdline and checked for injected code with windows.malfind.
bashvol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.cmdline > cmdline_output.txt
vol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.malfind > malfind_output.txt

Checked PID [REDACTED] or child processes for utilities like rundll32.exe executing [REDACTED].dll.


- **Skills**: Threat mapping (GCIH), malware analysis (CySA+).
- **Wireshark Correlation**: Filtered for payload downloads:
  wiresharktcp.port == 80 || tcp.port == 443 && http


### 7: Username of Malicious Process

- **Objective**: Identify the user account running the malicious process.
- **Technique**: Mapped PIDs to SIDs with windows.getsids.
bashvol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.getsids > getsids_output.txt

Matched PID [REDACTED] to its username via SID.


- **Skills**: User account analysis (Security+, GFACT).
- **Wireshark Correlation: Filtered for authentication**:
wiresharksmb || kerberos


### Key Findings

- **Vulnerability**: Malicious process leveraged a Windows utility to execute a DLL payload.
- **Attack Flow**: Initial execution via [REDACTED].exe, DLL payload delivery, potential SMB-based lateral movement, and C2 communication.
- **Impact**: Unauthorized code execution and potential network compromise.

### Tools and Techniques

- **Volatility 3**:

- **Plugins**: windows.info, windows.pslist, windows.cmdline, windows.filescan, windows.netscan, windows.getsids, windows.malfind
Analyzed OS profile, process hierarchy, injected code, and command lines


- **Filters**: tcp.port == 445 && smb2, tcp.port == 80 || tcp.port == 443 && http, udp.port == 53
Identified file downloads, SMB shares, and C2 traffic


- **Strings**:

Extracted artifacts (e.g., domains, mutexes) from dumped processes


- **Incident Response**:

Reconstructed attack timeline to assess breach scope



### Lessons Learned

Mastered memory forensics for identifying malicious processes and payloads
Correlated memory and network artifacts for incident response
Applied blue team skills for SOC and IR roles (CySA+, GCIH)
Developed portfolio documentation for career advancement

### Certifications

CompTIA Security+, CySA+, CASP+
GIAC GFACT, GSEC, GCIH

### About
Writeup for CyberDefenders Reveal Lab, showcasing blue team skills in memory forensics, malware analysis, and incident response.
