# CyberDefenders Reveal Lab Writeup

## Overview
This repository documents my approach to solving the **CyberDefenders Reveal Lab**, a blue team challenge focused on analyzing a Windows memory dump (`192-Reveal.dmp`) to reconstruct a multi-stage malware attack. The lab covers malicious process identification, command-line analysis, and network activity correlation, aligning with my certifications: CompTIA Security+, CySA+, CASP+, and GIAC GFACT, GSEC, GCIH. Answers are redacted (e.g., `[REDACTED]`) to respect the challenge’s integrity for GitHub sharing.

- **Skills Demonstrated**:
  - Memory forensics with Volatility 3
  - Malware process and payload analysis
  - Command-line argument extraction
  - Network forensics and threat intelligence
- **Tools Used**:
  - Volatility 3: Memory dump analysis (`windows.cmdline`, `windows.malfind`)
  - Strings: Artifact extraction from dumped processes
- **Environment**:
  - Memory dump: `192-Reveal.dmp` (Windows, likely 10 x64)
  - Malicious process: `[REDACTED].exe` (PID `[REDACTED]`)
  - Working directory: `~/Downloads/lab/temp_extract_dir`

## Methodology

### Q2: Malicious Process Name
- **Objective**: Identify the process executing malicious activity.
- **Technique**: Filtered process hierarchy with `windows.pstree` and checked for injected code using `windows.malfind`.
  ```bash
  vol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.pstree > pstree_output.txt
  vol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.malfind > malfind_output.txt

Identified process with unusual parent or RWX regions in memory.
Skills: Memory forensics (CySA+, GCIH), process analysis (GSEC).

Q3: Parent PID of Malicious Process

Objective: Determine the parent PID of the malicious process.
Technique: Used windows.pslist to list processes and their PIDs.
bashvol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.pslist > pslist_output.txt

Located PID [REDACTED] and noted its parent PID.


Skills: Process enumeration (Security+, GFACT).

Q4: Second-Stage Payload File Name

Objective: Identify the file name of the second-stage payload (format [REDACTED].dll, not smss.exe).
Technique: Extracted command-line arguments with windows.cmdline and verified files with windows.filescan.
bashvol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.cmdline > cmdline_output.txt
vol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.filescan | grep ".dll" > filescan_output.txt

Checked PID [REDACTED] for arguments invoking a DLL (e.g., rundll32.exe C:\Temp/[REDACTED].dll,EntryPoint). Confirmed DLL in filescan_output.txt.


Skills: Malware analysis (GCIH), file system forensics (CySA+).
Wireshark Correlation: Filtered for DLL downloads (if PCAP available):
wiresharktcp.port == 80 || tcp.port == 443 && http.request.method == GET && http.request.uri contains ".dll"
tcp.port == 445 && smb.file contains ".dll"


Q5: Shared Directory on Remote Server

Objective: Identify the remote SMB share name.
Technique: Enumerated network connections with windows.netscan.
bashvol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.netscan > netscan_output.txt

Identified SMB connections (port 445) for PID [REDACTED] or related processes, noting share names like \\192.168.x.x\[REDACTED].


Skills: Network forensics (CySA+, GCIH).
Wireshark Correlation: Filtered for SMB traffic:
wiresharktcp.port == 445 && smb2


Q6: MITRE ATT&CK Sub-Technique ID

Objective: Identify the sub-technique for DLL execution via a Windows utility (format T1218.011, not T1059.001).
Technique: Analyzed command-line arguments with windows.cmdline and checked for injected code with windows.malfind.
bashvol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.cmdline > cmdline_output.txt
vol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.malfind > malfind_output.txt

Checked PID [REDACTED] or child processes for utilities like rundll32.exe executing [REDACTED].dll.


Skills: Threat mapping (GCIH), malware analysis (CySA+).
Wireshark Correlation: Filtered for payload downloads:
wiresharktcp.port == 80 || tcp.port == 443 && http


Q7: Username of Malicious Process

Objective: Identify the user account running the malicious process.
Technique: Mapped PIDs to SIDs with windows.getsids.
bashvol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.getsids > getsids_output.txt

Matched PID [REDACTED] to its username via SID.


Skills: User account analysis (Security+, GFACT).
Wireshark Correlation: Filtered for authentication:
wiresharksmb || kerberos


Q8: Malware Family

Objective: Identify the malware family.
Technique: Analyzed injected code with windows.malfind and extracted artifacts with windows.procdump.
bashvol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.malfind > malfind_output.txt
vol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.procdump --pid [REDACTED] --dump-dir dump/
strings dump/[REDACTED].exe > strings.txt

Checked malfind_output.txt for injected code and strings.txt for C2 domains or signatures.


Skills: Malware identification (GCIH), artifact extraction (CySA+).
Wireshark Correlation: Filtered for C2 traffic:
wiresharkudp.port == 53 || http


Key Findings

Vulnerability: Malicious process leveraged a Windows utility to execute a DLL payload.
Attack Flow: Initial execution via [REDACTED].exe, DLL payload delivery, potential SMB-based lateral movement, and C2 communication.
Impact: Unauthorized code execution and potential network compromise.

Tools and Techniques

Volatility 3:

Plugins: windows.pstree, windows.malfind, windows.cmdline, windows.netscan, windows.getsids, windows.procdump
Analyzed process hierarchy, injected code, and command lines


Wireshark

Filters: tcp.port == 445 && smb2, tcp.port == 80 || tcp.port == 443 && http, udp.port == 53
Identified file downloads, SMB shares, and C2 traffic


Strings:

Extracted artifacts (e.g., domains, mutexes) from dumped processes


Incident Response:

Reconstructed attack timeline to assess breach scope



Lessons Learned

Mastered memory forensics for identifying malicious processes and payloads
Correlated memory and network artifacts for incident response
Applied blue team skills for SOC and IR roles (CySA+, GCIH)
Developed portfolio documentation for career advancement

Certifications

CompTIA Security+, CySA+, CASP+
GIAC GFACT, GSEC, GCIH

About
Writeup for CyberDefenders Reveal Lab, showcasing blue team skills in memory forensics, malware analysis, and incident response.
