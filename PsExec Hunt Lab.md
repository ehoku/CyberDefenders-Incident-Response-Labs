# CyberDefenders PsExec Hunt Lab Writeup

## Overview
This repository documents my approach to solving the **CyberDefenders PsExec Hunt Lab**, a blue team challenge rated 4.5/5 stars, focusing on analyzing SMB traffic in a PCAP file using Wireshark to identify PsExec lateral movement, compromised systems, user credentials, and administrative shares. The lab, categorized under Network Forensics, covers tactics like Execution, Defense Evasion, Discovery, and Lateral Movement, aligning with my certifications: CompTIA Security+, CySA+, CASP+, and GIAC GFACT, GSEC, GCIH. Answers are redacted (e.g., `[REDACTED]`) to respect the challenge’s integrity. Unzip the file with password `cyberdefenders.org` in a secure, isolated environment.

- **Skills Demonstrated**:
  - Network traffic analysis with Wireshark
  - SMB protocol and PsExec behavior analysis
  - Credential extraction
  - Lateral movement tracking
- **Tools Used**:
  - Wireshark: Packet filtering and object export
- **Environment**:
  - Network capture: PCAP file (unzip with password)
  - Working directory: `~/Downloads/lab/temp_extract_dir`
- **Details**:
  - Difficulty: Easy
  - Duration: 30 mins
  - Status: Retired
  - Questions: 7/7 (100% Completed)

## Methodology

### 1: Initial Access IP Address
- **Objective**: Identify the IP address of the machine from which the attacker initially gained access.
- **Technique**: Analyzed PCAP with Wireshark, focusing on unusual traffic patterns and SMB negotiation.
  ```wireshark
  smb.cmd == 0x72 || smb2.cmd == 0x00

Used Statistics > Conversations (IPv4 tab) to examine high-volume or frequent connections.
Identified the first source IP with SMB activity.
Skills: Network traffic analysis (CySA+), anomaly detection (GSEC).

2: First Pivot Hostname

Objective: Determine the machine's hostname to which the attacker first pivoted.
Technique: Filtered SMB packets and reviewed NTLMSSP challenge messages.
wiresharkntlmssp.challenge.target_name

Located the Target Name field in the challenge message to identify the hostname.


Skills: Protocol analysis (GCIH), hostname extraction (CySA+).

3: Attacker’s Username

Objective: Identify the username used by the attacker for authentication.
Technique: Filtered SMB Session Setup packets and extracted credentials.
wiresharkntlmssp.auth.username

Analyzed NTLMSSP Authenticate messages for the submitted username.


Skills: Credential analysis (GFACT), network forensics (CySA+).

4: Service Executable Name

Objective: Determine the name of the service executable the attacker set up on the target.
Technique: Exported SMB objects to identify transferred executables.
wiresharksmb

Used File > Export Objects > SMB to list files, focusing on service-related executables.


Skills: Malware artifact identification (GCIH), file analysis (CySA+).

5: Network Share for Service Installation

Objective: Identify the network share used by PsExec to install the service on the target machine.
Technique: Analyzed SMB traffic for share usage during service setup.
wiresharksmb

Checked Tree Connect packets for the administrative share name.


Skills: Lateral movement analysis (GCIH), share identification (CySA+).

6: Network Share for Communication

Objective: Identify the network share used by PsExec for communication between machines.
Technique: Examined SMB communication for command execution activity.
wiresharksmb.file == "stdout" || smb.file == "stdin" || smb.file == "stderr"

Identified the share linked to files with stdout, stdin, or stderr.


Skills: Command execution tracking (GCIH), network analysis (CySA+).

7: Second Pivot Hostname

Objective: Identify the hostname of the second machine the attacker targeted to pivot.
Technique: Filtered NTLMSSP challenge messages for the next target.
wiresharkntlmssp.challenge.target_name

Used IP filters (e.g., ip.src == 10.0.0.133 and ip.dst != 10.0.0.130) to focus on post-pivot traffic or use the filter ntlmssp.challenge.target_name to identify the second machine that the attacker targeted for pivoting.


Skills: Lateral movement tracking (GCIH), hostname extraction (CySA+).

Tools and Techniques

Wireshark:

Filters: smb, ntlmssp.challenge.target_name, ntlmssp.auth.username, smb.file == "stdout" || smb.file == "stdin" || smb.file == "stderr", smb.cmd == 0x72 || smb2.cmd == 0x00
Features: Statistics > Conversations, File > Export Objects > SMB
Analyzed IP patterns, SMB negotiations, and file transfers


Incident Response:

Reconstructed attacker movement and service installation



Lessons Learned

Mastered Wireshark for SMB and NTLMSSP analysis
Identified PsExec lateral movement patterns
Applied blue team skills for network forensics (CySA+, GCIH)
Developed portfolio documentation for career advancement

Certifications

CompTIA Security+, CySA+, CASP+
GIAC GFACT, GSEC, GCIH

About
Writeup for CyberDefenders PsExec Hunt Lab, showcasing network forensics and lateral movement analysis.
