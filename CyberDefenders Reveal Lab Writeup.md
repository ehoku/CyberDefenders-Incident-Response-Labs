# CyberDefenders Reveal Lab Writeup

## Overview
This repository documents my approach to solving the **CyberDefenders Reveal Lab**, a blue team challenge focused on analyzing a **Windows memory dump (192-Reveal.dmp)** to reconstruct a multi-stage malware attack.  
The lab covers malicious process identification, command-line analysis, and network activity correlation, aligning with my certifications:

**CompTIA Security+, CySA+, CASP+, GIAC GFACT, GSEC, GCIH**

> ⚠️ Answers are redacted (e.g., `[REDACTED]`) to preserve the integrity of the CyberDefenders challenge.

---

## Skills Demonstrated
- Memory forensics with **Volatility 3**
- Malware process and payload analysis
- Command-line argument extraction
- Network forensics and threat intelligence

---

## Tools Used
- **Volatility 3** – Memory dump analysis (`windows.cmdline`, `windows.malfind`, `windows.netscan`)
- **Strings** – Artifact extraction from dumped processes

---

## Environment
- Memory dump: `192-Reveal.dmp` (Windows 10 x64)
- Malicious process: `[REDACTED].exe` (PID `[REDACTED]`)
- Working directory: `~/Downloads/lab/temp_extract_dir`

---

## Methodology

### Q2: Malicious Process Name
**Objective:** Identify the process executing malicious activity.  
**Technique:** Filtered process hierarchy with `windows.pstree` and checked for injected code using `windows.malfind`.

```bash
vol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.pstree > pstree_output.txt
vol -f ~/Downloads/lab/temp_extract_dir/192-Reveal.dmp windows.malfind > malfind_output.txt

