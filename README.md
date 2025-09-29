# WinLogs-Toolkit
PowerShell tool for parsing and formatting Windows Event Logs into structured data for investigations.
 # ⚡ PowerShell Sysmon Event Parser & Detection Scripts

This repository provides a **PowerShell script** to parse and normalize Windows Event Logs, with a focus on **Sysmon** and **Security** events.  
It includes a function `Format-WinEvent` that converts positional event properties into named ones, making analysis and hunting much easier.

---

## ✨ Features
- 📑 Load Windows event logs (`.evtx`) with `Get-WinEvent`.
- 🛠 Normalize event properties into structured objects.
- 🔍 Support for multiple Sysmon event IDs (process, file, network, registry, WMI, DNS, clipboard, etc.).
## 🛡️ Example detections for common malicious behaviors:  
  - Scheduled tasks executing `mshta.exe`  
  - `WINWORD.EXE` loading suspicious DLLs  
  - `mshta.exe` performing DNS queries  

---
👩‍💻 Author

Aiymgul Toktarbayeva
 https://x.com/aiymgul91521
https://www.linkedin.com/in/aiymgul-toktarbayeva-68a52a196/
