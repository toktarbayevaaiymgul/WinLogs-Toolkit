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

---

## Installation

>```PowerShell
>Import-Module ./Format-WinEvent.ps1
>```

## Usage

Load Windows event logs using the built-in `Get-WinEvent` cmdlet:

>```PowerShell
>$events = Get-WinEvent -Path ./Examples/Microsoft-Windows-Sysmon%4Operational.evtx | Format-WinEvent
>```

By default, the `Properties` property in each event is a list of values that must be accessed via positional parameters:

>```PowerShell
>$events[0].Properties
>```

![Format-WinEvent](Images/Screenshot_Properties.png "Format-WinEvent Screenshot Properties")
<img width="1672" height="633" alt="Image" src="https://github.com/user-attachments/assets/e61cf89d-ee00-4ca1-a90a-d15fc942d9f1" />
However, after running `Format-WinEvent` the newly-added `Props` property contains these properties normalized as named key-value pairs:

>```PowerShell
>$events[0].Props
>```

![Format-WinEvent](Images/Screenshot_Props.png "Format-WinEvent Screenshot Props")
<img width="1022" height="598" alt="Image" src="https://github.com/user-attachments/assets/2e9b0b0c-8503-4f8c-beec-13f52c052c63" />

This normalization simplifies referencing properties by name (even across different EIDs) as is demonstrated in the following examples:

### EXAMPLE 1:
Identify counts for each EID containing an Image property ending with "\mshta.exe":

>```PowerShell
>$events | Format-WinEvent `
>         | Where-Object { $_.Props.Image -match '\\mshta\.exe' } `
>         | Group-Object Id -NoElement
>```

![Format-WinEvent](Images/Screenshot_Example_1.png "Format-WinEvent Screenshot Example 1")
<img width="1570" height="227" alt="Image" src="https://github.com/user-attachments/assets/20f3abd5-2cdd-4cf7-ae70-396237b658d1" />

### EXAMPLE 2:
Identify counts of Company and Product property combinations for EID 7 (Image Load Events):

>```PowerShell
>$events | Format-WinEvent `
>         | Where-Object { $_.Id -eq 7 } `                       
>         | ForEach-Object { $_.Props } `
>         | Group-Object Company,Product `
>         | Select-Object Count,Name
>```

![Format-WinEvent](Images/Screenshot_Example_2.png "Format-WinEvent Screenshot Example 2")
<img width="1542" height="651" alt="Image" src="https://github.com/user-attachments/assets/46a39bd9-2004-496a-8243-2466134e40e1" />


### EXAMPLE 3:
Simulate detection to find events containing Scheduled Task executing an Image property ending with "\mshta.exe":

>```PowerShell
| Format-WinEvent        | Where-Object {                                       
 $_.Id -eq 1 -and           
 $_.Props.ParentImage -match '\\svchost\.exe$' -and
  $_.Props.ParentCommandLine -match ' -p -s Schedule$' -and
$_.Props.Image -match '\\mshta\.exe$'
  } 
 | ForEach-Object { $_.Props } 
 | Select-Object RuleName,ParentImage,ParentCommandLine,Image,CommandLine
>```

![Format-WinEvent](Images/Screenshot_Example_3.png "Format-WinEvent Screenshot Example 3")
<img width="1897" height="240" alt="Image" src="https://github.com/user-attachments/assets/8ae7a2cd-7d92-445c-98df-0156be624f38" />
---

## Future Updates

Additional EIDs and LogName sources can be added to this function with their corresponding property name positional mappings.

---

## ✨ Author

Aiymgul Toktarbayeva
- https://x.com/aiymgul91521
- https://www.linkedin.com/in/aiymgul-toktarbayeva-68a52a196/
