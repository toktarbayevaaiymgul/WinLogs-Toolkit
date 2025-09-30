function Format-WinEvent
{
<#
.SYNOPSIS

Normalizes positional properties in input Windows event logs with named properties for easier analysis.

.DESCRIPTION

Format-WinEvent takes parsed Windows event logs from Get-WinEvent cmdlet and normalizes positional properties with named properties for easier analysis.

Author: Aiymgul Toktarbayeva (@aiymgul91521)
License: Apache License, Version 2.0
Required Dependencies: Get-WinEvent

.PARAMETER Events

Specifies parsed Windows event logs from Get-WinEvent cmdlet.

.EXAMPLE

PS C:\> $events = Get-WinEvent -Path ./Examples/Microsoft-Windows-Sysmon%4Operational.evtx
PS C:\> $events | Format-WinEvent `
                | Where-Object { $_.Id -eq 7 } `
                | ForEach-Object { $_.Props } `
                | Group-Object Company,Product `
                | Select-Object Count,Name

Count Name
----- ----
    4 Kroll, gkape
    1 Microsoft, Microsoft© ADAL
  113 Microsoft Corporation, Internet Explorer
   86 Microsoft Corporation, Microsoft (R) Windows (R) Operating System
    4 Microsoft Corporation, Microsoft ® Script Runtime
    1 Microsoft Corporation, Microsoft ® VBScript
    3 Microsoft Corporation, Microsoft ® Windows Script Host Runtime Library
   21 Microsoft Corporation, Microsoft OneDrive
    2 Microsoft Corporation, Microsoft SharePoint
    1 Microsoft Corporation, Microsoft SharePoint Calc Library
    1 Microsoft Corporation, Microsoft SharePoint HTTP Server
    1 Microsoft Corporation, Microsoft SharePoint Web Socket Client
    3 Microsoft Corporation, Microsoft Visual Basic for Applications
   10 Microsoft Corporation, Microsoft® .NET
   72 Microsoft Corporation, Microsoft® .NET Framework
    6 Microsoft Corporation, Microsoft® Visual Studio®
 3870 Microsoft Corporation, Microsoft® Windows® Operating System
    1 Sysinternals - www.sysinternals.com, Sysinternals autoruns
    2 The OpenSSL Project, https://www.openssl.org/, The OpenSSL Toolkit

.EXAMPLE

PS C:\> # Detection 1: Scheduled task executing mshta
PS C:\> $events = Get-WinEvent -Path ./Examples/Microsoft-Windows-Sysmon%4Operational.evtx
PS C:\> $events | Format-WinEvent `
                | Where-Object {
                    $_.Id -eq 1 -and
                    $_.Props.ParentImage -match '\\svchost\.exe$' -and
                    $_.Props.ParentCommandLine -match ' -p -s Schedule$' -and
                    $_.Props.Image -match '\\mshta\.exe$'
                } `
                | ForEach-Object { $_.Props } `
                | Select-Object RuleName,ParentImage,ParentCommandLine,Image,CommandLine

RuleName          : technique_id=T1218.005,technique_name=Mshta
ParentImage       : C:\Windows\System32\svchost.exe
ParentCommandLine : C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
Image             : C:\Windows\System32\mshta.exe
CommandLine       : "C:\Windows\System32\mshta.exe" C:\Users\user\AppData\Local\Settings\locale

.EXAMPLE

PS C:\> # Detection 2: Winword loading suspicious DLLs
PS C:\> $events = Get-WinEvent -Path ./Examples/Microsoft-Windows-Sysmon%4Operational.evtx
PS C:\> $events | Format-WinEvent `
                | Where-Object {
                    $_.Id -eq 7 -and
                    $_.Props.Image -match '\\WINWORD\.EXE$' -and
                    $_.Props.ImageLoaded -match '\\(taskschd.dll|wshom.ocx)$'
                } `
                | ForEach-Object { $_.Props } `
                | Select-Object RuleName,Image,ImageLoaded,Signed,Signature,SignatureStatus

RuleName        : technique_id=T1059,technique_name=Command and Scripting Interpreter
Image           : C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
ImageLoaded     : C:\Windows\System32\wshom.ocx
Signed          : true
Signature       : Microsoft Windows
SignatureStatus : Valid

RuleName        : technique_id=T1053,technique_name=Scheduled Task
Image           : C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
ImageLoaded     : C:\Windows\System32\taskschd.dll
Signed          : true
Signature       : Microsoft Windows
SignatureStatus : Valid

RuleName        : technique_id=T1059,technique_name=Command and Scripting Interpreter
Image           : C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
ImageLoaded     : C:\Windows\System32\wshom.ocx
Signed          : true
Signature       : Microsoft Windows
SignatureStatus : Valid

.EXAMPLE

PS C:\> # Detection 3: Mshta making DNS request/query
PS C:\> $events = Get-WinEvent -Path ./Examples/Microsoft-Windows-Sysmon%4Operational.evtx
PS C:\> $events | Format-WinEvent `
                | Where-Object {
                    $_.Id -eq 22 -and
                    $_.Props.Image -match '\\mshta\.exe$'
                } `
                | ForEach-Object { $_.Props } `
                | Select-Object RuleName,Image,QueryName

RuleName Image                         QueryName
-------- -----                         ---------
-        C:\Windows\System32\mshta.exe background-services.net

.NOTES

This is a personal project developed by Aiymgul Toktarbayeva.

.LINK

https://x.com/aiymgul91521
https://www.linkedin.com/in/aiymgul-toktarbayeva-68a52a196/
#>

    [OutputType('PSCustomObject')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]
        $Events
    )

    begin
    {

    }

    process
    {
        # Loop through all input events.
        $Events.ForEach(
        {
            $curEvent = $_

            # Extract positional properties and normalize to named properties in new "Props" property.
            $props = $curEvent.Properties
            $propsNormalized = $null
            $propsNormalized = switch ($curEvent.LogName)
            {
                'Security' {
                    switch ($curEvent.Id)
                    {
                        4688 {
                            # Process Creation Event
                            [PSCustomObject] @{
                                SubjectUserSid = $props[0].Value
                                SubjectUserName = $props[1].Value
                                SubjectDomainName = $props[2].Value
                                SubjectLogonId = $props[3].Value
                                NewProcessId = $props[4].Value
                                NewProcessName = $props[5].Value
                                TokenElevationType = $props[6].Value
                                ProcessId = $props[7].Value
                                CommandLine = $props[8].Value
                                TargetUserSid = $props[9].Value
                                TargetUserName = $props[10].Value
                                TargetDomainName = $props[11].Value
                                TargetLogonId = $props[12].Value
                                ParentProcessName = $props[13].Value
                                MandatoryLabel = $props[14].Value
                            }
                        }
                    }
                }
                'Microsoft-Windows-Sysmon/Operational' {
                    # Source: https://github.com/olafhartong/sysmon-cheatsheet/blob/master/Sysmon-Cheatsheet.pdf

                    # Remove rule name if present instead of UtcTime as first property.
                    $ruleName = $null
                    if ($props[1].Value -match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+')
                    {
                        $ruleName = $props[0].Value
                        $props = $props | Select-Object -Skip 1
                    }

                    switch ($curEvent.Id)
                    {
                        1 {
                            # Process Create
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                ProcessGuid = $props[1].Value
                                ProcessId = $props[2].Value
                                Image = $props[3].Value
                                FileVersion = $props[4].Value
                                Description = $props[5].Value
                                Product = $props[6].Value
                                OriginalFileName = $props[7].Value
                                Company = $props[8].Value
                                CommandLine = $props[9].Value
                                CurrentDirectory = $props[10].Value
                                User = $props[11].Value
                                LogonGuid = $props[12].Value
                                LogonId = $props[13].Value
                                TerminalSessionId = $props[14].Value
                                IntegrityLevel = $props[15].Value
                                Hashes = $props[16].Value
                                ParentProcessGuid = $props[17].Value
                                ParentProcessId = $props[18].Value
                                ParentImage = $props[19].Value
                                ParentCommandLine = $props[20].Value
                                ParentUser = $props[21].Value
                            }
                        }
                        2 {
                            # File Creation Time Changed
                            [PSCustomObject] @{
                                RuleName=$ruleName
                                UtcTime = $props[0].Value
                                ProcessGuid = $props[1].Value
                                ProcessId = $props[2].Value
                                Image = $props[3].Value
                                TargetFilename = $props[4].Value
                                CreationUtcTime = $props[5].Value
                                PreviousCreationUtcTime = $props[6].Value
                                User = $props[7].Value
                            }
                        }
                        3 {
                            # Network Connection
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                ProcessGuid = $props[1].Value
                                ProcessId = $props[2].Value
                                Image = $props[3].Value
                                User = $props[4].Value
                                Protocol = $props[5].Value
                                Initiated = $props[6].Value
                                SourceIsIpv6 = $props[7].Value
                                SourceIp = $props[8].Value
                                SourceHostname = $props[9].Value
                                SourcePort = $props[10].Value
                                SourcePortName = $props[11].Value
                                DestinationIsIpv6 = $props[12].Value
                                DestinationIp = $props[13].Value
                                DestinationHostname = $props[14].Value
                                DestinationPort = $props[15].Value
                                DestinationPortName = $props[16].Value
                            }
                        }
                        4 {
                            # Sysmon Service State Changed
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                State = $props[1].Value
                                Version = $props[2].Value
                                SchemaVersion = $props[3].Value
                            }
                        }
                        5 {
                            # Process Terminated
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                ProcessGuid = $props[1].Value
                                ProcessId = $props[2].Value
                                Image = $props[3].Value
                                User = $props[4].Value 
                            }
                        }
                        6 {
                            # Kernel Driver Loaded
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                ImageLoaded = $props[1].Value
                                Hashes = $props[2].Value
                                Signed = $props[3].Value
                                Signature = $props[4].Value
                                SignatureStatus = $props[5].Value
                            }
                        }
                        7 {
                            # Image Loaded
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                ProcessGuid = $props[1].Value
                                ProcessId = $props[2].Value
                                Image = $props[3].Value
                                ImageLoaded = $props[4].Value
                                FileVersion = $props[5].Value
                                Description = $props[6].Value
                                Product = $props[7].Value
                                Company = $props[8].Value
                                OriginalFileName = $props[9].Value
                                Hashes = $props[10].Value
                                Signed = $props[11].Value
                                Signature = $props[12].Value
                                SignatureStatus = $props[13].Value
                                User = $props[14].Value
                            }
                        }
                        8 {
                            # Remote Thread
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                SourceProcessGuid = $props[1].Value
                                SourceProcessId = $props[2].Value
                                SourceImage = $props[3].Value
                                TargetProcessGuid = $props[4].Value
                                TargetProcessId = $props[5].Value
                                TargetImage = $props[6].Value
                                NewThreadId = $props[7].Value
                                StartAddress = $props[8].Value
                                StartModule = $props[9].Value
                                StartFunction = $props[10].Value
                                SourceUser = $props[11].Value
                                TargetUser = $props[12].Value
                            }
                        }
                        9 {
                            # Raw Access Read
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                ProcessGuid = $props[1].Value
                                ProcessId = $props[2].Value
                                Image = $props[3].Value
                                Device = $props[4].Value
                                User = $props[5].Value
                            }
                        }
                        10 {
                            # Process Access
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                SourceProcessGuid = $props[1].Value
                                SourceProcessId = $props[2].Value
                                SourceThreadId = $props[3].Value
                                SourceImage = $props[4].Value
                                TargetProcessGuid = $props[5].Value
                                TargetProcessID = $props[6].Value
                                TargetImage = $props[7].Value
                                GrantedAccess = $props[8].Value
                                CallTrace = $props[9].Value
                                SourceUser = $props[10].Value
                                TargetUser = $props[11].Value
                            }
                        }
                        11 {
                            # File Create
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                ProcessGuid = $props[1].Value
                                ProcessId = $props[2].Value
                                Image = $props[3].Value
                                TargetFileName = $props[4].Value
                                CreationUtcTime = $props[5].Value
                                User = $props[6].Value
                            }
                        }
                        12 {
                            # Registry Event (Object Create and Delete)
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                ProcessGuid = $props[1].Value
                                ProcessId = $props[2].Value
                                Image = $props[3].Value
                                TargetObject = $props[4].Value
                                User = $props[5].Value
                            }
                        }
                        13 {
                            # Registry Event (Value Set)
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                EventType = $props[1].Value
                                ProcessGuid = $props[2].Value
                                ProcessId = $props[3].Value
                                Image = $props[4].Value
                                TargetObject = $props[5].Value
                                Details = $props[6].Value
                                User = $props[7].Value
                            }
                        }
                        14 {
                            # Registry Event (Key and Value Rename)
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                ProcessGuid = $props[1].Value
                                ProcessId = $props[2].Value
                                Image = $props[3].Value
                                TargetObject = $props[4].Value
                                NewName = $props[5].Value
                                User = $props[6].Value
                            }
                         }
                         15 {
                            # File Create Stream Hash
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                ProcessGuid = $props[1].Value
                                ProcessId = $props[2].Value
                                Image = $props[3].Value
                                TargetFilename = $props[4].Value
                                CreationUtcTime = $props[5].Value
                                Hash = $props[6].Value
                                User = $props[7].Value
                            }
                         }
                         16 {
                            # Sysmon Config State Changed
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                Configuration = $props[1].Value
                                ConfigurationFileHash = $props[2].Value
                            }
                         }
                         17 {
                            # Pipe Event (Pipe Created)
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                ProcessGuid = $props[1].Value
                                ProcessId = $props[2].Value
                                PipeName = $props[3].Value
                                Image = $props[4].Value
                                User = $props[5].Value
                            }
                         }
                         18 {
                            # Pipe event (Pipe Connected)
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                EventType = $props[1].Value
                                ProcessGuid = $props[2].Value
                                ProcessId = $props[3].Value
                                PipeName = $props[4].Value
                                Image = $props[5].Value
                                User = $props[6].Value
                            }
                         }
                         19 {
                            # WMI Event (WmiEventFilter Activity Cetected)
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                EventType = $props[1].Value
                                Operation = $props[2].Value
                                User = $props[3].Value
                                EventNamespace = $props[4].Value
                                Name = $props[5].Value
                                Query = $props[6].Value
                            }
                         }
                         20 {
                            # WMI Event (WmiEventConsumer Activity Detected)
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                EventType = $props[1].Value
                                Operation = $props[2].Value
                                User = $props[3].Value
                                Name = $props[4].Value
                                Type = $props[5].Value
                                Destination = $props[6].Value
                            }
                         }
                         21 {
                            # WMI Event (WmiEventConsumerToFilter Activity Detected)
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                EventType = $props[1].Value
                                Operation = $props[2].Value
                                User = $props[3].Value
                                Consumer = $props[4].Value
                                Filter = $props[5].Value
                            }
                         }
                         22 {
                            # DNS Event
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                ProcessGuid = $props[1].Value
                                ProcessId = $props[2].Value
                                QueryName = $props[3].Value
                                QueryStatus = $props[4].Value
                                QueryResults = $props[5].Value
                                Image = $props[6].Value
                                User = $props[7].Value
                            }
                         }
                         23 {
                            # File Delete Event
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                ProcessGuid = $props[1].Value
                                ProcessId = $props[2].Value
                                User = $props[3].Value
                                Image = $props[4].Value
                                TargetFilename = $props[5].Value
                                Hashes = $props[6].Value
                                IsExecutable = $props[7].Value
                                Archived = $props[8].Value
                            }
                         }
                         24 {
                            # Clipboard Event
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                ProcessGuid = $props[1].Value
                                ProcessId = $props[2].Value
                                Image = $props[3].Value
                                Session = $props[4].Value
                                Clientinfo = $props[5].Value
                                Hashes = $props[6].Value
                                Archived = $props[7].Value
                                User = $props[8].Value
                            }
                         }
                         25 {
                            # Process Tampering
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                ProcessGuid = $props[1].Value
                                ProcessId = $props[2].Value
                                Image = $props[3].Value
                                Type = $props[4].Value
                                User = $props[5].Value
                            }
                         }
                         26 {
                            # File Delete Detected
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                ProcessGuid = $props[1].Value
                                ProcessId = $props[2].Value
                                Image = $props[3].Value
                                TargetFilename = $props[4].Value
                                Hashes = $props[5].Value
                                IsExecutable = $props[6].Value
                            }
                         }
                         255 {
                            # Sysmon Error
                            [PSCustomObject] @{
                                RuleName = $ruleName
                                UtcTime = $props[0].Value
                                ID = $props[1].Value
                                Description = $props[2].Value
                            }
                        }
                    }
                }
            }

            # Add "Props" property with normalized named properties.
            if ($propsNormalized)
            {
                $curEvent | Add-Member -MemberType NoteProperty -Name 'Props' -Value $propsNormalized -Force
            }

            $curEvent
        } )

    }

    end
    {

    }
}