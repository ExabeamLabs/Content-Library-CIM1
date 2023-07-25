Vendor: Amazon
==============
### Product: [AWS GuardDuty](../ds_amazon_aws_guardduty.md)
### Use-Case: [Evasion](../../../../UseCases/uc_evasion.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  38   |   0    |     19     |      1      |    1    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Models |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| process-created | <b>T1070 - Indicator Removal on Host</b><br> ↳ <b>A-Formbook</b>: Possible Formbook usage on this asset<br> ↳ <b>Formbook</b>: Possible Formbook usage.<br><br><b>T1542.003 - T1542.003</b><br> ↳ <b>A-Formbook</b>: Possible Formbook usage on this asset<br> ↳ <b>Formbook</b>: Possible Formbook usage.<br><br><b>T1053 - Scheduled Task/Job</b><br> ↳ <b>A-BITS-Suspicious-Service</b>: First abnormal BITS job created on the asset.<br> ↳ <b>BITS-Suspicious-Service</b>: First abnormal BITS jobs created on the endpoint<br><br><b>T1059.001 - Command and Scripting Interperter: PowerShell</b><br> ↳ <b>A-Base64-Powershell-CmdLine-Keywords</b>: Base64 encoded strings were found in hidden malicious Powershell command lines on this asset.<br> ↳ <b>A-SIGRed</b>: Possible SIGRed (CVE-2020-1350) exploitation on this asset<br> ↳ <b>EXPERT-POWERSHELL-ENCRYPTED</b>: Encrypted argument in a Powershell command detected<br> ↳ <b>Sus-Powershell-Param</b>: Powershell was invoked with a suspicious parameter substring<br><br><b>T1059 - Command and Scripting Interperter</b><br> ↳ <b>A-TasksFolder-Evasion</b>: The 'tasks' directory was observed in a file creation command on this asset<br> ↳ <b>TasksFolder-Evasion</b>: The 'tasks' directory was observed in a file creation command<br><br><b>T1064 - Scripting</b><br> ↳ <b>A-TasksFolder-Evasion</b>: The 'tasks' directory was observed in a file creation command on this asset<br> ↳ <b>TasksFolder-Evasion</b>: The 'tasks' directory was observed in a file creation command<br><br><b>T1211 - Exploitation for Defense Evasion</b><br> ↳ <b>A-EquationEditor-Droppers</b>: Possible 'Eqnetd32.exe' exploit usage on this asset<br> ↳ <b>A-TasksFolder-Evasion</b>: The 'tasks' directory was observed in a file creation command on this asset<br> ↳ <b>EquationEditor-Droppers</b>: Possible 'Eqnetd32.exe' exploit usage<br> ↳ <b>TasksFolder-Evasion</b>: The 'tasks' directory was observed in a file creation command<br><br><b>T1036 - Masquerading</b><br> ↳ <b>A-Ping-Hex-IP</b>: A ping command used a hex decoded IP address on this asset.<br> ↳ <b>A-Taskmgr-Local-System</b>: A taskmgr.exe process was executed in the context of LOCAL_SYSTEM<br> ↳ <b>A-Sys-File-Exec-Anomaly</b>: A Windows program executable was started in a suspicious folder on this asset.<br> ↳ <b>A-Squibly-Two</b>: A WMI SquiblyTwo Attack with possibly renamed WMI by looking for imphash was detected on this asset.<br> ↳ <b>A-Taskmgr-as-Parent</b>: A process was created from Windows task manager on this asset.<br> ↳ <b>A-DLL-ULOAD-EquationGroup</b>: A known 'Equation Group' artifact was observed on this asset<br> ↳ <b>Sus-MsiExec-Directory</b>: Suspicious msiexec process started in an uncommon directory.<br> ↳ <b>Sus-Svchost-Process</b>: A suspicious svchost process was started.<br> ↳ <b>Sys-File-Exec-Anomaly</b>: A Windows program executable was started in a suspicious folder.<br> ↳ <b>Win-Proc-Sus-Parent</b>: A suspicious parent process of well-known Windows processes was detected.<br> ↳ <b>Taskmgr-as-Parent</b>: A process was created from Windows task manager.<br><br><b>T1127.001 - Trusted Developer Utilities Proxy Execution: MSBuild</b><br> ↳ <b>A-Win-Proc-Sus-Parent</b>: A suspicious parent process of well-known Windows processes was detected on this asset.<br> ↳ <b>Applocker-Bypass</b>: Execution of executables that can be used to bypass Applocker<br><br><b>T1218.004 - Signed Binary Proxy Execution: InstallUtil</b><br> ↳ <b>A-Win-Proc-Sus-Parent</b>: A suspicious parent process of well-known Windows processes was detected on this asset.<br> ↳ <b>Applocker-Bypass</b>: Execution of executables that can be used to bypass Applocker<br><br><b>T1218.009 - Signed Binary Proxy Execution: Regsvcs/Regasm</b><br> ↳ <b>A-Win-Proc-Sus-Parent</b>: A suspicious parent process of well-known Windows processes was detected on this asset.<br> ↳ <b>Applocker-Bypass</b>: Execution of executables that can be used to bypass Applocker<br><br><b>T1202 - Indirect Command Execution</b><br> ↳ <b>A-Applocker-Bypass</b>: Execution of executables that can be used to bypass Applocker on this asset<br> ↳ <b>Indirect-Cmd-Exec</b>: An indirect command was executed via Program Compatibility Assistant pcalua.exe or forfiles.exe.<br><br><b>T1562.004 - Impair Defenses: Disable or Modify System Firewall</b><br> ↳ <b>A-MsiExec-Web-Install</b>: A suspicious msiexec process was started with web addresses as a parameter on this asset.<br> ↳ <b>Firewall-Disabled-Netsh</b>: Windows firewall was turned off using netsh commands.<br><br><b>T1027 - Obfuscated Files or Information</b><br> ↳ <b>A-Base64-CommandLine</b>: Base64 string in command line execution on this asset<br> ↳ <b>A-Sus-Svchost-Process</b>: A suspicious svchost process was started on this asset.<br> ↳ <b>Ping-Hex-IP</b>: A ping command used a hex decoded IP address<br><br><b>T1140 - Deobfuscate/Decode Files or Information</b><br> ↳ <b>Ping-Hex-IP</b>: A ping command used a hex decoded IP address<br><br><b>T1564.004 - Hide Artifacts: NTFS File Attributes</b><br> ↳ <b>A-Powershell-ADS</b>: Powershell invoked using 'Alternate Data Stream' on this asset<br> ↳ <b>Powershell-ADS</b>: Powershell invoked using 'Alternate Data Stream'<br><br><b>T1132.001 - Data Encoding: Standard Encoding</b><br> ↳ <b>Base64-CommandLine</b>: Base64 string in command line<br><br><b>T1036.003 - Masquerading: Rename System Utilities</b><br> ↳ <b>A-PSExec-Rename</b>: PS Exec used on this asset<br> ↳ <b>PSExec-Rename</b>: PS Exec used<br><br><b>T1543.003 - Create or Modify System Process: Windows Service</b><br> ↳ <b>EPA-RANDOM-SERVICE</b>: Random service name for the user |        |