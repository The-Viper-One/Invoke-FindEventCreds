# Invoke-FindEventCreds
PowerShell script to parse Sysmon Event ID 1 and Security Event Log ID 4688 for command line credentials

`Invoke-FindEventCreds` connects to either the local or a remote computers Security log (Event ID 4688) and Sysmon Operational log (Event ID 1), parses each process creation event’s command‑line string, and matches it against a library of regex patterns for common binaries (net, schtasks, wmic, psexec, sc.exe, etc.). 

## Requirements

- Requires local administrator or SYSTEM privileges to local or remote system for successful querys
- Sysmon must be installed and configured to log ProcessCreate (Event ID 1) for the Sysmon portion to return data
- Audit Process Creation must be enabled under Advanced Audit Policy Configuration for event ID 4688 to be populated

## Usage

Download into memory
```powershell
IRM "https://raw.githubusercontent.com/The-Viper-One/Invoke-FindEventCreds/refs/heads/main/Invoke-FindEventCreds.ps1" | IEX
```

Execution
```powershell
# Local Execution
Invoke-FindEventCreds

# Remote Execution
Invoke-FindEventCreds -ComputerName WEB01
```
## Example Output
```
PS > Invoke-FindEventCreds


TimeCreated       : 05/07/2025 16:46:07
AccountName       : SECURITY\Moe
ProcessName       : C:\Windows\System32\net.exe
ParentProcessName : C:\Windows\System32\cmd.exe
CommandLine       : net  user testu /add Password123

TimeCreated       : 05/07/2025 16:46:03
AccountName       : SECURITY\Moe
ProcessName       : C:\Windows\System32\net.exe
ParentProcessName : C:\Windows\System32\cmd.exe
CommandLine       : net  user test /add Password123

TimeCreated       : 04/07/2025 21:23:20
AccountName       : SECURITY\Moe
ProcessName       : C:\Windows\System32\wbem\WMIC.exe
ParentProcessName : C:\Windows\System32\cmd.exe
CommandLine       : wmic  /node:"TARGETHOST" /user:AdminUser /password:Adm1nP@ss process call create "cmd.exe /c whoami"

TimeCreated       : 04/07/2025 21:22:50
AccountName       : SECURITY\Moe
ProcessName       : C:\Windows\System32\sc.exe
ParentProcessName : C:\Windows\System32\cmd.exe
CommandLine       : sc.exe  create MyService binPath= "C:\MyApp\app.exe" obj= "DOMAIN\ServiceAcct" password=SvcP@ss!

TimeCreated       : 05/07/2025 16:46:07
AccountName       : Moe
ProcessName       : C:\Windows\System32\net.exe
ParentProcessName : C:\Windows\System32\cmd.exe
CommandLine       : net  user testu /add Password123

TimeCreated       : 05/07/2025 16:46:03
AccountName       : Moe
ProcessName       : C:\Windows\System32\net.exe
ParentProcessName : C:\Windows\System32\cmd.exe
CommandLine       : net  user test /add Password123

TimeCreated       : 04/07/2025 21:23:20
AccountName       : Moe
ProcessName       : C:\Windows\System32\wbem\WMIC.exe
ParentProcessName : C:\Windows\System32\cmd.exe
CommandLine       : wmic  /node:"TARGETHOST" /user:AdminUser /password:Adm1nP@ss process call create "cmd.exe /c whoami"

TimeCreated       : 04/07/2025 21:22:50
AccountName       : Moe
ProcessName       : C:\Windows\System32\sc.exe
ParentProcessName : C:\Windows\System32\cmd.exe
CommandLine       : sc.exe  create MyService binPath= "C:\MyApp\app.exe" obj= "DOMAIN\ServiceAcct" password=SvcP@ss!

TimeCreated       : 04/07/2025 21:06:04
AccountName       : Moe
ProcessName       : C:\Windows\System32\net.exe
ParentProcessName : C:\Windows\System32\cmd.exe
CommandLine       : net  user logtest P@ssw0rd! /add

TimeCreated       : 04/07/2025 08:24:19
AccountName       : Moe
ProcessName       : C:\Windows\System32\schtasks.exe
ParentProcessName : C:\Windows\System32\cmd.exe
CommandLine       : schtasks  /Create /SC DAILY /TN "Backup" /TR "C:\Scripts\Backup.cmd" /RU ServiceAcct /RP P@ssServ!

TimeCreated       : 04/07/2025 08:24:16
AccountName       : Moe
ProcessName       : C:\Windows\System32\net.exe
ParentProcessName : C:\Windows\System32\cmd.exe
CommandLine       : net  use Z: \\FILESERVER\Share /user:DOMAIN\AdminUser SecureP@ss!

TimeCreated       : 04/07/2025 08:24:13
AccountName       : Moe
ProcessName       : C:\Windows\System32\net.exe
ParentProcessName : C:\Windows\System32\cmd.exe
CommandLine       : net  user NewUser P@ssw0rd123! /add
```
