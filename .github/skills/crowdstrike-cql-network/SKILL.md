---
name: crowdstrike-cql-network
description: "Use for CrowdStrike CQL hunts covering endpoint network connections, DNS, public IPs, RDP exposure, lateral movement, C2 beaconing, Tor, or remote-management DNS."
user-invocable: true
---

# Network and Lateral-Movement Hunting

Use these query bodies as starting points. Validate event names, fields, time scope, function support, and telemetry availability in the target tenant. These queries are investigative leads, not verdicts.

## External Connectons with Process

Source file: `External_Connectons_with_Process.yml`

```cql
#event_simpleName=NetworkConnectIP4 aid=?aid ComputerName=?Computername RemoteAddressIP4=?RemoteIP 
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8","192.168.0.0/16","172.16.0.0/12","127.0.0.0/8"])
| join({#event_simpleName=ProcessRollup2  FileName=?Processname }, field=[ContextProcessId],key=TargetProcessId, include=[FileName, UserName,ImageFileName, RemoteAddressIP4, RemotePort,CommandLine], mode=left)
| groupBy(UserName, function=collect([FileName, UserName, ImageFileName, RemoteIP, RPort, CommandLine]))
| sort([_count], order=asc)
```

## Detection of External Direct IP Usage in CommandLine Windows and Mac

Source file: `Detection_of_External_Direct_IP_Usage_in_CommandLine_Windows_and_Mac.yml`

```cql
in(#event_simpleName, values=["ProcessRollup2","SyntheticProcessRollup2"])
| CommandLine=*http* event_platform!="Lin"
// Basline to exclude legitimate process 
//| !in(field="ParentBaseFileName", values=//["UmbrellaDiagnostic.exe","HPClickExe","Eagle" ,"HPClick.exe"])
//| !in(field="FileName", values=["Google Chrome","chrome.exe"]) 
//| !in(field="CommandLine", values=["Google Chrome.app"])
| regex("(?<Urlink>\\bhttps?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*\\/\\b)", field=CommandLine)
| regex("(?<Ipaddress>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})", field=Urlink)
| !cidr(Ipaddress, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "168.63.0.0/16", "0.0.0.0/8"])
// Basline to exclude legitimate url | !in(field="Urlink", values=[
// Basline to exclude legitimate url  "http://100.1.1.1"
// Basline to exclude legitimate url ])
| default(field=GrandParentBaseFileName, value="Unknown")
| rootURL := "https://falcon.crowdstrike.com/"
| ProcessStartTime := round(ProcessStartTime)
| processStart:=formattime(field=ProcessStartTime, format="%m/%d %H:%M:%S")
// If Context Process ID is available utilize it, if not utilize Target Process ID
| case{ ContextProcessId ="*"
| ContextId:=ContextProcessId; TargetProcessId="*"
| ContextId:=TargetProcessId}
// Create URLs for Process and Graph Explorers
| format("[ProcessExplorer]%sinvestigate/process-explorer/%s/%s?_cid=%s", field=["rootURL", "aid", "ContextId", "cid"], as="ProcessExplorer")
| format("[GraphExplorer]%sgraphs/process-explorer/graph?id=pid:%s:%s", field=["rootURL", "aid", "TargetProcessId"], as="GraphExplorer")
// Format Execution Details for easy analysis
| format(format="%s\n\t↳ %s[ppid=%s]\n\t\t↳ %s [pid=%s|raw_pid=%s|start=%s]\n\t\t\t%,.100s[...TRIMMED]\n\t\t\t%s\n\t\t\t%s\n---", field=[GrandParentBaseFileName, ParentBaseFileName, ParentProcessId, ImageFileName, TargetProcessId, RawProcessId, processStart, CommandLine, ProcessExplorer, GraphExplorer], as="ExecutionSummary")
// Group by Source Host
| groupBy([ComputerName],function=([count(aid, as=executeCount), min(@timestamp, as=firstSeen), max(@timestamp, as=lastSeen), collect([UserName,ExecutionSummary,Ipaddress,ParentBaseFileName,ParentProcessId,ImageFileName,TargetProcessId], limit=1000)]))
| firstSeen:=formattime(field=firstSeen, format="%Y/%m/%d %H:%M:%S")
| lastSeen:=formattime(field=lastSeen, format="%Y/%m/%d %H:%M:%S")
```

## DNS Resolutions from Browser Processes

Source file: `DNS_Resolutions_from_Browser_Processes.yml`

```cql
// Get all process execution and DNS events on Windows
(#event_simpleName=ProcessRollup2 OR #event_simpleName=DnsRequest) event_platform=Win
| ComputerName=~wildcard(?ComputerName, ignoreCase=true)
// Normalize file name value across both events
| fileName:=concat([FileName, ContextBaseFileName])
// Make sure responsible process is a web browser
| in(field="fileName", values=[chrome.exe, firefox.exe, msedge.exe], ignoreCase=true)
// Normalize Falcon UPID
| falconPID:=TargetProcessId | falconPID:=ContextProcessId
// Use selfJoinFilter to make sure execution and DNS resolution occured under the same UPID value
| selfJoinFilter(field=[aid, falconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=DnsRequest}])
// Aggregate results
| groupBy([aid, falconPID], function=([collect([ComputerName, UserName, fileName, DomainName])]))
```

## Internet-Exposed RDP - Inbound Accepts from Public IPs

Source file: `Internet_Exposed_RDP_Inbound_Accepts_from_Public_IPs.yml`

```cql
#event_simpleName=NetworkReceiveAcceptIP4 event_platform=Win
| LocalPort=3389
// Drop private, loopback, link-local and CGNAT source ranges
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10"])
| groupBy([ComputerName, aip], function=[count(as=TotalAccepts), count(RemoteAddressIP4, distinct=true, as=UniqueRemoteIPs), collect([RemoteAddressIP4], limit=20), max(@timestamp, as=LastSeen)])
| formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen, as=LastSeen)
| sort(UniqueRemoteIPs, order=desc, limit=200)
```

## Lateral Movement Detection

Source file: `Lateral_Movement_Detection.yml`

```cql
#event_simpleName=NetworkConnect 
| (RemotePort=445 OR RemotePort=3389 OR RemotePort=5985)
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| join({#event_simpleName=ProcessRollup2}, field=[aid, RawProcessId], include=[ImageFileName, CommandLine])
| join({#event_simpleName=UserIdentity}, field=AuthenticationID, include=[UserName])
| table([aid, UserName, ImageFileName, RemoteAddressIP4, RemotePort, CommandLine])
```

## C2 Beaconing Detection

Source file: `c2_beaconing_detection.yml`

```cql
#event_simpleName=NetworkConnectIP4

// Keep only egress to routable / external destinations
| !cidr(RemoteAddressIP4, subnet=[
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
    "0.0.0.0/8", "100.64.0.0/10"
  ])

// Drop high-volume benign services that create artificial regularity
| RemotePort != 53
| RemotePort != 123
| RemotePort != 137
| RemotePort != 138

// ===== STAGE 1: detect beacons per destination IP =====
// Channel = host -> (remote IP + port). Keeping the IP here means two distinct
// beacons to the same provider are never merged before their cadence is measured.
| ConnKey := format(format="%s:%s", field=[RemoteAddressIP4, RemotePort])
| ts := @timestamp
| sort(field=[aid, ConnKey, ts], order=[asc, asc, asc], limit=max)
| neighbor(include=[ts, aid, ConnKey], prefix=prev, direction=preceding)
| test(aid == prev.aid)
| test(ConnKey == prev.ConnKey)
| Delta := (ts - prev.ts) / 1000
| Delta >= 1
| groupBy([aid, ComputerName, RemoteAddressIP4, RemotePort], function=[
    count(as=Beacons),
    avg(Delta, as=AvgInterval),
    stdDev(field=Delta, as=JitterStdDev)
  ], limit=max)
| CoV := JitterStdDev / AvgInterval

// Beaconing profile (applied per IP so each real channel is judged on its own)
| Beacons >= 8
| AvgInterval >= 10
| AvgInterval <= 86400
| CoV < 0.10

// ===== STAGE 2: de-duplicate anycast edges by (org + cadence) =====
| asn(RemoteAddressIP4)
| Org := coalesce([RemoteAddressIP4.org, RemoteAddressIP4])

// --- OPTIONAL ALLOWLIST ------------------------------------------------
// Populate with orgs already attributed to benign scheduled software.
// Do NOT blanket-trust Fastly / Cloudflare / Google - they are common C2
// fronting providers; allowlist only AFTER confirming the process.
// | !in(field=Org, values=["EXAMPLE VENDOR ORG", "ANOTHER TRUSTED ORG"])
// -----------------------------------------------------------------------

// Bucket the interval to the nearest minute so identical-cadence siblings merge,
// but channels with genuinely different intervals remain distinct rows.
| CadenceBucket := AvgInterval / 60
| CadenceBucket := round(CadenceBucket)
| groupBy([aid, ComputerName, Org, RemotePort, CadenceBucket], function=[
    count(as=EdgeIPs),
    collect([RemoteAddressIP4], limit=25),
    avg(Beacons, as=Beacons),
    avg(AvgInterval, as=AvgInterval),
    avg(JitterStdDev, as=JitterStdDev),
    avg(CoV, as=CoV)
  ], limit=max)

| Beacons := round(Beacons)
| AvgInterval := round(AvgInterval)
| JitterStdDev := round(JitterStdDev)
| sort(field=CoV, order=asc, limit=20000)
| format(format="%.4f", field=CoV, as=CoV)
| table([ComputerName, aid, Org, RemotePort, EdgeIPs, RemoteAddressIP4, Beacons, AvgInterval, JitterStdDev, CoV], limit=20000)
```

## Connections to Tor Exit Nodes

Source file: `connections_to_tor_exit_nodes.yml`

```cql
#event_simpleName=NetworkConnectIP4
| match(file="tor-exit-nodes.csv", field=RemoteAddressIP4, column=ip, strict=true)
| groupBy(
    [aid, ComputerName],
    function=[
        count(aid, as=ConnectionCount),
        count(aid, distinct=true, as=UniqueIPs),
        collect([RemoteAddressIP4, RemotePort]),
        min(@timestamp, as=FirstSeen),
        max(@timestamp, as=LastSeen)
    ]
  )
| FirstSeen := formatTime(format="%Y-%m-%d %H:%M:%S", field=FirstSeen)
| LastSeen  := formatTime(format="%Y-%m-%d %H:%M:%S", field=LastSeen)
| sort(ConnectionCount, order=desc)
```

## Detect Remote Monitoring and Management (RMM) Tools over DNS

Source file: `detect_rmm_dns.yml`

```cql
#event_simpleName=DnsRequest
| DomainName=/anydesk\.com|action1\.com|beamyourscreen\.com|snapview\.de|rustdesk\.com|fleetdeck\.io|tailscale\.com|dwservice\.net|secure\.logmein\.com|teamviewer\.com|screenconnect\.com|fixme\.it|n-able\.com|domotz\.com|datto\.com|level\.io|itarian\.com|pulseway\.com|zoho\.com|manageengine\.com|bomgarcloud\.com|bomgar\.com|zabbix\.com/i
| groupBy([DomainName],function=[collect(ContextBaseFileName), count(aid,distinct=true,as=HostCount)])
| sort(HostCount,order=asc)
```

## Additional Query Patterns

The following CQL bodies are embedded directly for reuse. Validate event names, field availability, query-surface support, and telemetry in the target environment.

### DNS Staging Detection: ClickFix-Inspired nslookup Execution

Source YAML: `dns_staging_detection_clickfix_inspired_nslookup_execution.yml`

```cql
// Start with process execution events for performance
#event_simpleName = ProcessRollup2
// Filter for nslookup.exe
| ImageFileName = /\\nslookup\.exe$/i
// Looks for nslookup using specific record types (like TXT or ALL) and a piped parsing/execution chain associated with payload staging
| CommandLine = /(nslookup|n\^s\^l\^o\^o\^k\^u\^p).*(((-q|querytype|type)=?\s*)?(txt|all)).*\|.*findstr.*\|.*for \/f.*\|.*cmd/i
// Exclude common administrative noise if necessary
| ParentBaseFileName != /services\.exe|monitoring_agent\.exe/i
// Summarize the activity
| groupBy([ComputerName, UserName, ParentBaseFileName, CommandLine], limit=max)
```

### Overnight Post-RDP Activity Detection

Source YAML: `overnight-post-rdp-activity.yml`

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|wmic|msbuild|installutil|regasm|regsvcs|certutil|bitsadmin|schtasks|sc|net|net1|nltest|whoami|quser|query|systeminfo|hostname|tasklist|netstat|ipconfig|curl|wget|rclone|scp|sftp|ftp|makecab|tar|7z|7za|rar|winrar|psexec|paexec|winrs|ssh|python|pythonw)\.exe$/i
// Parent/GrandParent: DENYLIST (fails open) — blank or unknown lineage still passes; only listed off-hours noise is dropped.
// To tune: add a process BASE name (no path, no .exe), case-insensitive, pipe-separated, inside the ( ) on BOTH lines as you confirm benign off-hours jobs.
// Example (parent): | ParentBaseFileName!=/^(AteraAgent|Syncro|Pulseway)\.exe$/i
// Example (grandparent): | GrandParentBaseFileName!=/^(MeshAgent|NinjaRMMAgent|CagService)\.exe$/i
| ParentBaseFileName!=/^()\.exe$/i
| GrandParentBaseFileName!=/^()\.exe$/i
| case {
CommandLine=/\b(whoami|quser|query\s+user|net1?(\.exe)?"?\s+(users?|group|localgroup|session)|nltest|ipconfig\s+\/all|systeminfo|hostname|tasklist|wmic|netstat)\b/i
| SignalType := "Enumeration";
CommandLine=/\b(Get-Process|Get-NetTCPConnection|Get-SmbShare|Get-ADUser|Get-ADComputer|Get-DomainUser|Get-DomainComputer)\b/i
| SignalType := "PowerShell Enumeration";
CommandLine=/\b(rclone|curl|wget|scp|sftp|ftp|bitsadmin|certutil|makecab|tar|7z|7za|rar|winrar)\b/i
| SignalType := "Transfer or Archive Utility";
CommandLine=/\b(Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|Compress-Archive|System\.IO\.Compression)\b/i
| SignalType := "PowerShell Transfer or Archive";
ImageFileName=/\\(cmd|powershell|pwsh)\.exe$/i AND CommandLine=/\s-(?:enc|encodedcommand)(?:\s|$|:)/i
| SignalType := "Windows Command Processor or PowerShell";
*
| SignalType := "Other"
}
| SignalType!="Other"
| CommandTimestampMs := ProcessStartTime * 1000
| join(
{
#event_simpleName=UserLogon event_platform=Win LogonType=10
| remoteHour := formatTime("%H", field=@timestamp, locale=en_US, timezone="America/Vancouver") // adjust timezone to where your clients/company operate (e.g. America/New_York for Eastern)
| in(field=remoteHour, values=["21","22","23","00","01","02","03"]) // adjust hours here as well if needed: Example: "02" will detect up to 02:59:99
| LogonTimestampMs := LogonTime * 1000
},
field=[aid, AuthenticationId],
include=[LogonTimestampMs, UserPrincipal, RemoteAddressIP4, LogonType]
)
| TimeFromLogonMinutes := (CommandTimestampMs - LogonTimestampMs) / 60000
| TimeFromLogonMinutes >= 0
| TimeFromLogonMinutes <= 30 // adjust for a longer capture window from logon to command execution
| table([@timestamp, cid, LogonTimestampMs, CommandTimestampMs, TimeFromLogonMinutes, aid, ComputerName, UserName, UserPrincipal, LogonType, RemoteAddressIP4, SignalType, ImageFileName, FileName, FilePath, CommandLine, ParentBaseFileName, GrandParentBaseFileName, OriginalFilename, SHA256HashData], limit=1000)
| sort(@timestamp, order=desc)
```

### Process Execution directly from SMB share or SMB-mapped path

Source YAML: `process_execution_directly_from_smb_share_or_smb_mapped_path.yml`

```cql
| #Vendor = crowdstrike
| #repo = "base_sensor"
| "#event_simpleName"="ProcessExecOnSMBFile"
| table([@timestamp,UserName,ComputerName,ClientComputerName,LocalAddressIP4,RemoteAddressIP4])
```

### Systems Initiating Connections to a High Number of Ports

Source YAML: `systems_initiating_connections_to_a_high_number_of_ports.yml`

```cql
#event_simpleName=/^(NetworkConnectIP4|ProcessRollup2)$/
| falconPID:=TargetProcessId | falconPID:=ContextProcessId
| UserID:=UserSid | UserID:=UID
| selfJoinFilter(field=[aid, falconPID], where=[{#event_simpleName=NetworkConnectIP4}, {#event_simpleName=ProcessRollup2}])
| groupBy([aid, ComputerName, falconPID], function=([
	collect([FileName, CommandLine, UserName, UserID]), 
	count(RemotePort, as=uniquePortCount), 
	collect([RemotePort], separator=", ", limit=25), 
	count(RemoteAddressIP4, distinct=true, as=remoteIPcount)
	]), limit=max)
| FileName=* RemotePort=*
| test(uniquePortCount>25)
```

### Unauthorized RMM Tool Usage

Source YAML: `unauthorized_rmm_tool_usage.yml`

```cql
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2
| ImageFileName=/(\\|\/)(?<FileName>[^\\\/]+)$/
| case {
    FileName=/^anydesk(_custom)?(\.exe)?$/i                                  | RMMTool:="AnyDesk";
    FileName=/^(teamviewer(_service|_desktop)?|tv_w32|tv_x64)(\.exe)?$/i     | RMMTool:="TeamViewer";
    FileName=/^(screenconnect|connectwise)[\w.]*(\.exe)?$/i                  | RMMTool:="ScreenConnect / ConnectWise";
    FileName=/^(ateraagent|atera[\w.]*)(\.exe)?$/i                           | RMMTool:="Atera";
    FileName=/^(splashtop[\w.]*|srservice|strwinclt|srmanager)(\.exe)?$/i    | RMMTool:="Splashtop";
    FileName=/^rustdesk(\.exe)?$/i                                           | RMMTool:="RustDesk";
    FileName=/^supremo(helper|service)?(\.exe)?$/i                           | RMMTool:="Supremo";
    FileName=/^ammyy[\w.]*(\.exe)?$/i                                        | RMMTool:="Ammyy Admin";
    FileName=/^ultraviewer[\w.]*(\.exe)?$/i                                  | RMMTool:="UltraViewer";
    FileName=/^(dwagent|dwagsvc)(\.exe)?$/i                                  | RMMTool:="DWService";
    FileName=/^meshagent(\.exe)?$/i                                          | RMMTool:="MeshCentral / TacticalRMM";
    FileName=/^(logmein[\w.]*|lmiguardiansvc)(\.exe)?$/i                     | RMMTool:="LogMeIn";
    FileName=/^(gotoassist[\w.]*|gotohttp|g2comm|g2host)(\.exe)?$/i          | RMMTool:="GoTo Assist";
    FileName=/^(rutserv|rfusclient|remoteutilities[\w.]*)(\.exe)?$/i         | RMMTool:="Remote Utilities";
    FileName=/^radmin[\w.]*(\.exe)?$/i                                       | RMMTool:="Radmin";
    FileName=/^(nomachine|nxservice|nxplayer|nxnode)(\.exe)?$/i              | RMMTool:="NoMachine";
    FileName=/^(dwrcs|dameware[\w.]*)(\.exe)?$/i                             | RMMTool:="DameWare";
    FileName=/^(zohours|zohomeeting|zaservice|za_connect)(\.exe)?$/i         | RMMTool:="Zoho Assist";
    FileName=/^(ngrok|frpc|frps)(\.exe)?$/i                                  | RMMTool:="Tunneling (ngrok/frp)";
    * | RMMTool:="none";
}
| RMMTool != "none"
| groupBy([RMMTool, aid, ComputerName, UserName], function=[
    count(as=Executions),
    collect([ImageFileName, CommandLine], limit=10),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ], limit=10000)
| formatTime(format="%F %T %Z", field=FirstSeen, as=FirstSeen)
| formatTime(format="%F %T %Z", field=LastSeen, as=LastSeen)
| sort(LastSeen, order=desc)
```

### Users creating Network Shares

Source YAML: `users_creating_network_shares.yml`

```cql
#event_simpleName="NetShareAdd"
| wildcard(field=UserName, pattern=?UserName, ignoreCase=true)
| wildcard(field=ComputerName, pattern=?ComputerName, ignoreCase=true)
| groupBy([ComputerName, UserName, ShareName, SharePath, ShareData, @timestamp])
```
