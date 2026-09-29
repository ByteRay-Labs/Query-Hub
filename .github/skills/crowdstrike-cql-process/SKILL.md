---
name: crowdstrike-cql-process
description: "Use when writing CrowdStrike CQL for process execution, PowerShell, encoded commands, command lines, LOLBins, process trees, credential-dumping indicators, or DLL side-loading."
user-invocable: true
---

# Process and Script Hunting

Use these query bodies as starting points. Validate event names, fields, time scope, function support, and telemetry availability in the target tenant. These queries are investigative leads, not verdicts.

## Command History with Process Tree

Source file: `Command_History_with_Process_Tree.yml`

```cql
#event_simpleName=/^(CommandHistory|ProcessRollup2)$/
event_platform=Win
| selfJoinFilter(
    field=[aid, TargetProcessId],
    where=[
      { #event_simpleName=ProcessRollup2 },
      { #event_simpleName=CommandHistory }
    ]
  )
| case {
    #event_simpleName=CommandHistory
    | CommandHistory=*
    | splitString(
        field=CommandHistory,
        by="¶",
        as=CommandHistorySplit
      )
    | concatArray(
        CommandHistorySplit,
        separator="\n",
        as=CommandHistoryClean
      );

    #event_simpleName=ProcessRollup2
    | ImageFileName=/\\(?<ChildBaseFileName>[^\\]+)$/
    | ExecutionChain := format(
        format="%s → %s (PID: %s)",
        field=[ParentBaseFileName, ChildBaseFileName, RawProcessId]
      );
  }
| groupBy([aid, ComputerName, TargetProcessId], function=[
    selectLast(ExecutionChain),
    selectLast(CommandHistoryClean)
  ], limit=max)
| CommandHistoryClean=*
```

## Credential Dumping Detection

Source file: `Credential_Dumping_Detection.yml`

```cql
#event_simpleName=ProcessRollup2
| (CommandLine=/mimikatz|procdump|lsass|sekurlsa/i OR ImageFileName=/\\(mimikatz|procdump|pwdump)\.exe$/i)
| ParentImageFileName!=/\\(powershell|cmd)\.exe$/i
| join({#event_simpleName=UserIdentity}, field=[aid, AuthenticationId], include=[UserName], mode=left)
| join({#event_simpleName=SyntheticProcessRollup2 | ParentSHA256HashData := SHA256HashData},
      field=[aid, ParentProcessId], key=[aid, TargetProcessId], include=[ParentSHA256HashData], mode=left)
| table([aid, UserName, ImageFileName, CommandLine, ParentImageFileName, SHA256HashData, ParentSHA256HashData])
```

## Detect Suspicious Windows Command-Line Activity Using System Utilities

Source file: `Detect_Suspicious_Windows_Command-Line_Activity_Using_System_Utilities.yml`

```cql
// Get all Windows ProcessRollup2 Events
#event_simpleName=ProcessRollup2 event_platform=Win
// Narrow to processes of interest and create FileName variable
| ImageFileName=/\\(?<FileName>(whoami|net1?|systeminfo|ping|nltest|sc|hostname|ipconfig)\.exe)/i
// Get timestamp value with date and hour value
| ProcessStartTime := ProcessStartTime*1000
| dayBucket := formatTime("%Y-%m-%d %H", field=ProcessStartTime, locale=en_US, timezone=Z)
// Force CommandLine and FileName into lower case
| CommandLine := lower(CommandLine)
| FileName := lower(FileName)
// Parse flag used in "net" command
| regex("(sc|net1?)\s+(?<netFlag>\S+)\s+", field=CommandLine, strict=false)
// Force netFlag to lower case
| netFlag := lower(netFlag)
// Create evaulation criteria and weighting for process usage; modified behaviorWeight integer as desired
| case {
       FileName=/net1?\.exe/ AND netFlag="start" | behaviorWeight := "4" ;
       FileName=/net1?\.exe/ AND netFlag="stop" | behaviorWeight := "4" ;
       FileName=/net1?\.exe/ AND netFlag="stop" AND CommandLine=/falcon/i | behaviorWeight := "25" ;
       FileName=/sc\.exe/ AND netFlag="start" | behaviorWeight := "4" ;
       FileName=/sc\.exe/ AND netFlag="stop" | behaviorWeight := "4" ;
       FileName=/sc\.exe/ AND netFlag=/(query|stop)/i AND CommandLine=/csagent/i | behaviorWeight := "25" ;
       FileName=/net1?\.exe/ AND netFlag="share" | behaviorWeight := "2" ;
       FileName=/net1?\.exe/ AND netFlag="user" AND CommandLine=/\/delete/i | behaviorWeight := "10" ;
       FileName=/net1?\.exe/ AND netFlag="user" AND CommandLine=/\/add/i | behaviorWeight := "10" ;
       FileName=/net1?\.exe/ AND netFlag="group" AND CommandLine=/\/domain\s+/i | behaviorWeight := "5" ;
       FileName=/net1?\.exe/ AND netFlag="group" AND CommandLine=/admin/i | behaviorWeight := "5" ;
       FileName=/net1?\.exe/ AND netFlag="localgroup" AND CommandLine=/\/add/i | behaviorWeight := "10" ;
       FileName=/net1?\.exe/ AND netFlag="localgroup" AND CommandLine=/\/delete/i | behaviorWeight := "10" ;
       FileName=/nltest\.exe/ | behaviorWeight := "3" ;
       FileName=/systeminfo\.exe/ | behaviorWeight := "3" ;
       FileName=/whoami\.exe/ | behaviorWeight := "3" ;
       FileName=/ping\.exe/ | behaviorWeight := "3" ;
       FileName=/hostname\.exe/ | behaviorWeight := "3" ;
       FileName=/ipconfig\.exe/ | behaviorWeight := "3" ;
 * }
| default(field=behaviorWeight, value=1)
// Create FileName and CommandLine one-liner
| format(format="(Score: %s) %s • %s", field=[behaviorWeight, FileName, CommandLine], as="executionDetails")
// Group and organize output
| groupby([cid,aid, dayBucket], function=[count(FileName, distinct=true, as="fileCount"), sum(behaviorWeight, as="behaviorWeight"), series(executionDetails)], limit=max)
// Set thresholds
| fileCount >= 5 OR behaviorWeight > 30
// Add Host Search link
| format("[Host Search](https://falcon.crowdstrike.com/investigate/events/en-us/app/eam2/investigate__computer?earliest=-24h&latest=now&computer=*&aid_tok=%s&customer_tok=*)", field=["aid"], as="Host Search")
// Sort descending by behavior weighting
| sort(behaviorWeight)
| drop([@timestamp, _duration])
```

## Detect and Decode Base64-Encoded PowerShell Commands - http

Source file: `Detect_and_Decode_Base64-Encoded_PowerShell_Commands-http.yml`

```cql
#event_simpleName=ProcessRollup2 event_platform=Win ImageFileName=/.*\\powershell\.exe/
| CommandLine=/.*\s+\-(e|encoded|encodedcommand|enc)\s+.*/
| length("CommandLine", as="cmdLength")
| groupby([CommandLine], function=stats([count(aid, distinct=true, as="uniqueEndpointCount"), count(aid, as="executionCount")]), limit=max)
| EncodedString := splitString(field=CommandLine, by="-e* ", index=1)
| CmdLinePrefix := splitString(field=CommandLine, by="-e* ", index=0)
| DecodedString := base64Decode(EncodedString, charset="UTF-16LE")
// Look for encoded messages in the decoded message and decode those too.
| case {
  DecodedString = /encoded/i
  | SubEncodedString := splitString(field=DecodedString, by="-EncodedCommand ", index=1)
  | SubCmdLinePrefix := splitString(field=EncodedString, by="-EncodedCommand ", index=0)
  | SubDecodedString := base64Decode(SubEncodedString, charset="UTF-16LE");
  *
}
| DecodedString=/.*https?\:\/\/.*/
| table([executionCount, uniqueEndpoitnCount, DecodedString, CommandLine])
| sort(executionCount, order=desc)
```

## Detect and Decode Base64-Encoded PowerShell Commands

Source file: `Detect_and_Decode_Base64-Encoded_PowerShell_Commands.yml`

```cql
#event_simpleName=ProcessRollup2 event_platform=Win ImageFileName=/.*\\powershell\.exe/
| CommandLine=/\s+\-(e|encoded|encodedcommand|enc)\s+/i
| CommandLine=/\-(?<psEncFlag>(e|encoded|encodedcommand|enc))\s+/i
| length("CommandLine", as="cmdLength")
| groupby([psEncFlag, cmdLength, CommandLine], function=stats([count(aid, distinct=true, as="uniqueEndpointCount"), count(aid, as="executionCount")]), limit=max)
| EncodedString := splitString(field=CommandLine, by="-e* ", index=1)
| CmdLinePrefix := splitString(field=CommandLine, by="-e* ", index=0)
| DecodedString := base64Decode(EncodedString, charset="UTF-16LE")
// Look for encoded messages in the decoded message and decode those too.
| case {
  DecodedString = /encoded/i
  | SubEncodedString := splitString(field=DecodedString, by="-EncodedCommand ", index=1)
  | SubCmdLinePrefix := splitString(field=EncodedString, by="-EncodedCommand ", index=0)
  | SubDecodedString := base64Decode(SubEncodedString, charset="UTF-16LE");
  *
}
| table([executionCount, uniqueEndpoitnCount, cmdLength, DecodedString, CommandLine])
| sort(executionCount, order=desc)
```

## Encoded PowerShell Command Execution

Source file: `Encoded_Powershell_Executions.yml`

```cql
#event_simpleName=ProcessRollup2 ImageFileName=/\\(powershell|pwsh)\.exe$/i
| replace("\\^", with="", field=CommandLine, as=cmd)
| cmd=/\s[-\/]e(c|nc?[a-z]*)?\s+(?<b64>[A-Za-z0-9+\/=]{16,})/i
| decoded := base64Decode(b64, charset="UTF-16LE")
| join({#event_simpleName=UserIdentity}, field=[aid, AuthenticationId], include=[UserName], mode=left)
| table([aid, UserName, ParentImageFileName, ImageFileName, CommandLine, decoded])
```

## Powershell Command Length Anomaly Detection

Source file: `Hunting_Powershell_Command_Length_Anomaly.yml`

```cql
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell(_ise)?|pwsh)\.exe/i
| CommandLength := length("CommandLine") | CommandLength>0
| aid=?AID
// Classify Data into Historical and LastDay
| case {
    test(@timestamp < (end() - duration(7d))) | DataSet:="Historical";
    test(@timestamp > (end() - duration(1d))) | DataSet:="LastDay";
    *
}
// Calculate Average Command Length
| groupBy([DataSet, aid], function=avg(CommandLength))
| case {
    DataSet="Historical" | rename(field="_avg", as="historicalAvg");
    DataSet="LastDay" | rename(field="_avg", as="todaysAvg");
    *
}
// Aggregate Averages
| groupBy([aid], function=[avg("historicalAvg", as=historicalAvg), avg("todaysAvg", as=todaysAvg)])
// Calculate Percentage Increase
| PercentIncrease := (todaysAvg - historicalAvg) / historicalAvg * 100
| format("%d", field=PercentIncrease, as=PercentIncrease)
| format(format="%.2f", field=[historicalAvg], as=historicalAvg)
// Filter and Sort Results
| PercentIncrease > 0
| sort(PercentIncrease, limit=10000)
```

## LOLBin Certutil

Source file: `LOLBin_Certutil.yml`

```cql
in(#event_simpleName, values=["ProcessRollup2","ProcessBlocked"])
| event_platform=Win and ImageFileName=/certutil.exe/i and CommandLine=/(https?:)/i
```

## LOLBin Mshta

Source file: `LOLBin_Mshta.yml`

```cql
in(#event_simpleName, values=["ProcessRollup2","ProcessBlocked"])
| event_platform=Win and ImageFileName=/mshta.exe/i
| CommandLine=/mshta(?:\.exe)?\"?\s+\"?(?<HtaPath>(?:.*?\.hta|(?=\").*?(?=\")|.*?(?=(?:\s|$))))/i
| HtaPath=/(?<HtaFolder>.*)(\\\\|\/)/i
| HtaPath=/(.*(\\\\|\/))?(?<HtaFile>.*)$/i
```

## LOLBin Msiexec

Source file: `LOLBin_Msiexec.yml`

```cql
in(#event_simpleName, values=["ProcessRollup2","ProcessBlocked"])
| event_platform=Win and ImageFileName=/msiexec.exe/i and CommandLine=/http/i
```

## LOLBin Regsvr32

Source file: `LOLBin_Regsvr32.yml`

```cql
in(#event_simpleName, values=["ProcessRollup2","ProcessBlocked"])
| event_platform=Win
| ImageFileName=/regsvr32.exe/i CommandLine=/scrobj.dll/i CommandLine=/i:/i
```

## LOLBin Rundll32

Source file: `LOLBin_Rundll32.yml`

```cql
in(#event_simpleName, values=["ProcessRollup2","ProcessBlocked"])
| event_platform=Win and ImageFileName=/rundll32.exe/i
| in(ParentBaseFileName, values=["cmd.exe","winword.exe","powerpnt.exe","excel.exe","outlook.exe","mshta.exe","cscript.exe","wscript.exe"])
```

## LOLBin WMIC

Source file: `LOLBin_WMIC.yml`

```cql
in(#event_simpleName, values=["ProcessRollup2","ProcessBlocked"])
| event_platform=Win and ImageFileName=/wmic.exe/i
```

## Powershell Downloads

Source file: `Powershell_Downloads.yml`

```cql
#event_simpleName=CommandHistory
| CommandHistory=/Invoke\-WebRequest|Net\.WebClient|Start\-BitsTransfer/i
| regex("(?<URL>https?://[^'\"]+)", field=CommandHistory)
| replace("https://", with="", field=URL, as=ShortURL)
| replace("\/.*", with="", field=ShortURL, as=otx_lookup)
| UrlBase:="https://otx.alienvault.com/indicator/domain/"
| format(format="[Alienvault](%s%s)", field=[UrlBase, otx_lookup], as=DomainLookup)
| table([DomainLookup, URL, ComputerName, UserName, CommandHistory], limit=20000)
```

## Rare windows shell parent process

Source file: `Rare_Windows_Shell_Parent.yml`

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| case { in(field=FileName, values=["powershell.exe", "cmd.exe", "pwsh.exe"]) | IsChild := "1"; * | IsChild := "0" }
| case { IsChild = "1" | ProcId := ParentProcessId | ChildProcess := FileName | ChildCommandLine := CommandLine;
IsChild = "0" | ProcId := TargetProcessId | ParentCommandLine := CommandLine | ParentFileName := FileName | ParentFilePath := FilePath | ParentSHA256HashData := SHA256HashData; }
| groupBy([ComputerName, ProcId], function=([count(ParentProcessId, distinct=true, as=EventCount), collect([ParentFileName, ParentSHA256HashData, ParentFilePath, ParentCommandLine, ChildProcess]), collect(ChildCommandLine, limit=4)]), limit=max)
| EventCount > 1
| groupBy([ParentSHA256HashData], function=([collect([aid, ParentFileName, ParentFilePath, ParentCommandLine, ChildProcess, ChildCommandLine]), count(ComputerName, as=HostCount)]))
| HostCount < 5
| sort([HostCount, ParentFileName], order=asc)
```

## Rundll32 Remote UNC DLL Ordinal Execution

Source file: `Rundll32_Remote_UNC_DLL_Ordinal_Execution.yml`

```cql
// OVERVIEW: Detects rundll32 loading a DLL from a remote UNC path and
// invoking an export by ordinal, a proxy-execution pattern used to run remote code.
// SOURCE HUNTPACK: EtherHiding ClickFix Hunt
// MITRE: T1218.011, T1105
// CONF: high | FP: low | COST: low
// REQUIRES: ProcessRollup2
// FALSE POSITIVES: Approved software deployment tooling using DLLs from network shares.
// TUNING: Exclude validated deployment shares, distribution hosts, and known command lines.
// LOOKBACK: 7d - set with the Falcon time picker.
#event_simpleName=ProcessRollup2
| FileName=/^rundll32(\.exe)?$/i
// UNC host, optionally with WebDAV @port / @SSL suffixes (\\host\ , \\host@80\ , \\host@SSL\)
| CommandLine=/\\\\[a-z0-9._\-]+(@[a-z0-9]+)*\\/i
| CommandLine=/,#[0-9]+/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
| sort(@timestamp, order=desc, limit=500)
```

## Rust Build Toolchain Spawning Interpreter or Downloader

Source file: `Rust_Build_Toolchain_Spawning_Interpreter_or_Downloader.yml`

```cql
// OVERVIEW: Detects Rust build tools spawning interpreters or download utilities,
// which may indicate malicious dependency or build-script execution.
// SOURCE HUNTPACK: Rust Build-Toolchain Supply-Chain Hunt
// MITRE: T1195.002, T1059
// CONF: medium | FP: medium | COST: low
// REQUIRES: ProcessRollup2, SyntheticProcessRollup2
// FALSE POSITIVES: Legitimate build scripts downloading dependencies or invoking shells.
// TUNING: Exclude approved CI wrappers, artifact mirrors, and known build scripts.
// LOOKBACK: 30d - set with the Falcon time picker.
#event_simpleName=/ProcessRollup2|SyntheticProcessRollup2/
| in(ParentBaseFileName, values=["cargo.exe","cargo","rustc.exe","rustc"], ignoreCase=true)
| in(FileName, values=["powershell.exe","pwsh.exe","wscript.exe","cscript.exe","cmd.exe","curl.exe","curl","wget","bash","sh"], ignoreCase=true)
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, ParentCommandLine])
| sort(@timestamp, order=desc, limit=500)
```

## ClickFix Run Dialog Command Detection

Source file: `clickfix_run_dialog_command_detection.yml`

```cql
// HUNT: ClickFix Run-dialog paste recorded in RunMRU (ACR Stealer initial access)
// MITRE: T1204, T1189, T1059.003
// CONF: high | FP: low | COST: low | REQUIRES: registry telemetry (RunMRU writes)
// FALSE POSITIVES: IT staff pasting legitimate remote-admin one-liners into Run
// TUNING: exclude your admin asset group / privileged accounts. Removing the second
//         RegStringValue filter widens this to every interpreter typed into Run (noisier hunt).
#event_simpleName=/^(RegGenericValueUpdate|AsepValueUpdate|RegSystemConfigValueUpdate)$/
| RegObjectName=/RunMRU/i
| RegStringValue=/(powershell|cmd|mshta|rundll32|conhost|curl|msiexec|certutil|bitsadmin|python)/i
| RegStringValue=/(http|\\\\|-enc|-e |hidden|iex|FromBase64|--headless)/i
| table([@timestamp, ComputerName, UserName, RegObjectName, RegValueName, RegStringValue, aid], limit=200)
```

## Count Windows Discovery Commands

Source file: `count_windows_discovery_commands.yml`

```cql
// Insert Discovery commands of interest here
event_platform=Win #event_simpleName=ProcessRollup2 FileName=/(whoami|ping|net1?|systeminfo|quser|ipconfig)/iF

// Restrict to non-system UserSid Values
| UserSid=S-1-5-21-*

// User case() to create discovery command counter
| case {
    FileName=/whoami/iF     | whoami:="1";
    FileName=/ping/iF       | ping:="1";
    FileName=/net1?/iF      | net:="1";
    FileName=/systeminfo/iF | systeminfo:="1";
    FileName=/quser/iF      | quser:="1";
    FileName=/ipconfig/iF   | ipconfig:="1";
}

// Aggregate results by duration used in time picker
| groupBy([UserName, UserSid], function=([sum(whoami, as=whoami), sum(ping, as=ping), sum(net, as=net), sum(systeminfo, as=systeminfo), sum(quser, as=quser), sum(ipconfig, as=ipconfig), selectLast([CommandLine])]), limit=max)

// Rename field for clarity
| rename(field="CommandLine", as="LastCommandRun")

// Get total number of discovery commands run per UserName/UserSid key pair
| totalDiscovery:=whoami+ping+net+systeminfo+quser+ipconfig

// Set threshold for commands runs (optional)
| totalDiscovery>5

// Reorder using table for easier reading
| table([UserName, UserSid, totalDiscovery, whoami, ping, net, systeminfo, quser, ipconfig, LastCommandRun])
```
