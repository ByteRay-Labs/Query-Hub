---
name: crowdstrike-cql-host-integrity
description: "Use for CrowdStrike CQL investigations of DLL side-loading, vulnerable driver abuse, firewall changes, registry modifications, and locally disabled response tooling."
user-invocable: true
---

# Host Integrity and Configuration Hunting

Use these query bodies as starting points. Validate event names, fields, time scope, function support, and telemetry availability in the target tenant. These queries are investigative leads, not verdicts.

## Dll-Side Loading Detection Query

Source file: `Dll-Side_Loading_Detection_Query.yml`

```cql
//Tracing the ProcessId of a Process / File which is writting atleast 1 each EXE and DLL to same Path, Doing the Process Original name masquarading and atleast 1 File Author name is Microsoft in "DLL-Filewrite", tracking throughtout as SusProcessID
defineTable(query={#event_simpleName=/(PeFileWritten)/iF 
|lowercase("FileName")
|lowercase("OriginalFilename")
|(FileName="*" and OriginalFilename="*")
| regex("(?<DllFileName>^.*)\.dll", field=FileName, strict=false)
| regex("(?<EXEFileName>^.*)\.exe", field=FileName, strict=false)
| MasquraeCheck:=if(FileName==OriginalFilename, then="Normal", else="Masquarade") |MasquraeCheck!="Normal"
|SusProcessID:=format(format="%s%s", field=[aid,ContextProcessId])
|rename(field="SHA256HashData", as="SusHash")
|rename(field="FileName", as="FileWritten")
// Exclusions FOr Edge Browser
|OriginalFilename!=microsoftedgeupdate.exe OriginalFilename!=msedgeupdate.dll
|groupBy([SusProcessID,FilePath],function=([collect([DllFileName,EXEFileName,SusHash,FileWritten,OriginalFilename,CompanyName]),count(DllFileName,as=DllC),count(EXEFileName,as=EXEC)]),limit=max)
|DllC>=1 EXEC>=1 CompanyName=/Microsoft/iF 
}, include=[FilePath,FileWritten,OriginalFilename,SusHash,DllFileName,EXEFileName,CompanyName,SusProcessID,ComputerName,UserName], name="DLL-Filewrite")

// Then tracing the Parent File for files written operation in "DLL-Filewrite" getting FileWriteParent, tracked as "DLL-Parent"
|defineTable(query={#event_simpleName=/(ProcessRollup2)/iF  
|TargetProcessId:=format(format="%s%s", field=[aid,TargetProcessId])
|ParentProcessId:=format(format="%s%s", field=[aid,ParentProcessId])
|match(file="DLL-Filewrite", field=[TargetProcessId],column=[SusProcessID],strict=true,include=[FilePath,FileWritten,OriginalFilename,SusHash,CompanyName,SusProcessID,ComputerName,UserName])
|rename(field="ParentBaseFileName", as="FileWriteParent")
|case{
CommandLine=* |regex("\"[^\"]+\"\\s+\"(?P<FullPath>[^\"]*\\\\)?", field=CommandLine)| regex(".*\\\\(?<FileNamey>[^\\\\\"]+?)\"?$", field=CommandLine);
*
}
|case{
  FullPath="*" or FileNamey="*" | FileWriteFileSource:=format(format="%s\n\t└-> %s", field=[FileNamey,FullPath]);
  FullPath!="*" FileNamey!="*" | FileWriteFileSource:=format(format="%s", field=[FileName]);
  *
}
| coalesce([FileNamey,FileName],as=FileWriteFile,ignoreEmpty=false)
}, include=[FileWriteFile,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName], name="DLL-Parent")

// Then Tracing the DLL-side-Loading Process startup for "DLL-Parent", getting DLLSideLoadProcess, tracked as "DLLSideLoadProcess"
|defineTable(query={#event_simpleName=/(ProcessRollup2)/iF |DLLSideLoadProcess:=format(format="%s\n\t└-> %s", field=[ParentBaseFileName,FileName])
|TargetProcessId:=format(format="%s%s", field=[aid,TargetProcessId])
|ParentProcessId:=format(format="%s%s", field=[aid,ParentProcessId])
|match(file="DLL-Parent", field=[ParentProcessId],column=[SusProcessID],strict=true,include=[FileWriteFile,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName])
|rename(field="TargetProcessId", as="ModuleLoadId")
| rename(field="ProcessStartTime", as="ProcessStartTime")
}, include=[FileWriteFile,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,ModuleLoadId,SusProcessID,ComputerName,UserName], name="DLLSideLoadProcess")

// Then tracing the DLL/EXE side loaded for DLLSideLoadProcess from "DLLSideLoadProcess", tracked as "DllLoading"
|defineTable(query={#event_simpleName=/(ClassifiedModuleLoad)/iF |rename(field="FileName", as="DllLoad") 
|TargetProcessId:=format(format="%s%s", field=[aid,TargetProcessId])
|ParentProcessId:=format(format="%s%s", field=[aid,ParentProcessId])
|ContextProcessId:=format(format="%s%s", field=[aid,ContextProcessId])
| "DllLoaded Files":= format(format="%s\n\t└-> %s", field=[DllLoad,FilePath])
|match(file="DLLSideLoadProcess", field=[ContextProcessId],column=[ModuleLoadId],strict=true,include=[FileWriteFile,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName])
|rename(field="TargetProcessId", as="ModuleLoadId")

|case {
  ModuleLoadTelemetryClassification = 1
| ModuleLoadTelemetryClassification := "FIRST_LOAD\n\t\t└->This is the first time this module has been loaded into a process on the host";
  ModuleLoadTelemetryClassification = 2
| ModuleLoadTelemetryClassification := "RUNDLL32_TARGET\n\t\t└->This module is the target of a rundll32.exe invocation";
  ModuleLoadTelemetryClassification = 4
| ModuleLoadTelemetryClassification := "DETECT_TREE\n\t\t└->The module was loaded into a process that is in an active detect tree";
  ModuleLoadTelemetryClassification = 8
| ModuleLoadTelemetryClassification := "MAPPED_FROM_KERNEL_MODE\n\t\t└->The module was loaded into kernel mode address space";
  ModuleLoadTelemetryClassification = 16
| ModuleLoadTelemetryClassification := "UNUSUAL_EXTENSION\n\t\t└->The module has an unexpected, unusual or rare extension";
  ModuleLoadTelemetryClassification = 32
| ModuleLoadTelemetryClassification := "MOTW\n\t\t└->The module has the Mark of the Web zone identifier";
  ModuleLoadTelemetryClassification = 64
| ModuleLoadTelemetryClassification := "SIGN_INFO_CONTINUITY\n\t\t└->The module does not have a valid signature and it was loaded into a process with a primary module that does have a valid signature";
  ModuleLoadTelemetryClassification = 256
| ModuleLoadTelemetryClassification := "ORIGINAL_FILENAME_MISMATCH\n\t\t└->Module's ImageFileName doesn't match OriginalFileName";
  ModuleLoadTelemetryClassification = 512
| ModuleLoadTelemetryClassification := "REMOVABLE_MEDIA\n\t\t└->The module was loaded from removable media (ISO/IMG)";
  ModuleLoadTelemetryClassification = 1024
| ModuleLoadTelemetryClassification := "DATA_EXTENSION\n\t\t└->The module has a data type extension";
  ModuleLoadTelemetryClassification = 257
| ModuleLoadTelemetryClassification := "FIRST_LOAD_AND_FILENAME_MISMATCH\n\t\t└->This is the first time this module has been loaded into a process on the host and its ImageFileName doesnt match OriginalFileName";
  *
| ModuleLoadTelemetryClassification := format(format="Value=%s\n\t\t└->Multiple module load telemetry flags are set, Check ModuleLoadTelemetryClassification documentation", field=[ModuleLoadTelemetryClassification])
}

}, include=[FileWriteFile,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName], name="DllLoading")

//Performing the aggregation in the presentable format + to prepare for matchup for MOTW URLS in next table
|defineTable(query={readFile([DllLoading])
|groupBy([ProcessStartTime,SusProcessID,ComputerName,UserName],function=([collect([FileWriteFile,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,OriginalFilename,CompanyName,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,SusHash]),count("DllLoaded Files",distinct=true,as="DllLoaded Files Count")]),limit=max)},include=[ProcessStartTime,SusProcessID,ComputerName,FileWriteFile,UserName,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,OriginalFilename,CompanyName,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,SusHash,"DllLoaded Files Count"], name="Aggregation")

//Fetching MOTW URLS
|defineTable(query={#event_simpleName=MotwWritten 
|match(file="Aggregation", field=[ComputerName,FileName],column=[ComputerName,FileWriteFile],strict=true,ignoreCase=true, include=[FileWriteFile,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName,"DllLoaded Files Count"])
|case{
  HostUrl!="" ReferrerUrl="" |FileWriteFileSourceURL:=format(format="Download URL= %s", field=[HostUrl]);
  HostUrl="" ReferrerUrl!="" |FileWriteFileSourceURL:=format(format="Referrer URL= %s", field=[ReferrerUrl]);
  HostUrl!="" OR ReferrerUrl!="" |FileWriteFileSourceURL:=format(format="Download URL= %s\nReferrer URL= %s", field=[HostUrl,ReferrerUrl]);
  *
}
}, include=[FileWriteFile,FileWriteFileSourceURL,FileWriteFileSource,ProcessStartTime,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,FileWriteParent,FilePath,FileWritten,SusHash,OriginalFilename,CompanyName,SusProcessID,ComputerName,UserName,"DllLoaded Files Count"], name="MOTW")
|readFile(["Aggregation","MOTW"])
|case{
  FileWriteFileSourceURL!="*" |FileWriteFileSourceURL:=format(format="No URL Found", field=[]);
  * 
}
|groupBy([ProcessStartTime,SusProcessID,ComputerName,UserName],function=([collect([FileWriteFileSourceURL,FileWriteFileSource,FileWriteParent,FilePath,FileWritten,OriginalFilename,CompanyName,DLLSideLoadProcess,"DllLoaded Files",ModuleLoadTelemetryClassification,SusHash,"DllLoaded Files Count"])]))
| ProcessStartTime:=ProcessStartTime*1000 |ProcessStartTime := formatTime("%e %b %Y %r", field=ProcessStartTime, locale=en_UAE, timezone="Asia/Dubai")
| rename([[FilePath,FileWrittenPath],[CompanyName,"ExeAuthorCompanyName"],[ModuleLoadTelemetryClassification,"DllLoaded Files Signature"]])
|drop([SusProcessID])
```

## BYOVD Driver Load with EDR/AV Process Termination (Medusa Ransomware)

Source file: `byovd_driver_load_with_edr_av_process_termination_medusa_ransomware.yml`

```cql
/* Phase 1 — Detect BYOVD: known-vulnerable or out-of-place signed drivers */
#event_simpleName = DriverLoad OR #event_simpleName = ClassifiedModuleLoad
| case {
    in(field=FileName, values=[
      "gdrv.sys", "msio64.sys", "ntiolib.sys", "kprocesshacker.sys",
      "physmem.sys", "dbk64.sys", "procexp152.sys", "NSSM.sys",
      "wantd.sys", "AsrDrv104.sys", "mhyprot2.sys"
    ]) | BYOVDIndicator := "Known vulnerable driver loaded";
    FilePath = /AppData|Temp|ProgramData|Users\\.*\\Desktop/i
      FileName = /\.sys$/i
      | BYOVDIndicator := "Driver loaded from suspicious user-writable path";
    * | BYOVDIndicator := "none";
  }
| BYOVDIndicator != "none"
| join(
    {
      #event_simpleName = TerminateProcess
      | ImageFileName = /(MsMpEng|CsAgent|CsFalconService|csshell|SentinelAgent|cbdefense|MBAMService|avp\.exe|fmon|avgnt|bdservicehost|mcshield|ekrn)\.exe$/i
      | rename(field=ImageFileName, as=TerminatedSecurity)
    },
    field=aid, key=aid
  )
| TerminatedSecurity = *
```

## Firewall Rule Additions

Source file: `Firewall_Rule_Additions.yml`

```cql
#event_simpleName=ProcessRollup2
| join({#event_simpleName=FirewallSetRule}, key=ContextProcessId, field=TargetProcessId, include=[FirewallRule, FirewallRuleId])
| ImageFileName=/.*\\(?<fileName>.*\..*)/
| table([aid, UserSid, fileName, FirewallRuleId, FirewallRule, ImageFileName, CommandLine])
```

## Suspicious Registry Modifications

Source file: `Suspicious_Registry_Modifications.yml`

```cql
#event_simpleName=RegGenericValue 
| RegObjectName=/\\(Run|RunOnce|Winlogon|AppInit_DLLs|Image File Execution Options)/i
| RegValueName!=/^(ctfmon|SecurityHealth|OneDrive)$/i
| join({#event_simpleName=UserIdentity}, field=AuthenticationID, include=[UserName])
| table([aid, UserName, RegObjectName, RegValueName, RegStringValue, ProcessImageFileName])
```

## Detect locally disabled RTR

Source file: `detect_locally_disabled_rtr.yml`

```cql
#event_simpleName=SensorHeartbeat
| groupBy([aid], function=selectLast([@timestamp, ComputerName, SensorStateBitMap]), limit=max)
| bitfield:extractFlags(
field=SensorStateBitMap,
 output=[
   [2, RTR_Locally_Disabled]
])
| RTR_Locally_Disabled="true"
```

## Additional Query Patterns

The following CQL bodies are embedded directly for reuse. Validate event names, field availability, query-surface support, and telemetry in the target environment.

### EDRCHOKER - QoS Policy Abuse Targeting EDR/AV Processes

Source YAML: `edrchoker_qos_policy_abuse_targeting_edr_av_processes.yml`

```cql
// // EDRCHOKER - QoS Policy abuse targeting EDR/AV processes (T1562 – Impair Defenses)
// // https://www.zerosalarium.com/2026/06/edrchoker-choking-telemetry-stream-block-edr.html
// Author: Aamir Muhammad
|case{
#event_simpleName=/ProcessRollup2|WmiCreateProcess/iF
CommandLine=/New-NetQosPolicy|Set-NetQosPolicy/iF
CommandLine=/ThrottleRateActionBitsPerSecond|AppPathNameMatchCondition/iF 
CommandLine=/(SenseIR\.exe|MsSense\.exe|MsMpEng\.exe|WinDefend\.exe|falcon-sensor\.exe|CSFalconService\.exe|SentinelService\.exe|SentinelAgent\.exe|CortexXDR\.exe|cyvera\.exe|pmsu\.exe|cb\.exe|carbonblack\.exe|edragent\.exe|HarfangLab\.exe|elastic-agent\.exe)/iF
| SuspectActivity := format( "QoS Policy Creation via Process Command Line: %s", field=[#event_simpleNam]);
#event_simpleName=/RegGenericValueUpdate|AsepValueUpdate|RegSystemConfigValueUpdate|RegistryHiveFileWritten|reg/iF
RegObjectName=/\\SOFTWARE\\Policies\\Microsoft\\Windows\\QOS/i
RegStringValue=/(SenseIR\.exe|MsSense\.exe|MsMpEng\.exe|WinDefend\.exe|falcon-sensor\.exe|CSFalconService\.exe|SentinelService\.exe|SentinelAgent\.exe|CortexXDR\.exe|cyvera\.exe|pmsu\.exe|cb\.exe|carbonblack\.exe|edragent\.exe|HarfangLab\.exe|elastic-agent\.exe)/i
| SuspectActivity := format("QoS Registry Manipulation targeting: %s", field=[RegStringValue])
}
|groupBy([@timestamp,ComputerName,FileName,ParentBaseFileName,CommandLine,#event_simpleName])
```

### Hunting EDR Freeze

Source YAML: `hunting_edr_freeze.yml`

```cql
// Look for process handles opening Falcon
#event_simpleName=FalconProcessHandleOpDetectInfo FileName="WerFaultSecure.exe"

// Check for command line switching signal
| GrandparentCommandLine=/\.exe"?\s+\d+\s+\d+$/ OR ParentCommandLine=/\.exe"?\s+\d+\s+\d+$/ OR CommandLine=/\.exe"?\s+\d+\s+\d+$/

// Create process lineage tree for easier reading
| ProcessLineage:=format(format="%s (%s)\n   └ %s (%s)\n      └ %s (%s)", field=[GrandparentImageFileName, GrandparentCommandLine, ParentImageFileName, ParentCommandLine, ImageFileName, CommandLine])

// Output deatils to table
| table([@timestamp, aid, ComputerName, ContextProcessId, ProcessLineage])

// Create direct link to Process Explorer - Uncomment the rootURL value that matches your cloud
| rootURL  := "https://falcon.crowdstrike.com/" /* US-1 */
//| rootURL  := "https://falcon.us-2.crowdstrike.com/" /* US-2 */
//| rootURL  := "https://falcon.laggar.gcw.crowdstrike.com/" /* Gov */
//| rootURL  := "https://falcon.eu-1.crowdstrike.com/"  /* EU */
| format("[Responsible Process](%sgraphs/process-explorer/tree?id=pid:%s:%s)", field=["rootURL", "aid", "ContextProcessId"], as="Process Explorer") 

// Remove unnecessary fields
| drop([rootURL, ContextProcessId])
```

### IOC search | PTC Windchill & FlexPLM vulnerability

Source YAML: `ioc_search_ptc_windchill_flexplm_vulnerability.yml`

```cql
case{
  #event_simpleName = /.*FileWritten/i
  | FileName = /GW\.class/i or FileName = /Gen\.class/i or FileName = /dpr_.*\.jsp/i;
  #event_simpleName = /.*FileWritten/i
  | in(field="FileName",values=["Gen.java","GW.java","HTTPRequest.java","HTTPResponse.java","IXBCommonStreamer.java","IXBStreamer.java","MethodFeedback.java","MethodResult.java","WTContextUpdate.java"]);
}
| table(@timestamp,ComputerName,FileName,ContextBaseFileName)
```

### Packed Binary Detected

Source YAML: `packed_binary_detected.yml`

```cql
| #Vendor = crowdstrike
| #repo = "base_sensor"
| "#event_simpleName" = "PackedExecutableWritten"
| aid = ?aid
//| ComputerName ="XXXX" //Put your hostname here to check it for specfic host.

| case {
    wildcard(field=FilePath, pattern="*\\Temp\\*")         | location_risk := "High - Temp Directory" ;
    wildcard(field=FilePath, pattern="*\\AppData\\*")      | location_risk := "High - AppData" ;
    wildcard(field=FilePath, pattern="*\\Windows\\*")      | location_risk := "Critical - Windows Directory" ;
    wildcard(field=FilePath, pattern="*\\System32\\*")     | location_risk := "Critical - System32" ;
    wildcard(field=FilePath, pattern="*\\Startup\\*")      | location_risk := "Critical - Startup Folder" ;
    wildcard(field=FilePath, pattern="*\\Downloads\\*")    | location_risk := "Medium - Downloads" ;
    *                                                       | location_risk := "Low - Standard Path"
  }

| groupBy([ComputerName], function=[collect(FileName),collect(FilePath),collect(TargetFileName),collect(SHA256HashData),collect(location_risk),count(as=total_packed_writes)])
| sort(total_packed_writes, order=desc)
```

### Ransomware Precursors

Source YAML: `ransomware_precursors.yml`

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
// Optional scoping for testing on a single host
| ComputerName=?ComputerName
// Normalise the command line once for all subsequent matching
| CmdLower := lower("CommandLine")
// --- Recovery-inhibition classification ---------------------------------
| case {
    // Shadow copy deletion via vssadmin
    ImageFileName=/\\vssadmin\.exe$/i
      AND CmdLower=/delete\s+shadows/
      | Hypothesis := "H1_VSSADMIN_SHADOW_DELETE" | Confidence := "High";

    // Shadow storage resize to force silent shadow deletion (401 KB trick)
    ImageFileName=/\\vssadmin\.exe$/i
      AND CmdLower=/resize\s+shadowstorage/
      | Hypothesis := "H2_VSSADMIN_SHADOWSTORAGE_RESIZE" | Confidence := "Medium";

    // Shadow copy deletion via WMIC
    ImageFileName=/\\wmic\.exe$/i
      AND CmdLower=/shadowcopy/ AND CmdLower=/delete/
      | Hypothesis := "H3_WMIC_SHADOW_DELETE" | Confidence := "High";

    // Shadow copy deletion via PowerShell WMI/CIM
    ImageFileName=/\\(powershell|powershell_ise|pwsh)\.exe$/i
      AND CmdLower=/win32_shadowcopy|get-wmiobject.{0,40}shadowcopy|get-ciminstance.{0,40}shadowcopy/
      AND CmdLower=/delete|remove/
      | Hypothesis := "H4_POWERSHELL_SHADOW_DELETE" | Confidence := "High";

    // Backup catalog / system state backup destruction
    ImageFileName=/\\wbadmin\.exe$/i
      AND CmdLower=/delete\s+(catalog|systemstatebackup|backup)/
      | Hypothesis := "H5_WBADMIN_BACKUP_DELETE" | Confidence := "High";

    // Disable Windows Recovery Environment / automatic repair
    ImageFileName=/\\bcdedit\.exe$/i
      AND CmdLower=/recoveryenabled\s+(no|off)|bootstatuspolicy\s+ignoreallfailures/
      | Hypothesis := "H6_BCDEDIT_RECOVERY_TAMPER" | Confidence := "High";

    // USN change journal deletion (anti-forensics, common in ransomware playbooks)
    ImageFileName=/\\fsutil\.exe$/i
      AND CmdLower=/usn\s+deletejournal/
      | Hypothesis := "H7_FSUTIL_USN_DELETE" | Confidence := "Medium";

    * | Hypothesis := "NO_MATCH";
}
| Hypothesis != "NO_MATCH"
// --- Output --------------------------------------------------------------
| groupBy([aid, ComputerName], function=[
    count(as=PrecursorEvents),
    count(Hypothesis, distinct=true, as=DistinctTechniques),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen),
    collect([Hypothesis, Confidence, UserName, ImageFileName, CommandLine, ParentBaseFileName])
  ], limit=10000)
// Multiple distinct recovery-inhibition techniques on one host is near-certain ransomware staging
| case {
    DistinctTechniques >= 2 | Priority := "CRITICAL - multiple recovery-inhibition techniques";
    PrecursorEvents >= 3    | Priority := "HIGH - repeated recovery-inhibition activity";
    *                       | Priority := "MEDIUM - single event, validate context";
}
| FirstSeen := formatTime("%F %T %Z", field=FirstSeen)
| LastSeen := formatTime("%F %T %Z", field=LastSeen)
| sort(DistinctTechniques, order=desc)
```

### Recent RTR Sessions

Source YAML: `recent_rtr_sessions.yml`

```cql
// Get RTR Start events
#repo=detections #event_simpleName=Event_RemoteResponseSessionStartEvent

// Rename Agent ID value
| rename(field="AgentIdString", as="aid")

// Display results in table
| table([StartTimestamp, UserName, aid], limit=20000)

// Bring in data from AID Master lookup file
| aid=~match(file="aid_master_main.csv", column=[aid], strict=false)

// Convert timestamp to human-readable value
| formatTime(format="%F %T %Z", as=StartTimestamp, field=StartTimestamp)
```

### Suspicious DLL / Module loads

Source YAML: `suspicious_dll_module_loads.yml`

```cql
| #Vendor = crowdstrike
| #repo = "base_sensor"
| "#event_simpleName" = "ModuleLoadV3DetectInfo"
| aid=?aid
//| ComputerName="XXXXX"//Enter computer name to check for specific endpoint
| groupBy([ComputerName,aid], function=[collect(FileName),collect(FilePath),collect(ImageFileName),collect(ParentCommandLine),count(as=total_module_loads)])
| sort(total_module_loads, order=desc)
```
