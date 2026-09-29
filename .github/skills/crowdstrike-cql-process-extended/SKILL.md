---
name: crowdstrike-cql-process-extended
description: "Use for additional CrowdStrike CQL process hunts covering file names, command lines, Bitsadmin, macOS InstallFix, JAR files, npm packages, host-specific prevalence, and runtime interpreters."
user-invocable: true
---

# Process Hunting: Additional Patterns

Use these complete CQL bodies as starting points. Validate event names, field availability, functions, and telemetry against the target tenant. Queries are investigative leads, not verdicts.

### Hunt for specific Command Line Activity

Source YAML: `hunt_command_line.yml`

```cql
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2
| aid=?aid
| CommandLine like ?CommandLine
| ImageFileName=/(\/|\\)(?<FileName>\w*\.?\w*)$/
| table([aid, FileName, ImageFileName, CommandLine], limit=1000)
```

### Hunt for a file name

Source YAML: `hunt_filename.yml`

```cql
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2
| aid=?aid
| ImageFileName like ?ImageFileName
| ImageFileName=/(\/|\\)(?<FileName>\w*\.?\w*)$/
| table([aid, FileName, ImageFileName, CommandLine], limit=1000)
```

### Hunting Bitsadmin usage

Source YAML: `hunting_bitsadmin_usage.yml`

```cql
| case {
    #event_simpleName=ProcessRollup2
    AND (ImageFileName=/\\bitsadmin\.exe$/i OR OriginalFilename="bitsadmin.exe")
    AND (
        CommandLine=/\/transfer/i
        OR CommandLine=/\/addfile/i
        OR CommandLine=/\/download/i
        OR CommandLine=/\/SetNotifyCmdLine/i
        OR CommandLine=/\/resume/i
        OR CommandLine=/https?:\/\//i
        OR CommandLine=/ftp:\/\//i
    )
    AND NOT (
        ParentBaseFileName=svchost.exe
        OR ParentBaseFileName=msiexec.exe
    )
    | hunt_hypothesis := "H1_BITSADMIN_DIRECT_EXEC" ;
    #event_simpleName=ScriptControlScanV2 OR #event_simpleName=CommandHistory
    AND (
        ScriptContent=/Start-BitsTransfer/i
        OR ScriptContent=/Import-Module\s+BitsTransfer/i
        OR ScriptContent=/BITS\.IBackgroundCopyManager/i
    )
    AND (
        ScriptContent=/https?:\/\//i
        OR ScriptContent=/\-Source/i
        OR ScriptContent=/\-Destination/i
    )
    | hunt_hypothesis := "H2_POWERSHELL_BITSTRANSFER" ;
    #event_simpleName=ProcessRollup2
    AND (
        CommandLine=/SetNotifyCmdLine/i
        OR CommandLine=/SetMinRetryDelay/i
        OR CommandLine=/SetNoProgressTimeout/i
    )
    AND NOT CommandLine=/Windows.Update/i
    | hunt_hypothesis := "H3_BITS_PERSISTENCE" ;
    #event_simpleName=ProcessRollup2
    AND ImageFileName=/\\bitsadmin\.exe$/i
    AND CommandLine=/getieproxy/i
    | hunt_hypothesis := "H4_BITS_PROXY_RECON" ;
    * | hunt_hypothesis := "NO_MATCH" ;
}
// Exclure les non-matchs
| hunt_hypothesis != "NO_MATCH"
| select([
    @timestamp,
    hunt_hypothesis,
    ComputerName,
    UserName,
    UserSid,
    ImageFileName,
    CommandLine,
    ParentBaseFileName,
    ParentCommandLine,
    ScriptContent,
    SHA256HashData
])
| sort(@timestamp, order=desc)
```

### InstallFix on macOS

Source YAML: `installfix_on_macos.yml`

```cql
#repo="base_sensor"
| #event_simpleName="ProcessRollup2"
| event_platform="Mac"
| correlate(
  Base64Decode: {
    #event_simpleName="ProcessRollup2"
    | CommandLine=/(?i)base64\s+-(d|D)/
  } include:[aid],

  SuspiciousCurl: {
    #event_simpleName="ProcessRollup2"
    | CommandLine=/(?i)curl\s+.*https?:\/\//
    | CommandLine=/(?i)curl\s+-[a-z]*[ksfls]{4,}/
    | rootURL := "https://falcon.us-2.crowdstrike.com/"
    | format("[Tree](%sgraphs/process-explorer/tree?id=pid:%s:%s)", field=["rootURL", "aid", "TargetProcessId"], as="URL")
  } include:[ComputerName, UserName, aid, CommandLine, URL],
  within=1m,
  sequence=true,
  globalConstraints=[aid],
  includeMatchesOnceOnly=true
)
| ComputerName            := SuspiciousCurl.ComputerName
| aid           := SuspiciousCurl.aid
| @timestamp         := SuspiciousCurl.@timestamp
| Tree           := SuspiciousCurl.URL
| UserName            := SuspiciousCurl.UserName
| Curl_CMD := SuspiciousCurl.CommandLine
| table([@timestamp, UserName, ComputerName, aid, Tree, Curl_CMD])
```

### JAR files executed from %AppData%

Source YAML: `jar_file_executed_from_appdata.yml`

```cql
#event_simpleName=ProcessRollup2 
| ImageFileName=/javaw.exe/i CommandLine=/appdata/i
| table([aid, @timestamp, #event_simpleName, ImageFileName, SHA256HashData], limit=1000)
```

### JAR files written to %AppData%

Source YAML: `jar_file_written_to_appdata.yaml`

```cql
#event_simpleName=JarFileWritten 
| TargetFileName=/\\AppData\\/i
| table([aid, @timestamp, TargetFileName, SHA256HashData], limit=1000)
```

### NPM Package Named Searches

Source YAML: `npm_package_named_searches.yml`

```cql
//Single package check
#event_simpleName=/written/i TargetFileName=*jscrambler@*
| groupBy([@timestamp, event_platform, #event_simpleName, ComputerName, TargetFileName, ParentBaseFileName, GrandParentBaseFileName, CommandLine])

//For multiple packages with versions
#event_simpleName=/written/i (TargetFileName=/chalk-5\.6\.1/i) OR (TargetFileName=/supports-hyperlinks-4\.1\.1/i) OR (TargetFileName=/chalk-template-1\.1\.1/i) OR (TargetFileName=/slice-ansi-7\.1\.1/i) OR (TargetFileName=/wrap-ansi-9\.0\.1/i) OR (TargetFileName=/has-ansi-6\.0\.1/i) OR (TargetFileName=/strip-ansi-7\.1\.1/i) OR (TargetFileName=/ansi-styles-6\.2\.2/i) OR (TargetFileName=/supports-color-10\.2\.1/i) OR (TargetFileName=/ansi-regex-6\.2\.1/i) OR (TargetFileName=/debug-4\.4\.2/i) OR (TargetFileName=/color-convert-3\.1\.1/i) OR (TargetFileName=/color-name-2\.0\.1/i) OR (TargetFileName=/is-arrayish-0\.3\.3/i) OR (TargetFileName=/color-5\.0\.1/i) OR (TargetFileName=/color-string-2\.1\.1/i) OR (TargetFileName=/simple-swizzle-0\.2\.3/i) OR (TargetFileName=/backslash-0\.2\.1/i)
| groupBy([@timestamp, event_platform, #event_simpleName, ComputerName, TargetFileName, ParentBaseFileName, GrandParentBaseFileName, CommandLine])
```

### Find processes that only ran a few of times on a specific host

Source YAML: `processes_specific_host.yml`

```cql
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2
| aid=?aid
| groupBy([SHA256HashData, ImageFileName], limit=max)
| _count <5
| sort(_count, limit=1000)
```

### Shadow MCP Server Activity via Common Runtime Interpreters

Source YAML: `shadow_mcp_server_activity_via_common_runtime_interpreters.yml`

```cql
#event_simpleName=ProcessRollup2
| FileName = /(?i)^(node|node\.exe|npx|npx\.cmd|python|python\.exe|python3|uv|uvx|docker|docker\.exe)$/
| CommandLine = /(?i)(server-filesystem|server-github|server-postgres|server-sqlite|server-puppeteer|server-brave|modelcontext|mcp)/
| groupBy([aid, ComputerName, UserName, FileName, CommandLine], function=[
    count(as=Executions),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ])
| sort(LastSeen, order=desc)
```
