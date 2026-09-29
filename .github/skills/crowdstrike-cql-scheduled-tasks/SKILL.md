---
name: crowdstrike-cql-scheduled-tasks
description: "Use for CrowdStrike CQL queries on scheduled task registration, hidden tasks, task triggers, principals, run levels, startup events, and time-based persistence."
user-invocable: true
---

# Scheduled Tasks and Startup Persistence

Use these complete CQL bodies as starting points. Validate event names, field availability, functions, and telemetry against the target tenant. Queries are investigative leads, not verdicts.

### Find events triggered on an event

Source YAML: `events_triggered_by_event.yml`

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Trigger:=rename(Task.Triggers.EventTrigger.Enabled)
| Trigger=* // Remove this line if you don't care if it's empty
| table([aid, Trigger, TaskXml], limit=1000)
```

### Find hidden scheduled tasks

Source YAML: `hidden_scheduled_tasks.yml`

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Hidden:=rename(Task.Settings.Hidden)
| Hidden=/true/i
| table([aid,Hidden,TaskXml],limit=1000)
```

### Find events that are scheduled

Source YAML: `scheduled_events.yml`

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Trigger:=rename(Task.Triggers.CalendarTrigger.Enabled)
| Trigger=* // Remove this line if you don't care if it's empty
| table([aid, Trigger, TaskXml], limit=1000)
```

### Find events triggered at startup

Source YAML: `startup_events.yml`

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Trigger:=rename(Task.Triggers.BootTrigger.Enabled)
| Trigger=* // Remove this line if you don't care if it's empty
| table([aid, Trigger, TaskXml], limit=1000)
```

### Suspicious Scheduled Task Creation

Source YAML: `suspicious_scheduled_task_creation.yml`

```cql
#event_simpleName=ScheduledTaskRegistered event_platform=Win

// Optional scoping for testing on a single host (leave as * for fleet-wide)
| ComputerName=?ComputerName

// Exclude the built-in Windows task namespace (Defender scan, Update, etc.)
| TaskName!=/^\\?Microsoft\\Windows\\/i

// To suppress recurring known-good automation after baselining, add an
// explicit author filter here, e.g.:  | TaskAuthor!=/sccm-svc|rmm-deploy/i

// Normalise the action fields into one searchable string
| TaskCmd := lower("TaskExecCommand")
| TaskArgs := lower("TaskExecArguments")
| CmdLine := format("%s %s", field=[TaskCmd, TaskArgs])

// --- Suspicion classification -------------------------------------------
| case {
    // Encoded PowerShell REQUIRES a second signal (download/exec intent),
    // because benign monitoring/management tooling uses -encodedCommand.
    CmdLine=/(powershell|pwsh)/i
      AND CmdLine=/(-enc|-encodedcommand|-e\s)/i
      AND CmdLine=/(downloadstring|downloadfile|iex|invoke-expression|frombase64string|net\.webclient|-w\s+hidden|-windowstyle\s+hidden)/i
      | Reason := "Encoded PowerShell w/ download or exec intent" ;

    // Common LOLBins used to proxy execution
    CmdLine=/\\(mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|installutil)\.exe/i
      | Reason := "LOLBin proxy execution" ;

    // Genuinely user-writable locations (ProgramData deliberately excluded)
    CmdLine=/(\\appdata\\|\\users\\public\\|\\temp\\|\\windows\\temp\\|%temp%|%appdata%)/i
      | Reason := "Payload in user-writable/temp path" ;

    // HTTP(S)/FTP URL embedded directly in the task action
    CmdLine=/(http:\/\/|https:\/\/|ftp:\/\/)/i
      | Reason := "Web URL in task action" ;

    // cmd one-liners chaining commands
    CmdLine=/cmd(\.exe)?\s+\/c.*(&&|\|)/i
      | Reason := "Chained cmd one-liner" ;

    * | Reason := "no-match" ;
}
| Reason != "no-match"

// --- Remote creation flag (lateral movement) ----------------------------
| case {
    RemoteAddressIP4=* AND RemoteAddressIP4!="0.0.0.0" | Origin := format("REMOTE (%s)", field=[RemoteAddressIP4]) ;
    RemoteAddressIP6=*                                 | Origin := format("REMOTE (%s)", field=[RemoteAddressIP6]) ;
    *                                                  | Origin := "local" ;
}

// --- Output --------------------------------------------------------------
| groupBy(
    [ComputerName, UserName, TaskAuthor, TaskName, Reason, Origin, TaskExecCommand, TaskExecArguments],
    function=[count(as=Count), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)],
    limit=max
)
| FirstSeen := formatTime("%F %T %Z", field=FirstSeen)
| LastSeen  := formatTime("%F %T %Z", field=LastSeen)
| sort(LastSeen, order=desc)
| table([LastSeen, ComputerName, UserName, TaskAuthor, Origin, Reason, TaskName, TaskExecCommand, TaskExecArguments, Count, FirstSeen], limit=10000)
```

### Find tasks scheduled by logon type

Source YAML: `task_scheduled_by_logon_type.yml`

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| LogonType:=rename(Task.Principals.Principal.LogonType)
| LogonType=* // Remove this line if you don't care if it's empty
| table([aid, LogonType, TaskXml], limit=1000)
```

### Find tasks scheduled by run level

Source YAML: `tasks_scheduled_by_run_level.yml`

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| RunLevel:=rename(Task.Principals.Principal.RunLevel)
| RunLevel=* // Remove this line if you don't care if it's empty
| table([aid, RunLevel, TaskXml], limit=1000)
```

### Find tasks scheduled by user ID

Source YAML: `tasks_scheduled_by_user_ID.yml`

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| UserId:=rename(Task.Principals.Principal.UserId)
| table([aid, UserId, TaskXml], limit=1000)
```

### Find tasks scheduled with ComHandler

Source YAML: `tasks_scheduled_with_ComHandler.yml`

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| ComHandlerData:=rename(Task.Actions.ComHandler.Data)
| ComHandlerData=* // Remove this line if you don't care if it's empty
| table([aid, ComHandlerData, TaskXml], limit=1000)
```

### Find events triggered at a specific time

Source YAML: `time_events.yml`

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Trigger:=rename(Task.Triggers.TimeTrigger.Enabled)
| Trigger=* // Remove this line if you don't care if it's empty
| table([aid, Trigger, TaskXml], limit=1000)
```
