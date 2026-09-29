---
name: crowdstrike-cql-data-movement
description: "Use for CrowdStrike CQL investigations of files written to removable media, external-storage exfiltration, Outlook links, and Outlook attachments."
user-invocable: true
---

# Email and Data-Movement Hunting

Use these query bodies as starting points. Validate event names, fields, time scope, function support, and telemetry availability in the target tenant. These queries are investigative leads, not verdicts.

## Files Written to Removable Media

Source file: `Files_Written_to_Removable_Media.yml`

```cql
#event_simpleName=/Written/ IsOnRemovableDisk=1 
| FileSizeMB:=unit:convert(Size, to=M) 
| groupBy([ComputerName], function=([sum(Size, as=SizeBytes), sum(FileSizeMB, as=FileSizeMB), count(TargetFileName, as="File Count"), collect([TargetFileName])]))
```

## Detect Data Exfiltration via external storage devices

Source file: `data_exfiltration_external_storage.yml`

```cql
#event_simpleName=/FileWritten/i and IsOnRemovableDisk = 1
| VolumeSessionUUID=*
| "Size (MB)" := Size/1024/1024
| format(format="%.2f", field=["Size (MB)"], as="Size (MB)")
| join(query={#event_simpleName=DcUsbDeviceConnected | rename(DeviceInstanceId, as="DiskParentDeviceInstanceId")}, mode=left, field=[DiskParentDeviceInstanceId], include=[DeviceManufacturer, DeviceProduct])
| groupBy([ComputerName, UserName, DeviceManufacturer, DeviceProduct], function=[min(field=@timestamp, as=firstTime),max(field=@timestamp, as=lastTime),sum(Size, as="Size")])
| "Size (MB)" := Size/1024/1024
| format(format="%.2f", field=["Size (MB)"], as="Size (MB)")
```

## Phishing - List of links opened from Outlook

Source file: `Hunt_links_opened_from_Outlook.yml`

```cql
#event_simpleName=ProcessRollup2 
| aid=?aid ImageFileName=/\\outlook\.exe/i
| regex("(?<FileName>[^\\/|\\\\]*)$", field=ImageFileName, strict=false)
| join(
    {
      #event_simpleName=ProcessRollup2 ImageFileName=/(chrome|firefox|iexplore)\.exe/i
      | MD5:=MD5HashData | ImageFileName=/(\/|\\)(?<ChildFileName>\w*\.?\w*)$/ 
      | ChildCLI:=CommandLine
    }, 
    key=ParentProcessId, field=TargetProcessId, include=[MD5, ChildFileName, ChildCLI]
  ) 
| groupBy([aid, FileName, CommandLine, ChildFileName, ChildCLI, MD5], limit=max)
```

## List of attachments sent from Outlook

Source file: `attachments_send_by_outlook.yml`

```cql
#event_simpleName=ProcessRollup2
| CommandLine=/content.outlook/i
| aid=?aid
| ImageFileName=/(\/|\\)(?<FileName>\w*\.?\w*)$/
| FileName=/(winword|excel|powerpnt)\.exe/i
| CommandLine=/Outlook\\(?<ShortFile>\w*\\.*)$/i
| table([@timestamp, aid, TargetProcessId, ShortFile, CommandLine], limit=1000)
```

## Additional Query Patterns

The following CQL bodies are embedded directly for reuse. Validate event names, field availability, query-surface support, and telemetry in the target environment.
The SMB file-copy query uses Microsoft Defender for Identity data fields, not Falcon `#event_simpleName` events; use it only against a compatible dataset.

### High Volume SMB File Copy (Data Exfiltration / Ransomware) – Microsoft Defender for Identity

Source YAML: `high_volume_smb_file_copy_data_exfiltration_ransomware_microsoft_defender_for_identity.yml`

```cql
#Vendor = "microsoft"
| #event.module = "defender-identity"
| Vendor.category = "AdvancedHunting-IdentityDirectoryEvents"
| Vendor.properties.ActionType = "SMB file copy"
| groupBy([user.name, source.address], function=[count(as=file_copies),collect(fields=Vendor.properties.DestinationDeviceName),collect(fields=Vendor.properties.DeviceName),min(@timestamp, as=start_time),max(@timestamp, as=end_time)])
| file_copies > 50
| time_diff_min := (end_time - start_time) / 60000
| time_diff_min <= 10
| start_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=start_time, timezone="UTC")
| end_time_fmt := formatTime("%Y-%m-%d %H:%M:%S", field=end_time, timezone="UTC")
| drop([start_time, end_time])
| sort([file_copies], order=desc)
```
