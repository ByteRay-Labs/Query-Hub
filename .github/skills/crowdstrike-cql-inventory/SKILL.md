---
name: crowdstrike-cql-inventory
description: "Use for CrowdStrike CQL endpoint inventory, operating-system prevalence, browser extensions, driver, boot-time, and software clustering queries."
user-invocable: true
---

# Endpoint Inventory and Prevalence

Use these query bodies as starting points. Validate event names, fields, time scope, function support, and telemetry availability in the target tenant. These queries are investigative leads, not verdicts.

## Evaluate Operating System Prevalence

Source file: `Evaluate_Operating_System_Prevalence.yml`

```cql
#event_simpleName=OsVersionInfo event_platform=Win
| groupby(aid, function=selectLast([ProductName]))
| groupBy([ProductName], function=stats([count(aid, as="endpointCount")]))
```

## Enumerate Windows Driver Loads

Source file: `Enumerate_Windows_Driver_Loads.yml`

```cql
// Get all DriverLoad events and Event_ModuleSummaryInfoEvent events so certificate data can be merged in
(#event_simpleName=DriverLoad event_platform=Win) OR (#repo=detections ExternalApiType=Event_ModuleSummaryInfoEvent )
// Shorten file path from DriverLoad event
| case{
    #event_simpleName=DriverLoad | FilePath=/Device\\HarddiskVolume\d+(?<ShortFileParth>.+$)/;
    *;
}
// Create selfJoinFilter
| selfJoinFilter(field=[SHA256HashData], where=[{#event_simpleName=DriverLoad}, {#repo=detections ExternalApiType=Event_ModuleSummaryInfoEvent}])
// Aggregate
| groupBy([SHA256HashData], function=([collect([ShortFileParth, FileName, OriginalFilename, SubjectCN, IssuerCN])]), limit=max)
| FileName=*
// Set default values
| default(value="-", field=[SubjectCN, IssuerCN, OriginalFilename])
```

## Frequency Analysis via Program Clustering

Source file: `Frequency_Analysis_via_Program_Clustering.yml`

```cql
// Get file names of interest
event_platform=Win #event_simpleName=ProcessRollup2 FileName=/(whoami|arp|cmd|net|net1|ipconfig|route|netstat|nslookup|nltest|systeminfo|wmic|tasklist|tracert|ping|adfind|nbtstat|find|ldifde|netsh|wbadmin)\.exe/i

// Aggregate in 10 minute buckets; set search to 24 hours
| bucket(span=10min, field=[cid, aid, ComputerName,ParentBaseFileName,ParentProcessId], function=[count(FileName, distinct=true, as=fNameCount), collect([FileName, CommandLine])], limit=500)

// Set threshold at three distinct file name values
| test(fNameCount>=3)
```

## Inventory of Installed Browser Extensions Across Endpoints

Source file: `Installed_Browser_Extensions_Across_Endpoints.yml`

```cql
#event_simpleName=InstalledBrowserExtension BrowserExtensionId!="no-extension-available"
| groupBy([event_platform, BrowserName, BrowserExtensionId, BrowserExtensionName], function=([count(aid, distinct=true, as=TotalEndpoints)]))
| format("[See Extension](https://chromewebstore.google.com/detail/%s)", field=[BrowserExtensionId], as="Chrome Store Link")
| sort(order=desc, TotalEndpoints, limit=1000)
| case{
    BrowserName="3" | BrowserName:="Chrome";
    BrowserName="4" | BrowserName:="Edge";
    *;
}
```

## Malicious Chrome Extension FreeVPN-One Detection

Source file: `Malicious_Chrome_Extension_FreeVPN-One_Detection.yml`

```cql
defineTable(query={#event_simpleName=InstalledBrowserExtension
|case{
    BrowserExtensionId=/jcbiifklmgnkppebelchllpdbnibihel/iF;
    BrowserExtensionName=/FreeVPN/iF
}
| case{ 
    "BrowserExtensionStatusEnabled"="0" | BrowserExtensionStatusEnabled:="Disabled";
    "BrowserExtensionStatusEnabled"="1" | BrowserExtensionStatusEnabled:="Enabled";
    *;
}
| BrowserExtensionInstalledTimestamp := BrowserExtensionInstalledTimestamp * 1000
| "Extension Installation date" := formatTime("%d-%m-%Y %H:%M:%S.%L", field=BrowserExtensionInstalledTimestamp, locale=en_UAE, timezone="Asia/Dubai")
| "Extension(s)":=format(format="Status=%s, Installation Date=%s", field=[BrowserExtensionStatusEnabled,"Extension Installation date"])
| groupBy([event_platform, aid, UserName, BrowserProfileId, BrowserName,BrowserExtensionName], function=([collect([ComputerName,"Extension(s)",BrowserExtensionPath,BrowserExtensionRequestedPermissions])]))
| drop([_count,aid])
| case{ 
    BrowserName ="0" | BrowserName := "UNKNOWN" ;
    BrowserName="1" | BrowserName:="Firefox";
    BrowserName="2" | BrowserName:="Safari";
    BrowserName="3" | BrowserName:="Chrome";
    BrowserName="4" | BrowserName:="Edge";
    BrowserName="5" | BrowserName:="EDGE CHROMIUM";
    BrowserName="6" | BrowserName:="Internet Explorer";
    BrowserName="7" | BrowserName:="Edge Legacy";
    BrowserName="8" | BrowserName:="IE_TYPED_URL";
    BrowserName="9" | BrowserName:="FIREFOX_APP";
    *;
}}, include=[*], name="Extension")
|defineTable(query={#event_simpleName=DnsRequest | in(field="DomainName", values=["aitd.one","extrahefty.com","scan.aitd.one","freevpn.one"],ignoreCase=true)}, include=[*], name="ExtensionTraffic")
|readFile(["Extension","ExtensionTraffic"])
|groupBy([ComputerName,DomainName], function=([collect([UserName, BrowserProfileId, BrowserName,BrowserExtensionName,"Extension(s)",BrowserExtensionPath,BrowserExtensionRequestedPermissions])]))
```

## Calculate Last Windows Boot Time

Source file: `calculate_last_windows_boot_time.yml`

```cql
#event_simpleName=AgentOnline event_platform=Win  
| groupBy([aid], function=([selectLast([BaseTime])]))
| LastReboot_milli:=(BaseTime/1000*1024)+978307200
| round("LastReboot_milli")
| LastRebootAgo:=now()-(LastReboot_milli*1000)
| formatDuration("LastRebootAgo", precision=2)
| LastReboot:=formatTime(format="%F %T %Z", field="LastReboot_milli")
```

## Check Domain Controller for NSX Driver

Source file: `check_domain_controller_for_nsx_driver.yml`

```cql
event_platform=/Win/i #event_simpleName=/DriverLoad/i 
| in(field=FileName,values=["vnetwfp.sys", "vnetflt.sys"],ignoreCase=true) 
| join({$falcon/investigate:aid_master()}, field=aid, key=aid, include=[ProductType]) 
| ProductType=2 
| "Domain Controller":=ComputerName 
| LocalIP:=LocalAddressIP4 
| Drivers:=FileName 
| groupBy([aid,"Domain Controller",LocalIP,Drivers],function=[])
```

## Chromium-Based Browser Hunting via DLL Load

Source file: `chromium_based_browser_hunting_via_dll_load.yml`

```cql
defineTable(query={#event_simpleName=ClassifiedModuleLoad
| ImageFileName=/chrome\.dll/i
| TargetImageFileName!=/chrome\.exe/i}, include=[ComputerName, TargetProcessId], name="DllLoads")
| #event_simpleName=ProcessRollup2 TargetProcessId=*
| match(table="DllLoads", field=[TargetProcessId])
| table([@timestamp, aid, ComputerName, FileName, TargetProcessId, ImageFileName, TargetImageFileName])
```

## Additional Query Patterns

The following CQL bodies are embedded directly for reuse. Validate event names, field availability, query-surface support, and telemetry in the target environment.

### Get USB Devices

Source YAML: `get_usb_devices.yml`

```cql
#event_simpleName=DcUsbDeviceConnected
| DeviceTimeStamp :=parseTimeStamp(field=DeviceTimeStamp,format=seconds)
| "Time Inserted" := formatTime("%Y-%m-%dT%H:%M:%S.%L", field=DeviceTimeStamp,timezone="Zulu")
| rename([[ComputerName,"Host Name"],[DevicePropertyClassName,"Connection Type"],[DeviceManufacturer,Manufacturer],[DeviceProduct,"Product Name"], [DevicePropertyDeviceDescription,Description], [DevicePropertyClassGuid,GUID],[DeviceInstanceId,"Device ID"]])
| groupBy([aid, "Device ID"], function=([collect(["TimeInserted", ComputerName, "Connection Type",Manufacturer, "Product Name", Description, GUID])]))
```

### Installed Browser Extensions (Aggregate by Extension)

Source YAML: `installed_browser_extensions__aggregate_by_extension_.yml`

```cql
// Get browser extension event
#event_simpleName=InstalledBrowserExtension BrowserExtensionId!="no-extension-available"

// Aggregate by event_platform, BrowserName, ExtensionID and ExtensionName
| groupBy([event_platform, BrowserName, BrowserExtensionId, BrowserExtensionName], function=([count(aid, distinct=true, as=TotalEndpoints)]))

// Check to see if the extension is installed on fewer than 50 systems
| test(TotalEndpoints<50)

// Create a link to the Chrome Extension Store
| format("[See Extension](https://chromewebstore.google.com/detail/%s)", field=[BrowserExtensionId], as="Chrome Store Link")

// Sort in descending order
| sort(order=desc, TotalEndpoints, limit=1000)

// Convert the browser name from decimal to human-readable
| case{
    BrowserName="3" | BrowserName:="Chrome";
    BrowserName="4" | BrowserName:="Edge";
    *;
}
```

### Installed Browser Extensions (Hunt Extension Name)

Source YAML: `installed_browser_extensions__hunt_extension_name_.yml`

```cql
// Get browser extension event
#event_simpleName=InstalledBrowserExtension BrowserExtensionId!="no-extension-available"

// Look for string "vpn" in extension name
| BrowserExtensionName=/vpn/i

// Make a new field that includes the extension ID and Name
| Extension:=format(format="%s (%s)", field=[BrowserExtensionId, BrowserExtensionName])

// Aggregate by endpoint and browser profile
| groupBy([event_platform, aid, ComputerName, UserName, BrowserProfileId, BrowserName], function=([collect([Extension])]))

// Get unnecessary field
| drop([_count])

// Convert browser name from decimal to human readable
| case{
    BrowserName="3" | BrowserName:="Chrome";
    BrowserName="4" | BrowserName:="Edge";
    *;
}
```

### Packages in Container Images - Match Parameter

Source YAML: `packages_in_container_images___match_parameter.yml`

```cql
ImageScanEventType = ImageVulnerabilityEvent
| array:eval("CVEMapping[]", asArray="PackageName[]", function={PackageName := splitString(by="\|",field="CVEMapping",index=1)})
| array:drop("CVEMapping[]")
| array:contains(array="PackageName[]", value=?Package)
| groupBy([ImageInfo.Registry,ImageInfo.Repository])
```

### Windows Store Installs

Source YAML: `windows_store_installs.yml`

```cql
| regex("WindowsApps\\\\(?<PackageName>[^\\\\]+)\\\\", field=FilePath, strict=true)
| regex("^(?<PackageBase>[^_]+)", field=PackageName, strict=false)
| ComputerName=~wildcard(?ComputerName, ignoreCase=true)
| PackageBase=~wildcard(?PackageBase, ignoreCase=true)
// Filter out good filepaths
//| !in(field=FilePath, values=[])
// Filter out good Packages
//| !in(field=PackageBase, values=[])
| groupBy([ComputerName, PackageBase])
| sort(ComputerName, order=asc, limit=max)
```
