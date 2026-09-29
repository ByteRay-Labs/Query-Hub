---
name: crowdstrike-cql-identity
description: "Use for CrowdStrike CQL hunts covering failed or successful logons, brute-force follow-up, account usage, and local user creation or deletion."
user-invocable: true
---

# Identity and Logon Hunting

Use these query bodies as starting points. Validate event names, fields, time scope, function support, and telemetry availability in the target tenant. These queries are investigative leads, not verdicts.

## Failed User Logon Thresholding

Source file: `Failed_User_Logon_Thresholding.yml`

```cql
// Get Windows UserLogonFailed events
event_platform=Win #event_simpleName=UserLogonFailed2

// This line is completely optional, but converts SubStatus to hex
| SubStatus_hex:=format(field=SubStatus, "%x") | SubStatus_hex:=upper(SubStatus_hex) | SubStatus_hex:=format(format="0x%s", field=[SubStatus_hex])

// Aggregate results
| groupBy([aid, ComputerName, UserName, LogonType, SubStatus_hex, SubStatus], function=([count(aid, as=FailCount), min(ContextTimeStamp, as=FirstLogonAttempt), max(ContextTimeStamp, as=LastLogonAttempt), collect([LocalAddressIP4, aip])]))

// Perform rate calculations
| firstLastDeltaHours:=((LastLogonAttempt-FirstLogonAttempt)/60/60) | round("firstLastDeltaHours")
| logonAttemptsPerHour:=(failCount/firstLastDeltaHours) | round("logonAttemptsPerHour")

// Convert timestamps from epoch to human
| FirstLogonAttempt:=formatTime(format="%F %T.%L", field="FirstLogonAttempt")
| LastLogonAttempt:=formatTime(format="%F %T.%L", field="LastLogonAttempt")

// Optional: set threshold for failed logins
| FailCount> 5

// Sort descending
| sort(FailCount, order=desc, limit=2000)

// Convert fields from decimal to human readable
| $falcon/helper:enrich(field=LogonType)
| $falcon/helper:enrich(field=SubStatus)
```

## Failed and Successful User Logon Events

Source file: `Failed_and_Successful_User_Logon_Events.yml`

```cql
#event_simpleName=/UserLogon/
| case{
    #event_simpleName=UserLogon | SuccessLogonTime:=ContextTimeStamp;
    #event_simpleName=UserLogonFailed2 | FailedLogonTime:=ContextTimeStamp;
}
| groupBy([UserSid, UserName], function=([min(FailedLogonTime, as=FirstFailedLogon), max(FailedLogonTime, as=LastFailedLogon), max(SuccessLogonTime, as=LastSuccessfulLogin), count(SuccessLogonTime, as=TotalSuccessfulLogins), count(FailedLogonTime, as=TotalFailedLogins), selectFromMax(field="@timestamp", include=[PasswordLastSet]), {#event_simpleName=UserLogon | selectFromMax(field="@timestamp", include=[ComputerName]) | rename(field="ComputerName", as="LastLoggedOnHost")}]))
| TotalFailedLogins>3
| $falcon/helper:enrich(field=UserLogonFlags)
| formatTime(format="%F %T", field=FirstFailedLogon, as="FirstFailedLogon", timezone="EST")
| formatTime(format="%F %T", field=LastFailedLogon, as="LastFailedLogon", timezone="EST")
| formatTime(format="%F %T", field=LastSuccessfulLogin, as="LastSuccessfulLogin", timezone="EST")
| PasswordLastSet:=PasswordLastSet*1000 | formatTime(format="%F %T", field=PasswordLastSet, as="PasswordLastSet", timezone="EST")
| default(value="-", field=[FirstFailedLogon, LastFailedLogon, LastSuccessfulLogin, TotalSuccessfulLogins, TotalFailedLogins, PasswordLastSet, LastLoggedOnHost])
| sort(order=desc, TotalFailedLogins, limit=20000)
```

## Failed logon attempt group by userName and unique Endpoint involved

Source file: `Failed_logon_attempt.yml`

```cql
#event_simpleName = UserLogonFailed
| groupBy(UserName, function=([count(timestamp, distinct=true, as=uniqueFailedLogons), (count(aid, distinct=true, as=uniqueEP)), collect(fields = [ComputerName, aid], limit =10000)]))
| default(field = "UserName", value="-", replaceEmpty=true)
| uniqueFailedLogons >= 5
| uniqueEP >= 10
| sort(uniqueEP)
```

## Public IP Successfully Authenticated Following Brute Force Activity

Source file: `Public_IP_Successfully_Authenticated_Following_Brute_Force_Activity.yml`

```cql
#Vendor ="crowdstrike"
|"#event_simpleName" ="RemoteBruteForceDetectInfo"
| DetectDescription=~/^A public IP successfully brute forced an account on this system/
|table([@timestamp,ComputerName,user.name,RemoteIP])
```

## Detection of Generic User Account Usage

Source file: `detection_of_generic_user_account_usage.yml`

```cql
"#event_simpleName" = UserLogon | user.name := lower("user.name") | groupBy(user.name,ComputerName) | match(file="generic-usernames.csv", field=[user.name], column=[username])
| table([user.name, ComputerName, _count])
| User := rename(user.name)
| Host := rename(ComputerName)
| LogonCount := rename(_count)
```

## Created Local User Accounts

Source file: `created_local_user_accounts.yml`

```cql
#event_simpleName=UserAccountCreated
| table([@timestamp, UserName, aid, aip, ComputerName, event_platform, LocalIP, name], limit=20000)
| sort(@timestamp)
```

## Deleted Local User Accounts

Source file: `deleted_local_user_accounts.yml`

```cql
#event_simpleName=UserAccountDeleted
| groupBy([UserName, aid, aip, ComputerName, event_platform, LocalIP, name], function=selectLast([@timestamp]))
| table([@timestamp, UserName, ComputerName, aid, aip, event_platform, LocalIP, name])
| sort(@timestamp)
```

## Additional Query Patterns

The following CQL bodies are embedded directly for reuse. Validate event names, field availability, query-surface support, and telemetry in the target environment.

### Find events triggered at logon

Source YAML: `logon_events.yml`

```cql
#event_simpleName=ScheduledTaskRegistered
| parseXml(TaskXml)
| Trigger:=rename(Task.Triggers.LogonTrigger.Enabled)
| Trigger=* // Remove this line if you don't care if it's empty
| table([aid, Trigger, TaskXml], limit=1000)
```

### NTLM authentication where Kerberos is expected (Baseline)

Source YAML: `ntlm_authentication_where_kerberos_is_expected_baseline.yml`

```cql
// Hunt for NTLM authentications in scenarios where Kerberos would normally be expected
#event_simpleName=ActiveDirectoryAuthentication

// Keep only NTLM authentications
| in(field=ActiveDirectoryAuthenticationMethod, values=[1, 2, 5])

// Focus on service-based access (SPN/service context),
// where Kerberos should normally be available
| TargetServiceAccessIdentifier=*

// Optional: suppress machine accounts if you want a user-only view
// | SourceAccountSamAccountName!=/$/

// Map NTLM authentication method values to readable names
| case {
    ActiveDirectoryAuthenticationMethod = 1 | AuthMethod := "NTLM_V1";
    ActiveDirectoryAuthenticationMethod = 2 | AuthMethod := "NTLM_V2";
    ActiveDirectoryAuthenticationMethod = 5 | AuthMethod := "UNKNOWN_NTLM";
    * | AuthMethod := "OTHER";
}

// Map AD protocol values for easier triage
| case {
    ActiveDirectoryDataProtocol = 0 | DataProtocol := "LDAP";
    ActiveDirectoryDataProtocol = 1 | DataProtocol := "DCE_RPC";
    ActiveDirectoryDataProtocol = 2 | DataProtocol := "RDP";
    ActiveDirectoryDataProtocol = 3 | DataProtocol := "SMB";
    * | DataProtocol := format(format="PROTO_%s", field=[ActiveDirectoryDataProtocol]);
}

// Summarize NTLM fallback activity
| groupBy([
    SourceEndpointHostName,
    SourceEndpointAddressIP4,
    SourceAccountDomain,
    SourceAccountSamAccountName,
    TargetServiceAccessIdentifier,
    TargetServerHostName,
    TargetServerAddressIP4,
    DataProtocol,
    AuthMethod
], function=[
    sum(AggregationActivityCount, as="ntlm_auth_count"),
    min(AggregationEarliestTimestamp, as="first_seen"),
    max(AggregationLatestTimestamp, as="last_seen")
])

// Show highest NTLM usage first
| sort(field=ntlm_auth_count, order=desc)
```

### User Logoff Activity

Source YAML: `user_logoff_activity.yml`

```cql
#event_simpleName=UserLogoff
| groupBy([UserName, name, aid, aip, ComputerName, event_platform, LocalIP, LogonDomain, LogonServer, LogonType], function=[count(@timestamp), selectLast([@timestamp])])
| table([@timestamp, UserName, ComputerName, aid, aip, event_platform, LocalIP, LogonDomain, LogonType], limit=20000)
```

### User Logon Activity

Source YAML: `user_logon_activity.yml`

```cql
#event_simpleName=UserLogon
| groupBy([UserName, name, aid, aip, ComputerName, event_platform, LocalIP, LogonDomain, LogonServer, LogonType], function=[count(@timestamp), selectLast([@timestamp])])
| table([@timestamp, UserName, ComputerName, aid, aip, event_platform, LocalIP, LogonDomain, LogonType], limit=20000)
```

### User Logon Details (Time, Type, Location, Last Password Change)

Source YAML: `user_logon_details__time__type__location__last_password_change_.yml`

```cql
#event_simpleName=UserLogon UserSid=S-1-5-21-*
| in(LogonType, values=["2","10"])
| ipLocation(aip)
| case {UserIsAdmin = "1" | UserIsAdmin := "Yes" ;
UserIsAdmin = "0" | UserIsAdmin := "No" ;
* }
| case {
LogonType = "2" | LogonType := "Interactive" ;
LogonType = "3" | LogonType := "Network" ;
LogonType = "4" | LogonType := "Batch" ;
LogonType = "5" | LogonType := "Service" ;
LogonType = "7" | LogonType := "Unlock" ;
LogonType = "8" | LogonType := "Network Cleartext" ;
LogonType = "9" | LogonType := "New Credentials" ;
LogonType = "10" | LogonType := "Remote Interactive" ;
LogonType = "11" | LogonType := "Cached Interactive" ;
* }
| PasswordLastSet := PasswordLastSet*1000
| LogonTime := LogonTime*1000
| PasswordLastSet := formatTime("%Y-%m-%d %H:%M:%S", field=PasswordLastSet, locale=en_US, timezone=Z)
| LogonTime := formatTime("%Y-%m-%d %H:%M:%S", field=LogonTime, locale=en_US, timezone=Z)
| table(["LogonTime", "aid", "UserName", "UserSid", "LogonType", "UserIsAdmin", "PasswordLastSet", "aip.city", "aip.state", "aip.country"])
```

### Windows authentication traffic metrics

Source YAML: `windows_authentication_traffic_metrics.yml`

```cql
#repo=base_sensor #event_simpleName="IdpDcPerfReport"
| aid=?SelectedAid
| IdpPerfCounterAvg:= IdpPerfCounterSum / IdpPerfSampleCount
| timeChart(span=15m, function=[avg("IdpPerfCounterAvg")], series=IdpPerfCounterPath)
```
