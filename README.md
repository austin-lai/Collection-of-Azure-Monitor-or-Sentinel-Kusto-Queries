# Collection of Azure Monitor or Sentinel Kusto Queries

> Austin Lai | April 30th, 2022

---

<!-- Description -->

A collection of Azure Monitor or Sentinel Kusto Queries for your reference.

<!-- /Description -->

## Table of Contents

<!-- TOC -->

- [Collection of Azure Monitor or Sentinel Kusto Queries](#collection-of-azure-monitor-or-sentinel-kusto-queries)
    - [Table of Contents](#table-of-contents)
    - [Queries](#queries)
        - [Monitor or Changes in Policy Detected](#monitor-or-changes-in-policy-detected)
        - [Detect Successful SSH Brute Force Attack using watchlist - that extract username list from potention SSH Brute Force Attack](#detect-successful-ssh-brute-force-attack-using-watchlist---that-extract-username-list-from-potention-ssh-brute-force-attack)
        - [Check specific host IP with SSH authentication failure using uid=0](#check-specific-host-ip-with-ssh-authentication-failure-using-uid0)
        - [**Linux add user to group via groupadd**](#linux-add-user-to-group-via-groupadd)
        - [**Linux add user via useradd**](#linux-add-user-via-useradd)
        - [**Linux delete user via userdel**](#linux-delete-user-via-userdel)
        - [**Linux monitor sudo command**](#linux-monitor-sudo-command)
        - [**Linux Password Change for user via passwd**](#linux-password-change-for-user-via-passwd)
        - [**Linux Login with invalid user with IP address extracted**](#linux-login-with-invalid-user-with-ip-address-extracted)
        - [**Linux Failed Login with wrong password**](#linux-failed-login-with-wrong-password)
        - [**Linux Root SSH Failed Attempt**](#linux-root-ssh-failed-attempt)
        - [**Linux SSH with publickey**](#linux-ssh-with-publickey)
        - [**Linux switch user to root via su command**](#linux-switch-user-to-root-via-su-command)
        - [**Finding MaliciousIP connect to VM**](#finding-maliciousip-connect-to-vm)
        - [**Monitor Get Secret in Kubernetes Cluster or KubeServices within last 30 minutes**](#monitor-get-secret-in-kubernetes-cluster-or-kubeservices-within-last-30-minutes)
        - [**Monitor Edit Secret in Kubernetes Cluster or KubeServices within last 30 minutes**](#monitor-edit-secret-in-kubernetes-cluster-or-kubeservices-within-last-30-minutes)
        - [**Linux SSH Brute Force attempts**](#linux-ssh-brute-force-attempts)
        - [**Monitor OPENVPN with MFA used Google Authenticator**](#monitor-openvpn-with-mfa-used-google-authenticator)
        - [**Monitor Azure DB for MySQL within specific resource group**](#monitor-azure-db-for-mysql-within-specific-resource-group)
        - [**Monitor Azure Blob Storage**](#monitor-azure-blob-storage)
        - [**Monitor Kubernetes Services available in Azure**](#monitor-kubernetes-services-available-in-azure)
        - [**Check Azure Log Analytics Agent for Windows and Linux Heatbeat within last 5 minutes**](#check-azure-log-analytics-agent-for-windows-and-linux-heatbeat-within-last-5-minutes)
        - [**Linux audit log with Username and IP address extracted**](#linux-audit-log-with-username-and-ip-address-extracted)
        - [**Search Kubernetes Logs in Azure with Azure Category**](#search-kubernetes-logs-in-azure-with-azure-category)
        - [**Search container log in Azure**](#search-container-log-in-azure)

<!-- /TOC -->

## Queries

### Monitor or Changes in Policy Detected

```
AzureActivity
| where parse_json(Properties).entity contains "policyDefinitions/XXXXX" or parse_json(Properties).entity contains "policyassignments/XXXXX"
| where isnotempty(ActivityStatusValue) and isnotnull(Properties_d) == true and isnotnull(parse_json(Properties_d).requestbody)
| sort by TimeGenerated desc 
```

### Detect Successful SSH Brute Force Attack using watchlist - that extract username list from potention SSH Brute Force Attack

```
Syslog
| where ProcessName =~ "sshd" 
| where SyslogMessage contains "Accepted publickey" or SyslogMessage contains "Accepted password"
| extend
    user = extract(@"(?:^Accepted publickey for |^Accepted password for )(\S+)", 1, SyslogMessage),
    ip = extract("(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.(([0-9]{1,3})))", 1, SyslogMessage),
    port = extract(@".*?port\s(\S+)", 1, SyslogMessage)
| where user in ( 
    ( _GetWatchlist('SSH-Brute-Force-user-list')
    | project SSHBruteForceUserList))
```

### Check specific host IP with SSH authentication failure using uid=0

```
Syslog
| where HostIP contains "x.x.x.x"
| where SyslogMessage contains "authentication failure" and SyslogMessage contains " uid=0"
| parse SyslogMessage with * "rhost=" ExternalIP
```

### **Linux add user to group via groupadd**

```
Syslog
| where ProcessName == "groupadd" and ( SyslogMessage !contains "syslog" or  SyslogMessage !contains "omsagent" )
```

### **Linux add user via useradd**

```
Syslog
| where ProcessName == "useradd" and ( SyslogMessage !contains "syslog" or  SyslogMessage !contains "omsagent" )
```

### **Linux delete user via userdel**

```
Syslog
| where ProcessName == "userdel"
```

### **Linux monitor sudo command**

```
Syslog
| where ProcessName == "sudo" and SyslogMessage !contains "omsagent" and SyslogMessage !contains "session opened" and SyslogMessage !contains "session closed" and SyslogMessage !contains "waagent"
//| summarize by SyslogMessage
| parse kind=relaxed SyslogMessage with * ""
```

### **Linux Password Change for user via passwd**

```
Syslog
| where ProcessName == "passwd"
| parse kind=relaxed SyslogMessage with * "password changed for " USER
```

### **Linux Login with invalid user with IP address extracted**

```
Syslog
| where SyslogMessage contains "Invalid user" and SyslogMessage !contains "omsagent" 
| extend IP_ADDRESS = extract(@"(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})", 1, SyslogMessage)
| summarize count(IP_ADDRESS) by IP_ADDRESS, SyslogMessage

OR

Syslog
| where SyslogMessage contains "Invalid user" and SyslogMessage !contains "omsagent" 
| extend IP_ADDRESS = extract(@"(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})", 1, SyslogMessage)
| summarize count(Computer) by IP_ADDRESS, SyslogMessage, Computer
```

### **Linux Failed Login with wrong password**

```
Syslog
| where SyslogMessage startswith "Failed Password"
| extend User = extract("for(?s)(.*)from",1,SyslogMessage)
| extend IPaddr = extract("(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.(([0-9]{1,3})))",1,SyslogMessage) 
| project HostName, SyslogMessage, EventTime, IPaddr, User
| summarize Count=count() by IPaddr

OR

Syslog
| where SyslogMessage contains "Failed password"
| extend IP_ADDRESS = extract(@"(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})", 1, SyslogMessage)
| extend USER_NAME = extract(@"invalid\suser\s(\S+)", 1, SyslogMessage)
| summarize count(IP_ADDRESS) by IP_ADDRESS

OR

Syslog
| where SyslogMessage contains "Failed password"
| extend IP_ADDRESS = extract(@"(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})", 1, SyslogMessage)
| extend USER_NAME = extract(@"invalid\suser\s(\S+)", 1, SyslogMessage)
| summarize count(Computer) by IP_ADDRESS, USER_NAME, Computer, SyslogMessage
```

### **Linux Root SSH Failed Attempt**

```
Syslog
| where (SyslogMessage contains "invalid user" or SyslogMessage contains "Failed password") 
| where SyslogMessage !contains "Disconnected" and SyslogMessage !contains "Connection closed"
| where ProcessName =~ "sshd"
| extend
    USER = extract(@"(?:^Failed password for invalid user |^Failed password for |^Invalid user )(\S+)", 1, SyslogMessage),
    S_IPaddr = extract("(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.(([0-9]{1,3})))", 1, SyslogMessage),
    S_Port = extract(@".*?port\s(\S+)", 1, SyslogMessage)
| where USER == "root"
| summarize Count = count() by S_IPaddr, USER, Computer,_ResourceId

OR

Syslog
| where (SyslogMessage contains "invalid user" or SyslogMessage contains "Failed password") 
| where SyslogMessage !contains "Disconnected" and SyslogMessage !contains "Connection closed"
| where ProcessName =~ "sshd"
| extend
    USER = extract(@"(?:^Failed password for invalid user |^Failed password for |^Invalid user )(\S+)", 1, SyslogMessage),
    S_IPaddr = extract("(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.(([0-9]{1,3})))", 1, SyslogMessage),
    S_Port = extract(@".*?port\s(\S+)", 1, SyslogMessage)
| project TimeGenerated, EventTime, Computer, USER, S_IPaddr, S_Port, SyslogMessage
| where USER == "root"
| summarize PerHourCount = count() by S_IPaddr, USER, Computer
```

### **Linux SSH with publickey**

```
Syslog
| where SyslogMessage contains "Accepted publickey"
| where ProcessName =~ "sshd"
| parse kind=relaxed SyslogMessage with * "Accepted publickey for " USER " from " S_IPaddr " port" S_Port " ssh2" *
```

### **Linux switch user to root via su command**

```
Syslog
| where ProcessName == "su" and SyslogMessage !contains "omsagent"
| parse kind=relaxed SyslogMessage with * "su for " USER " by " *
```

### **Finding MaliciousIP connect to VM**

```
VMConnection
| where MaliciousIp != ""
```

### **Monitor Get Secret in Kubernetes Cluster or KubeServices within last 30 minutes**

```
AzureDiagnostics
| where TimeGenerated > ago(30m)
| where ResourceType == "MANAGEDCLUSTERS"
| where Category == "kube-audit"
| where log_s contains "secret"
| where log_s contains "get"
```

### **Monitor Edit Secret in Kubernetes Cluster or KubeServices within last 30 minutes**

```
AzureDiagnostics
| where TimeGenerated > ago(30m)
| where ResourceType == "MANAGEDCLUSTERS"
| where Category == "kube-audit"
| where parse_json(log_s).requestURI == "/api/v1/namespaces/XXX/secrets/XXX?fieldManager=kubectl-edit"
```

### **Linux SSH Brute Force attempts**

```
Syslog
| where (SyslogMessage contains "invalid user" or SyslogMessage contains "Failed password") 
| where SyslogMessage !contains "Disconnected" and SyslogMessage !contains "Connection closed"
| where ProcessName =~ "sshd"
| extend
    USER = extract(@"(?:^Failed password for invalid user |^Failed password for |^Invalid user )(\S+)", 1, SyslogMessage),
    S_IPaddr = extract("(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.(([0-9]{1,3})))", 1, SyslogMessage),
    S_Port = extract(@".*?port\s(\S+)", 1, SyslogMessage)
| project TimeGenerated, EventTime, Computer, USER, S_IPaddr, S_Port, SyslogMessage
| summarize EventTimes = make_list(EventTime), PerHourCount = count() by S_IPaddr, USER, Computer
| mvexpand EventTimes
| extend EventTimes = tostring(EventTimes)
| summarize
    StartTimeUtc = min(EventTimes),
    EndTimeUtc = max(EventTimes),
    UserList = tostring(makeset(USER)),
    Count = sum(PerHourCount)
    by S_IPaddr, Computer

OR

Syslog
| where (SyslogMessage contains "invalid user" or SyslogMessage contains "Failed password") 
| where SyslogMessage !contains "Disconnected" and SyslogMessage !contains "Connection closed"
| where ProcessName =~ "sshd"
| extend USER = extract(@"(?:^Failed password for invalid user |^Failed password for |^Invalid user )(\S+)",1,SyslogMessage), S_IPaddr = extract("(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.(([0-9]{1,3})))",1,SyslogMessage), S_Port = extract(@".*?port\s(\S+)",1,SyslogMessage)
| project EventTime, Computer, USER, S_IPaddr, S_Port, SyslogMessage
| summarize EventTimes = make_list(EventTime), PerHourCount = count() by S_IPaddr, USER, Computer
| mvexpand EventTimes
| extend EventTimes = tostring(EventTimes)
| summarize StartTimeUtc = min(EventTimes), EndTimeUtc = max(EventTimes), UserList = tostring(makeset(USER)), Count = sum(PerHourCount) by  S_IPaddr, Computer
| sort by EndTimeUtc desc

OR

let threshold = 3;
Syslog
// | where TimeGenerated > ago(5m)
| where (SyslogMessage contains "invalid user" or SyslogMessage contains "Failed password") 
| where SyslogMessage !contains "Disconnected" and SyslogMessage !contains "Connection closed"
| where ProcessName =~ "sshd"
| extend USER = extract(@"(?:^Failed password for invalid user |^Failed password for |^Invalid user )(\S+)",1,SyslogMessage), S_IPaddr = extract("(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.(([0-9]{1,3})))",1,SyslogMessage), S_Port = extract(@".*?port\s(\S+)",1,SyslogMessage)
| project EventTime, Computer, USER, S_IPaddr, S_Port, SyslogMessage
//| summarize EventTimes = make_list(EventTime), PerHourCount = count() by S_IPaddr, USER, Computer, bin(EventTime, 5m)
| summarize EventTimes = make_list(EventTime), PerHourCount = count() by S_IPaddr, USER, Computer, bin(EventTime, 4h)
| where PerHourCount > threshold
| mvexpand EventTimes
| extend EventTimes = tostring(EventTimes)
| summarize StartTimeUtc = min(EventTimes), EndTimeUtc = max(EventTimes), UserList = tostring(makeset(USER)), Count = sum(PerHourCount) by  S_IPaddr, Computer
| sort by StartTimeUtc desc
```

OR 

```
let threshold = 5;
Syslog
| where (SyslogMessage contains "Failed password for invalid user" or SyslogMessage contains "invalid user" or SyslogMessage contains "Failed password") 
| where ProcessName =~ "sshd" 
//| parse kind=relaxed SyslogMessage with * "invalid user" user " from " ip " port" port " ssh2"
| extend
    user = extract(@"(?:^Failed password for invalid user |^Failed password for |^Invalid user )(\S+)", 1, SyslogMessage),
    ip = extract("(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.(([0-9]{1,3})))", 1, SyslogMessage),
    port = extract(@".*?port\s(\S+)", 1, SyslogMessage)
| project user, ip, port, SyslogMessage, EventTime, Computer
| summarize EventTimes = make_list(EventTime), PerHourCount = count() by ip, bin(EventTime, 4h), user, Computer
| where PerHourCount > threshold
| mvexpand EventTimes
| extend EventTimes = tostring(EventTimes) 
| summarize
    StartTimeUtc = min(EventTimes),
    EndTimeUtc = max(EventTimes),
    UserList = makeset(user),
    sum(PerHourCount)
    by IPAddress = ip, Computer
| extend UserList = tostring(UserList) 
| extend
    timestamp = StartTimeUtc,
    IPCustomEntity = IPAddress,
    AccountCustomEntity = UserList
```

OR

```
let threshold = 5;
Syslog
| where (SyslogMessage contains "Failed password for invalid user" or SyslogMessage contains "invalid user" or SyslogMessage contains "Failed password") 
| where ProcessName =~ "sshd" 
//| parse kind=relaxed SyslogMessage with * "invalid user" user " from " ip " port" port " ssh2"
| extend
    user = extract(@"(?:^Failed password for invalid user |^Failed password for |^Invalid user )(\S+)", 1, SyslogMessage),
    ip = extract("(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.(([0-9]{1,3})))", 1, SyslogMessage),
    port = extract(@".*?port\s(\S+)", 1, SyslogMessage)
| project user, ip, port, SyslogMessage, EventTime, Computer
| summarize EventTimes = make_list(EventTime), PerHourCount = count() by ip, bin(EventTime, 4h), user, Computer
| where PerHourCount > threshold
| mvexpand EventTimes
| extend EventTimes = tostring(EventTimes) 
| summarize
    StartTimeUtc = min(EventTimes),
    EndTimeUtc = max(EventTimes),
    UserList = makeset(user),
    sum(PerHourCount)
    by IPAddress = ip, Computer
| extend UserList = tostring(UserList) 
| extend
    timestamp = StartTimeUtc,
    IPCustomEntity = IPAddress,
    AccountCustomEntity = UserList
```

### **Monitor OPENVPN with MFA used Google Authenticator**

If you have OpenVPN VM and services setup in Azure, you will be able to monitor OpenVPN activities.

```
//Accepted google_authenticator for user
//Invalid verification code for user
//Did not receive verification code from user
//Failed to read "/etc/openvpn/google-authenticator/user" for "user"

Syslog
| where ProcessName == "openvpn(pam_google_authenticator"
```

### **Monitor Azure DB for MySQL within specific resource group**

```
AzureDiagnostics
| where ResourceGroup contains "XXX"
| where Category contains "MySqlAuditLogs"
```

### **Monitor Azure Blob Storage**

You can refer to this link for more information -> <https://docs.microsoft.com/en-us/azure/storage/blobs/blob-storage-monitoring-scenarios>

```
StorageBlobLogs
| where OperationName == "PutBlob" or
  OperationName == "PutBlock" or
  OperationName == "PutBlockList" or
  OperationName == "AppendBlock" or
  OperationName == "SnapshotBlob" or
  OperationName == "CopyBlob" or
  OperationName == "SetBlobTier"
| extend ContainerName = split(parse_url(Uri).Path, "/")[1]
| summarize WriteSize = sum(RequestBodySize), WriteCount = count() by tostring(ContainerName)
```

### **Monitor Kubernetes Services available in Azure**

```
KubeServices 
| summarize by SelectorLabels
```

### **Check Azure Log Analytics Agent for Windows and Linux Heatbeat within last 5 minutes**

```
Heartbeat
| summarize LastCall = max(TimeGenerated) by Computer
| where LastCall < ago(5m) | count
```

### **Linux audit log with Username and IP address extracted**

```
Syslog
| where (Facility == 'authpriv' and SyslogMessage has 'sshd:auth' and SyslogMessage has 'authentication failure') or (Facility == 'auth' and ((SyslogMessage has 'Failed' and SyslogMessage has 'invalid user' and SyslogMessage has 'ssh2') or SyslogMessage has 'error: PAM: Authentication failure'))
| extend User = extract("for(?s)(.*)from",1,SyslogMessage)
| extend IPaddr = extract("(([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.(([0-9]{1,3})))",1,SyslogMessage) 
| where EventTime < ago(60m)
| summarize Count=count() by Computer
```

### **Search Kubernetes Logs in Azure with Azure Category**

```
AzureDiagnostics
| where Category contains "kube"
| summarize by Category
```

### **Search container log in Azure**

```
ContainerLog
| summarize by LogEntry
```

You may look into Azure table listed below for further log search:

- ContainerImageInventory
- ContainerInventory

Or looking into container registry from Azure Table below:

- ContainerRegistryRepositoryEvents
- ContainerRegistryLoginEvents

<br />

---

> Do let me know any command or step can be improve or you have any question you can contact me via THM message or write down comment below or via FB
