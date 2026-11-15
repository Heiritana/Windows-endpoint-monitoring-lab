# Wazuh Alert 92032 — Investigation Report

**Project:** Windows Endpoint Security Monitoring Lab  
**Platform:** Windows 11 Enterprise Evaluation 26H2  
**Monitoring:** Wazuh 4.14 and Sysmon 15.22  
**Endpoint:** DESKTOP-1UNTTJL  
**Investigation status:** Completed with limitations  
**Assessment:** Likely legitimate Windows Hotpatch-related activity

## 1. Alert overview

| Field | Observed value |
|---|---|
| Alert description | Suspicious Windows cmd shell execution |
| Wazuh rule ID | 92032 |
| Severity | Level 3 |
| Timestamp | 10 November 2026, 19:14:45.450  |
| Process image | `C:\Windows\System32\conhost.exe` |
| Process ID | 6684 |
| Parent process | `C:\Windows\System32\cmd.exe` |
| Parent command line | `"C:\WINDOWS\system32\cmd.exe" /d /c C:\WINDOWS\system32\hpatchmonTask.cmd` |

The alert identified a command-line process execution involving `hpatchmonTask.cmd`.

## 2. Investigation objective

Determine whether the command execution associated with alert 92032 was potentially malicious or consistent with legitimate Windows activity.

The investigation used read-only inspection of the scheduled task, its configured action, the associated script and the Windows service.

## 3. Evidence collected

### 3.1 Scheduled task

The following scheduled task was identified:

- Task name: `Monitoring`
- Task path: `\Microsoft\Windows\Hotpatch\`
- Previously observed state: Ready

Its configured action was:

```text
Execute: %systemroot%\system32\cmd.exe
Arguments: /d /c %systemroot%\system32\hpatchmonTask.cmd
WorkingDirectory: (not specified)
```

The configured command matches the parent command line recorded in the Wazuh alert after environment-variable expansion.

### 3.2 Scheduled task execution information

The following information was retrieved:

| Property | Observed value |
|---|---|
| LastRunTime | 15 November 2026, 11:30:01 AM |
| LastTaskResult | 0 |
| NextRunTime | 16 November 2026, 3:07:18 AM |
| NumberOfMissedRuns | 0 |

The latest recorded execution was several days after the alert date. 

### 3.3 Script inspection

The script was found at:

`C:\WINDOWS\System32\hpatchmonTask.cmd`

File metadata:

| Property | Observed value |
|---|---|
| File size | 7,210 bytes |
| Creation time | 13 September 2026, 11:24 AM |
| Last modified | 13 September 2026, 11:24 AM |

The script was inspected using `Get-Content`.

Its main operations include:

- Checking whether Windows Hotpatches are registered through the registry.
- Checking whether Virtualization Based Security (VBS) is running.
- Checking whether the `hpatchmon` service is installed.
- Checking and potentially configuring the service startup type.
- Attempting to start the service when the script's conditions are met.

The script therefore performs Hotpatch-related service checks and management rather than simply displaying monitoring information.

### 3.4 Windows service inspection

The `hpatchmon` service was queried using `Get-CimInstance` and the `Win32_Service` class.

Observed results:

| Property | Observed value |
|---|---|
| Name | hpatchmon |
| State | Stopped |
| StartMode | Manual |
| PathName | `C:\WINDOWS\system32\svchost.exe -k LocalSystemNetworkRestricted -p` |

The service was stopped and configured for Manual startup at the time of inspection. However, the resultin values do not establish its state when the alert occurred.

## 4. Evidence analysis

Several observations support this is possibly a legitimate Windows Hotpatch event:

1. The scheduled task exists under the Windows Hotpatch task directory.
2. Its configured action invokes the same script identified in the Wazuh alert's parent command line.
3. The script contains operations related to Hotpatch registration, VBS status and the `hpatchmon` service.
4. The `hpatchmon` service was previously found to have a valid Microsoft Authenticode signature.

These observations are consistent with Windows Hotpatch maintenance activity.

However, the investigation did not establish that the scheduled task launched the exact process recorded in the alert at the alert timestamp.

The task's latest execution information and the service's current state cannot independently establish the historical execution sequence.

## 5. Investigation conclusion

**Assessment: Likely legitimate Windows Hotpatch-related activity.**

The script itself and the service details all provide some supporting evidence that the command execution could be part of some legitimate Windows maintenance activity.

The alert in itself doesn't establish malicious activity. The evidence available is also not sufficient to allow us to definitively categorise that particular historical execution as benign.

There were no scheduled tasks, services or scripts altered as part of this investigation.

## 6. Limitations

- The exact historical execution of the scheduled task at the alert timestamp was not confirmed.
- The most recent task execution time doesn't give you a full execution history.
- The service state and startup mode were observed after the alert.
- A complete historical process execution chain was not independently reconstructed.

- Further investigation would be appropriate if additional evidence indicates unexpected service changes, suspicious process ancestry or unauthorised modifications to the script or scheduled task.


