# Windows Endpoint Monitoring Lab

## 1. Project Overview

This is a practical Windows endpoint security monitoring lab designed to familiarize with security operations, endpoint monitoring, log analysis, detection engineering and incident investigation.

The lab uses Wazuh as its security monitoring platform and Sysmon to provide the detailed Windows endpoint telemetry.

The aim is to understand how endpoint events are created, collected, analysed and turned into security alerts and how to go about investigating any suspicious activity.

This is an educational project carried out in a controlled virtual environment.

## 2. Project Objectives

- Deploy and configure a Wazuh monitoring server.
- Configure Sysmon to collect Windows endpoint telemetry.
- Forward Sysmon events to Wazuh.
- Understand the difference between collected events and generated alerts.
- Develop and test custom Wazuh detection rules.
- Look at the security alerts and work out which is the suspicious activity and which is just potentially legitimate system behaviour.
- Document the findings and create reproducible lab configurations.

## 3. Laboratory Architecture

The lab utilises VMware Workstation Pro to run two VMS.

| Component | Configuration |
|---|---|
| Host operating system | Windows 11 Home |
| Virtualisation platform | VMware Workstation Pro |
| Monitoring server | Ubuntu Server 24.04.5 LTS |
| Security monitoring platform | Wazuh 4.14 |
| Endpoint operating system | Windows 11 Enterprise Evaluation |
| Endpoint telemetry | Sysmon 15.22 |
| Endpoint monitoring agent | Wazuh Agent 4.14.10 |

### Network Architecture

The two virtual machines communicate via a VMware host only network.

- Wazuh server: `192.168.149.10`
- Windows endpoint: DHCP-assigned address on the Host-only network
- Network: `192.168.149.0/24`

The Ubuntu server also has a NAT network interface for controlled internet access where required.

The endpoint is normally left on the Host-only network to limit its exposure to the external network.

### Event Collection Flow

1. Sysmon monitors activity on the Windows endpoint.
2. Sysmon records a selection of system events in the Windows Event Log.
3. The Wazuh Agent gathers events from the Sysmon Operational channel.
4. The agent sends the telemetry to the Wazuh Manager.
5. Wazuh analyses the incoming events using its detection rules.
6. Matching events will generate alerts which can be investigated via the Wazuh Dashboard.

## 4. Technologies and Tools

- Wazuh: Security monitoring, log analysis and detection.
- Sysmon: Detailed monitoring of Windows system activity.
- Windows Event Viewer: inspection of endpoint event logs.
- Ubuntu Server: Wazuh server OS.
- VMware Workstation Pro: virtual lab environment.
- PowerShell: Windows configuration and controlled testing.
- Linux command line: Server configuration and troubleshooting.
- Git: version control for the project files and documentation.
- GitHub: platform for publishing the portfolio project.

## 5. Implementation

The following components have been implemented and tested:

- VMware virtual lab created.
- Ubuntu Wazuh server deployed.
- Wazuh Manager, Indexer and Dashboard installed.
-  Windows endpoint VM deployed.
-  Sysmon installed and configured.
- Wazuh agent installed and registered.
-  Windows agent confirmed active on the Wazuh Manager.
-  Sysmon operational channel configured for Wazuh collection.
- Sysmon telemetry was successfully received and is searchable in Wazuh.
-  Looked at the difference between the raw archived events and the generated alerts.
- Custom Wazuh detection rule implemented and tested with both positive and negative test cases.
- Git repository initialised locally.

## 6. Custom Detection Rule

A custom Wazuh rule was created to detect a controlled PowerShell process creation test which contained a particular marker.

The rule makes use of Sysmon Event ID 1 in conjunction with a parent Wazuh rule to identify the relevant process creation event.

The custom rule was given ID 100002 and a severity of 5.

Testing included:

- Positive test using the WazuhRuleTest marker which produced the expected custom alert.
- A negative test using an ordinary PowerShell command (no marker) which didn't trigger an alert that matched the custom rule.

This is a lab detection rule, not a general purpose malicious PowerShell detection rule.

## 7. Security and Safety Considerations

- All monitoring and testing is carried out in a virtual lab.
- The Windows endpoint normally uses a Host-only virtual network.
- Raw forensic data (memory dumps, packet captures, event logs etc) should not be committed to the public repository.
- Credentials, agent auth keys and private config data must be excluded.
- All screenshots and event samples must be checked and cleaned prior to publication.

## 8. Known Limitations

- The custom PowerShell detection rule is based on a specific command line marker and will generate false negatives for any activity that doesn't contain that marker.
- Any legitimate activity which contains the marker would trigger the rule.
- The rule is intended to be a detection engineering example rather than a comprehensive PowerShell threat detection rule.
- Sysmon was configured for broad event collection, which can generate a great number of events.
- Archive logging was turned off following the testing phase due to the sheer volume of data being generated.
- No formal log retention policy has yet been put in place.
