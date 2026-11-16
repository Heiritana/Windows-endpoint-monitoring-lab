# Custom Wazuh Detection Rule 100002 — Testing Report

**Project:** Windows Endpoint Security Monitoring Lab  
**Platform:** Windows 11 Enterprise Evaluation 26H2  
**Monitoring:** Wazuh 4.14 and Sysmon 15.22  
**Endpoint:** DESKTOP-1UNTTJL  
**Investigation status:** Completed  
**Assessment:** Custom detection rule successfully implemented and tested

## 1. Rule overview

| Field | Observed value |
|---|---|
| Rule description | Lab test: PowerShell process creation with WazuhRuleTest marker |
| Wazuh rule ID | 100002 |
| Severity | Level 5 |
| Parent rule ID | 61603 |
| Windows event ID | 1 — Sysmon Process Create |
| Target process | powershell.exe |
| Command-line condition | WazuhRuleTest |

The custom rule was developed to identify PowerShell process-creation events containing a specific command-line marker.

## 2. Detection objective

Develop and test a custom Wazuh detection rule using Windows Sysmon event data.

The objective was to verify that Wazuh could identify a PowerShell process creation event when its command line contained a predefined marker, while not triggering the same custom rule when that marker was absent.

The implementation involved configuring a local Wazuh rule and performing controlled positive and negative tests on the Windows endpoint.

## 3. Evidence collected

### 3.1 Custom rule configuration

The following rule was added to the Wazuh manager's `local_rules.xml` configuration:

```xml
<rule id="100002" level="5">
    <if_sid>61603</if_sid>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">WazuhRuleTest</field>
    <description>Lab test: PowerShell process creation with WazuhRuleTest marker.</description>
    <group>sysmon,process_creation,lab_test,</group>
</rule>
```

The rule contains the following conditions:

- Parent rule ID `61603` must match.
- Windows event ID must be `1`, which corresponds to Sysmon Process Create.
- The process image must end with `powershell.exe`, using a case-insensitive regular expression.
- The command line must contain the marker `WazuhRuleTest`.

All configured conditions must match for the custom rule to generate an alert.

### 3.2 Positive test

A controlled PowerShell command was executed on the Windows endpoint:

```powershell
powershell.exe -noprofile -command "write-output  WazuhRuleTest"
```

The purpose was to generate a PowerShell process-creation event containing the marker configured in the custom rule.

**Observed result:**

Wazuh successfully generated an alert matching custom rule ID `100002`.

The generated alert contained the expected PowerShell process-creation event and the command-line marker.

**Result: Successful.** The positive test demonstrated that the custom rule triggered when the configured conditions were satisfied.

### 3.3 Negative test

A second controlled PowerShell command was executed:

```powershell
powershell.exe -noprofile -command "write-output NegativeTest"
```

This command did not contain the marker required by the custom rule.

**Observed result:**

No alert matching custom rule ID `100002` was generated for this test.

**Result: Successful.** The negative test demonstrated that the custom rule did not trigger when the configured command-line marker was absent.

This result concerns rule `100002` specifically and does not establish that no other Wazuh alert was generated.

## 4. Evidence analysis

The positive and negative tests demonstrate that the custom detection rule behaved according to its configured conditions.

Several observations support this assessment:

1. The positive test generated an alert with the expected custom rule ID `100002`.
2. The generated alert corresponded to a PowerShell process-creation event.
3. The command line contained the configured `WazuhRuleTest` marker.
4. The negative test did not generate an alert matching rule `100002` when the marker was absent.

These results demonstrate successful implementation and basic testing of the custom detection logic.

However, the rule relies on a specific process name and command-line marker. It does not independently determine whether PowerShell activity is malicious or legitimate.

## 5. Testing conclusion


The positive test confirmed that Wazuh generated the expected alert when a PowerShell process-creation event contained the configured marker.

The negative test confirmed that the same custom rule did not trigger for the tested command when the marker was absent.

The results demonstrate that the configured detection conditions worked as intended in the two controlled test scenarios.


## 6. Limitations

- The rule only matches the process image ending in `powershell.exe`.
- PowerShell activity using `pwsh.exe` would not satisfy the configured process-image condition.

- Legitimate PowerShell commands containing the marker could generate false positives.
- The rule does not analyze PowerShell script contents or determine whether an executed command is malicious.
- Detection depends on the relevant Sysmon event being collected and successfully processed by Wazuh.
- Testing was limited to the two controlled scenarios described in this report.

Further development could involve creating broader PowerShell detection rules using additional event attributes and behavioural indicators, followed by more extensive testing to evaluate detection coverage and false-positive rates.