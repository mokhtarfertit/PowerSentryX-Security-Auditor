"# PowerSentryX-Security_Auditor" 

**PowerSentryX** is a PowerShell-based Windows security auditing tool designed to analyze and assess the security posture of a Windows system.

The tool collects and evaluates security-relevant information such as local user accounts, administrator privileges, Windows Defender status, firewall configuration, listening network ports, startup entries, services, and other system settings that may affect security.

PowerSentryX helps identify potentially insecure configurations, unusual system settings, and areas that may require further investigation. It is intended for defensive security, system auditing, cybersecurity learning, and Windows security assessment.

The project also demonstrates practical PowerShell concepts such as cmdlets, functions, modules, objects, pipelines, registry access, Windows management, error handling, and report generation.

## Features

* **System Information Audit** — Collects Windows version, hostname, architecture, current user, domain/workgroup, and system uptime.
* **User & Administrator Audit** — Checks local accounts, disabled accounts, guest account status, and members of the Administrators group.
* **Windows Defender Audit** — Verifies antivirus status, real-time protection, behavior monitoring, and signature updates.
* **Windows Firewall Audit** — Checks Domain, Private, and Public firewall profiles.
* **Firewall Change History** — Detects when the firewall was enabled, disabled, started, stopped, or modified.
* **Firewall Rule Monitoring** — Detects firewall rules or exceptions that were added, modified, or deleted.
* **Network Audit** — Identifies listening ports, network services, and associated processes.
* **Persistence Audit** — Checks common persistence locations such as Run keys, Startup folders, scheduled tasks, and services.
* **Windows Service Audit** — Reviews service status, startup type, executable path, and service account.
* **Security Event Log Audit** — Analyzes important Windows security events and configuration changes.
* **Severity Classification** — Categorizes findings as `PASS`, `INFO`, `WARNING`, or `CRITICAL`.
* **Report Generation** — Generates structured audit results in formats such as HTML, JSON, or CSV.

## project structure 

```text
PowerSentryX/
│
├── PowerSentryX.ps1
│
├── launcher/
│   ├── Start-PowerSentryX.ps1
│   ├── Banner.psm1
│   └── assets/
│       └── powersentryx-logo.png
│
├── modules/
│   │
│   ├── collectors/
│   │   ├── SystemInfo.psm1
│   │   ├── UserAudit.psm1
│   │   ├── DefenderAudit.psm1
│   │   ├── FirewallAudit.psm1
│   │   ├── NetworkAudit.psm1
│   │   ├── ProcessAudit.psm1
│   │   ├── ServiceAudit.psm1
│   │   ├── ScheduledTaskAudit.psm1
│   │   └── SecurityPolicyAudit.psm1
│   │
│   ├── monitoring/
│   │   ├── EventLogMonitor.psm1
│   │   ├── FirewallMonitor.psm1
│   │   ├── DefenderMonitor.psm1
│   │   ├── UserMonitor.psm1
│   │   ├── ServiceMonitor.psm1
│   │   └── ProcessMonitor.psm1
│   │
│   ├── analysis/
│   │   ├── EventClassifier.psm1
│   │   ├── SecurityAnalyzer.psm1
│   │   └── StateComparator.psm1
│   │
│   └── reporting/
│       └── ReportGenerator.psm1
│
├── utils/
│   ├── Helpers.psm1
│   ├── Logger.psm1
│   ├── PrivilegeCheck.psm1
│   └── DateTimeUtils.psm1
│
├── config/
│   ├── settings.psd1
│   ├── EventMap.psd1
│   └── SeverityMap.psd1
│
├── data/
│   ├── baseline/
│   └── snapshots/
│
├── logs/
│   ├── application/
│   ├── security/
│   └── alerts/
│
├── reports/
│
├── tests/
│
├── docs/
│   └── diagrams/
│
├── README.md
├── LICENSE
└── .gitignore

```
# we need to make uml for been more strucutre 
# this for second commit 