# IAM Risk Digest

A lightweight Azure IAM drift detection and reporting tool that snapshots RBAC and PIM assignment state over time, scores elevated access risks by severity and blast radius, and generates manager-readable remediation reports with copy-pasteable remediation commands.

For the product strategy behind this tool, including persona decisions, what was deliberately not built and why, priority engine design, and roadmap reasoning, see [Product_Thinking.md](./docs/product thinking.md).

---

## The Problem

Cloud identity permissions accumulate without a natural cleanup mechanism. Access gets elevated during incidents and never reverted. Service principals outlive the projects that created them. PIM activations run past their intended window. Broad permissions get assigned at startup speed and never revisited. None of this surfaces until a compliance audit or a breach investigation forces the question, at which point the remediation cost is significantly higher than the detection cost would have been.

The tooling that exists for this speaks to identity engineers. The IT or Engineering Manager accountable for the risk has no lightweight, automated way to understand what their access landscape looks like, what changed since last week, and what specifically needs their attention.

---

## What It Does

IAM Risk Digest connects to Entra ID via Microsoft Graph API, snapshots current RBAC assignments and PIM activation state, and diffs that snapshot against the previous one. It also flags standing tier-0 directory roles that have exceeded the configured review threshold, even when nothing changed between runs. Each finding is classified by type, scored by severity, and ranked by a composite priority score that accounts for severity, age, and principal blast radius. Every run writes a self-contained HTML report, including the first run, so week one is itself a governance artifact.

The report has five sections:

**Decision Summary**: the three highest-priority findings this week, with 30-day impact projections and specific remediation commands. This is where a manager starts.

**Executive Summary**: overall risk score, scan period, finding counts, and a data quality notice when signals are incomplete or delayed.

**What Changed**: chronological table of all findings with severity classifications and human-readable change type labels.

**Action Items**: all medium and high findings ranked by priority, each with a plain-language description and a copy-pasteable step-by-step remediation instruction for the administrator.

**Full Audit Log**: complete timestamped record of all access events in the scan window, structured for use as compliance evidence.

The tool runs on a weekly schedule or triggered manually. Reports are written to a local `/reports` directory as self-contained HTML files that require no server or login to open. For persistent scheduling via cron, Task Scheduler, or Azure Automation, see `docs/scheduling.md`.

---

## Project Structure

```
iam-risk-digest/
├── .env.example
├── .gitignore
├── requirements.txt
├── run_digest.py
├── test_connection.py
├── src/
│   ├── __init__.py
│   ├── config.py
│   ├── auth.py
│   ├── preflight.py
│   ├── graph_client.py
│   ├── arm_client.py
│   ├── subscription_util.py
│   ├── snapshot.py
│   ├── diff_engine.py
│   ├── risk_scorer.py
│   ├── priority_engine.py
│   ├── action_generator.py
│   └── report_compiler.py
├── templates/
│   └── report.html.j2
├── snapshots/
│   └── .gitkeep
├── reports/
│   └── .gitkeep
└── docs/
    ├── scheduling.md
    ├── user guide.md
    └── environment-setup.md
```

---

## System Architecture

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#e8f0fe', 'primaryTextColor': '#1a1a2e', 'primaryBorderColor': '#4a6fa5', 'lineColor': '#4a6fa5', 'secondaryColor': '#f0f4f8', 'tertiaryColor': '#ffffff', 'clusterBkg': '#f0f4f8', 'clusterBorder': '#4a6fa5', 'edgeLabelBackground': '#ffffff', 'fontFamily': 'sans-serif'}}}%%
graph TD
    subgraph Azure["Microsoft Azure"]
        A[Entra ID Directory]
        B[Microsoft Graph API]
        C[RBAC Assignments]
        D[PIM Activation Events]
    end

    subgraph Engine["IAM Risk Digest Engine"]
        E[App Registration\nOAuth 2.0 Client Credentials]
        F[Preflight Validator]
        G[Snapshot Engine]
        H[Diff Engine and Data Quality Layer]
        I[Risk Scorer]
        J[Priority Engine]
        K[Action Generator]
        L[Report Compiler]
    end

    subgraph Storage["Local Storage"]
        M[Snapshot Store\n/snapshots]
    end

    subgraph Output["Report Output"]
        N[Five-Section HTML Report\n/reports]
    end

    subgraph Trigger["Execution Triggers"]
        O[Weekly Scheduler]
        P[Manual On-Demand]
    end

    A --> B
    C --> B
    D --> B
    B --> E
    E --> F
    F --> G
    G --> H
    M --> H
    H --> I
    I --> J
    J --> K
    K --> L
    G --> M
    L --> N
    O --> F
    P --> F
```

---

## Required Permissions

The app registration uses the OAuth 2.0 client credentials flow. Grant the following Microsoft Graph **application** permissions with admin consent:

| Permission | Purpose |
|---|---|
| `Directory.Read.All` | Preflight organization probe; expands principal objects on role assignments for orphan detection |
| `RoleManagement.Read.Directory` | Directory role assignments, PIM schedule instances, role definitions |

`AuditLog.Read.All` is not required by the current implementation. The data quality event-delay signal uses assignment `createdDateTime` and ARM `createdOn` timestamps as a proxy for reporting lag. If `AuditLog.Read.All` is granted in the future, the heuristic in `diff_engine.py` can be replaced with a direct `auditLogs/directoryAudits` query without touching any other module.

**Optional ARM**: when `AZURE_SUBSCRIPTION_ID` is set, grant the service principal at least Reader on that subscription so subscription-level RBAC assignments can be collected.

---

## Sample Output

<!-- Add screenshot of the Decision Summary section here after first demo run -->
<!-- Add screenshot of the Action Items section here -->

A representative finding from the Decision Summary:

```
Priority 01  [HIGH]
Privileged Role Administrator  •  Alex Wilber  (User)

Finding:   Direct active assignment exists in a tenant where PIM is configured,
           bypassing just-in-time access controls entirely.

Action:    Remove the permanent active assignment and recreate it as a
           PIM-eligible assignment with a 4-hour max activation window
           and required justification on each activation.

How:       In Entra PIM, navigate to Azure AD Roles > Privileged Role
           Administrator > Assignments. Remove the Active assignment for
           Alex Wilber. Add an Eligible assignment for the same principal
           with max duration set to 4 hours and justification required.

Owner:     Cloud Administrator

Impact:    If unresolved for 30 days, this standing privileged assignment
           continues to bypass JIT controls, increasing exposure in any
           incident or audit during that period.
```

---

## Setup

### Prerequisites

- Microsoft 365 Developer tenant or Azure account with an active Entra ID directory
- App registration with the two Graph permissions above granted and admin-consented
- Python 3.10 or later

For step-by-step environment setup including M365 Developer tenant creation and demo data seeding, see `docs/environment-setup.md`.

### Install

```bash
git clone https://github.com/your-username/iam-risk-digest
cd iam-risk-digest

python -m venv venv
source venv/bin/activate        # Mac / Linux
venv\Scripts\activate           # Windows

pip install -r requirements.txt
```

### Configure

Copy `.env.example` to `.env` and populate:

```
AZURE_TENANT_ID=                  # Entra ID tenant ID
AZURE_CLIENT_ID=                  # App registration client ID
AZURE_CLIENT_SECRET=              # App registration client secret
AZURE_SUBSCRIPTION_ID=            # Optional, leave blank if not using ARM RBAC
STALE_PIM_THRESHOLD_HOURS=24      # Hours before an active PIM session is flagged stale
STALE_RBAC_THRESHOLD_HOURS=168    # Hours before a standing tier-0 role is flagged for review;
                                  # also sets the medium vs low severity split for new assignments
REPORT_CADENCE_DAYS=7
```

Verify credentials before running:

```bash
python test_connection.py
# Expected output: Connected
```

---

## Running the Tool

**Establish baseline and generate first report:**
```bash
python run_digest.py --run-now
```
The first run saves a snapshot and writes a baseline report. The report notes that drift comparison begins on the next run. This baseline report is itself a governance artifact.

**Generate a diff report (all subsequent runs):**
```bash
python run_digest.py --run-now
```

**Start the weekly scheduler:**
```bash
python run_digest.py --schedule
```
The process must remain active. See `docs/scheduling.md` for persistent options.

**Debug mode:**
```bash
python run_digest.py --run-now --verbose
```

**Expected console output:**
```
[INFO] Preflight validation passed. PIM: configured. ARM: not configured.
[INFO] Pulled 47 Graph RBAC assignments, 12 PIM activations.
[INFO] Loaded previous snapshot: snapshots/snapshot_2025-01-08T10-00-00Z.json
[INFO] Data quality: PIM available, ARM not configured, 0 signal conflicts, no event delay.
[INFO] Diff complete: 3 high, 2 medium, 4 low findings.
[INFO] Priority engine: top 3 selected and ranked.
[INFO] Report written to: reports/iam_digest_2025-01-15.html
Summary: 9 findings | 3 HIGH | 2 MEDIUM | 4 LOW | Actions required: 5
```

---

## Current Limitations

**Single-tenant only.** One `.env` configuration maps to one Entra ID tenant. Multi-tenant support is planned for v2.

**No persistent backend.** Snapshots are JSON files on disk. There is no database, no historical trend view, and no web interface. A dashboard layer can be built on top of the snapshot files in a future iteration.

**ARM support is optional and limited.** Without a configured `AZURE_SUBSCRIPTION_ID`, resource-level RBAC assignments are not collected. ARM data availability is surfaced transparently in the report's Data Quality Notice when absent.

**Orphan detection uses snapshot signals.** Orphaned assignments are flagged when Graph returns no principal data on `$expand=principal`, indicating the principal has been deleted. The tool does not make additional lookup calls to verify `accountEnabled` status, keeping the permission surface to two scopes.

**Report delivery is manual in v1.** The scheduler writes reports to a local directory. Email delivery and ticketing integration are deferred to v2. See `docs/scheduling.md` for options to automate delivery using cron with a mail utility or a file sync service.

**Audit log event delay is estimated, not measured.** The event-delay signal uses the most recent assignment timestamp as a proxy for Graph pipeline freshness. If `AuditLog.Read.All` is granted, this can be upgraded to a direct audit log tail query without changes to any other module.

**Snapshot filenames are Windows-safe.** Colons in ISO timestamps are replaced with hyphens so filenames remain valid on NTFS while still sorting correctly by time.

---

## Roadmap

**v2: Enterprise and delivery layer**

Multi-tenant support, email delivery of the weekly digest, integration with ServiceNow and Jira for automated ticket creation from action items, and a historical trend view showing risk score over rolling 90-day windows.

**v3: Remediation intelligence**

What-if simulation using Azure Resource Graph to model the downstream impact of removing a role assignment before the action is taken. The feature depends on reliable resource dependency mapping and output validation before it can be surfaced to a non-technical manager.
