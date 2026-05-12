# Cursor Prompt: IAM Risk Digest

---

## Objective

Build a Python-based automated governance tool called **IAM Risk Digest**. The tool connects to Microsoft Azure via Microsoft Graph API, pulls identity and access data, compares it against a previously saved snapshot, scores the findings by severity, ranks them using a composite priority engine, generates plain-language action items with specific remediation commands, and produces a structured four-layer HTML report that a non-technical IT or Engineering Manager can read and act on without IAM expertise.

This is not a dashboard or web application. It is a script that runs on a schedule or on demand and produces a self-contained HTML report file as its output.

---

## Tech Stack

- **Language**: Python 3.10+
- **Authentication**: `msal` using the OAuth 2.0 client credentials flow
- **HTTP client**: `requests`
- **HTML templating**: `jinja2`
- **Environment variable management**: `python-dotenv`
- **Snapshot storage**: JSON files saved locally to a `/snapshots` directory
- **Report output**: A self-contained HTML file saved to a `/reports` directory
- **Scheduling**: The `schedule` library for the weekly automated run
- **CLI entry point**: `argparse`

Do not use any database. Do not use Flask, FastAPI, or any web framework. Do not use any frontend build tools.

---

## Project Structure

Create the following file and folder structure exactly:

```
iam-risk-digest/
├── .env.example
├── .gitignore
├── requirements.txt
├── run_digest.py
├── src/
│   ├── __init__.py
│   ├── auth.py
│   ├── preflight.py
│   ├── graph_client.py
│   ├── arm_client.py
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
    └── scheduling.md
```

---

## Environment Variables

The `.env.example` file must contain the following keys with empty values and inline comments:

```
AZURE_TENANT_ID=           # Your Entra ID tenant ID
AZURE_CLIENT_ID=           # App registration client ID
AZURE_CLIENT_SECRET=       # App registration client secret
AZURE_SUBSCRIPTION_ID=     # Optional — leave blank if not using ARM RBAC
STALE_PIM_THRESHOLD_HOURS=24
STALE_RBAC_THRESHOLD_HOURS=48
REPORT_CADENCE_DAYS=7
```

The `.gitignore` must include `.env`, `snapshots/*.json`, and `reports/*.html`.

---

## Module Specifications

### `src/auth.py`

Responsibilities:
- Use `msal.ConfidentialClientApplication` to acquire tokens via the client credentials flow
- Expose two functions: `get_graph_token()` and `get_arm_token()`
- `get_graph_token()` acquires a token with scope `https://graph.microsoft.com/.default`
- `get_arm_token()` acquires a token with scope `https://management.azure.com/.default`
- Both functions must cache the token in memory and only re-acquire when within 60 seconds of expiry
- Raise a descriptive `AuthenticationError` (custom exception) if token acquisition fails, including the MSAL error code and description

---

### `src/preflight.py`

Responsibilities:
- Validate that the app registration has the minimum required permissions before any data pull
- Call `GET https://graph.microsoft.com/v1.0/organization` to confirm Graph API is accessible
- Check whether PIM is configured by calling `GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$top=1`
- If `AZURE_SUBSCRIPTION_ID` is set, validate ARM access via `GET https://management.azure.com/subscriptions/{id}?api-version=2020-01-01`
- Return a `PreflightResult` dataclass with the following fields:

```python
@dataclass
class PreflightResult:
    graph_accessible: bool
    arm_accessible: bool
    pim_configured: bool
    subscription_accessible: bool
    graph_error: str | None
    arm_error: str | None
```

- If `graph_accessible` is False, raise `PreflightError` and halt execution with a message identifying the missing permission
- If `pim_configured` is False, do not halt — set the flag so the diff engine can surface this as a finding

---

### `src/graph_client.py`

Responsibilities:
- Pull Entra ID directory role assignments: `GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal,roleDefinition`
- Pull PIM activation instances: `GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal,roleDefinition`
- Handle paginated responses by following `@odata.nextLink` until absent
- Handle 403 by raising `PermissionError` identifying the missing scope
- Handle 429 with exponential backoff, maximum three retries
- Return two lists of normalized dictionaries matching the snapshot schema

---

### `src/arm_client.py`

Responsibilities:
- If `AZURE_SUBSCRIPTION_ID` is set, pull RBAC assignments at subscription scope: `GET https://management.azure.com/subscriptions/{id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01`
- Resolve `roleDefinitionId` to a human-readable role name — cache lookups within the session
- If `AZURE_SUBSCRIPTION_ID` is empty, return an empty list without error
- Apply the same 429 retry logic as `graph_client.py`

---

### `src/snapshot.py`

Responsibilities:
- `save_snapshot(data: dict)` writes to `/snapshots/snapshot_{ISO_timestamp}.json`
- `load_latest_snapshot()` reads the most recent file by timestamp. Returns `None` if none exists.
- Snapshot schema:

```json
{
  "snapshot_id": "uuid-v4",
  "timestamp": "ISO 8601 UTC",
  "is_pim_configured": true,
  "graph_rbac_assignments": [
    {
      "id": "string",
      "principal_id": "string",
      "principal_display_name": "string",
      "principal_type": "User | ServicePrincipal | Group",
      "role_definition_name": "string",
      "scope": "string",
      "created_date_time": "ISO 8601 or null",
      "is_pim_managed": false
    }
  ],
  "pim_activations": [
    {
      "id": "string",
      "principal_id": "string",
      "principal_display_name": "string",
      "principal_type": "User | ServicePrincipal | Group",
      "role_definition_name": "string",
      "scope": "string",
      "start_date_time": "ISO 8601",
      "end_date_time": "ISO 8601 or null",
      "justification": "string or null",
      "assignment_type": "Activated | Eligible"
    }
  ],
  "arm_rbac_assignments": [
    {
      "id": "string",
      "principal_id": "string",
      "principal_type": "string",
      "role_definition_name": "string",
      "scope": "string",
      "created_on": "ISO 8601 or null"
    }
  ]
}
```

---

### `src/diff_engine.py`

Responsibilities:
- Accept the current snapshot, the previous snapshot (or None), and the `PreflightResult`
- Return a `DiffResult` dataclass and a `DataQuality` dataclass

**DataQuality dataclass:**

```python
@dataclass
class DataQuality:
    pim_data_available: bool
    arm_data_available: bool
    signal_conflict_count: int       # Roles removed in RBAC but still active in PIM log
    event_delay_detected: bool       # Graph audit log lagging more than 2 hours behind UTC
    event_delay_hours: float | None  # Actual lag in hours if detected
```

Populate `DataQuality` before computing any findings. Pass it through to the report so the manager knows the coverage of the scan.

**Finding types to detect:**

| Finding type | Detection logic |
|---|---|
| `rbac_new` | In current snapshot, absent in previous |
| `rbac_removed` | In previous snapshot, absent in current |
| `rbac_escalated` | Scope changed from resource group to subscription level |
| `rbac_orphaned` | Assignment exists but principal is disabled or absent in directory |
| `rbac_pim_bypass` | Direct Owner or Contributor assignment where PIM is configured |
| `pim_stale` | Activation age exceeds `STALE_PIM_THRESHOLD_HOURS` and end time is null or future |
| `pim_no_justification` | Justification is null or empty, age is between 24 and 48 hours |
| `pim_repeated` | Three or more activations by same principal for same role within 7-day window |
| `pim_eligible_and_active` | Same principal has both eligible and permanent active assignment for same role |
| `pim_absent` | PIM not configured in tenant (from preflight) |
| `service_principal_elevated` | ServicePrincipal holds Owner or Contributor in any scope |

- For `pim_repeated`: group all activations into one finding with an `activation_count` field
- If previous snapshot is None: return empty `DiffResult` with `is_baseline_run = True`

---

### Finding Schema

Every finding must conform to this schema:

```json
{
  "finding_id": "uuid-v4",
  "finding_type": "string",
  "principal_id": "string",
  "principal_display_name": "string",
  "principal_type": "User | ServicePrincipal | Group",
  "role_definition_name": "string",
  "scope": "string",
  "detected_at": "ISO 8601 UTC",
  "age_hours": "float",
  "activation_count": "integer or null",
  "severity": "high | medium | low",
  "priority_rank": "integer or null",
  "priority_score": "float or null",
  "projected_impact": "string or null",
  "action_item": "string",
  "remediation_command": "string",
  "recommended_owner": "string"
}
```

---

### `src/risk_scorer.py`

Assign severity using the following rules in order. First match wins.

| Rule | Severity |
|---|---|
| `rbac_pim_bypass` | high |
| `rbac_orphaned` | high |
| `service_principal_elevated` | high |
| `pim_stale` and `age_hours` >= 168 | high |
| `pim_eligible_and_active` | high |
| `rbac_new` and `age_hours` >= 48 | medium |
| `pim_stale` and `age_hours` >= 24 | medium |
| `pim_no_justification` | medium |
| `pim_repeated` | medium |
| `pim_absent` | medium |
| `rbac_new` and `age_hours` < 48 | low |
| `rbac_removed` | low |
| All others | low |

---

### `src/priority_engine.py`

This is a new module. Its job is to rank all findings by business urgency and select the top three for the Decision Summary section of the report.

**Composite scoring formula:**

```
priority_score = (severity_weight × 4) + min(age_hours / 24, 15) + principal_type_weight

severity_weight:        high = 10, medium = 5, low = 1
age_weight:             min(age_hours / 24, 30)
principal_type_weight:  ServicePrincipal = 5, User = 2, Group = 1
```

The severity weight is multiplied by 3 to ensure a fresh high-severity finding outranks a very old low-severity one, while age weight ensures stale medium-severity findings do not remain permanently below new high-severity ones. Ties are broken by severity descending, then age descending.

**Responsibilities:**
- Accept the full scored finding list from `risk_scorer.py`
- Compute `priority_score` for each finding and set the `priority_rank` field (1 = highest)
- Select the top three findings by priority score
- For each of the top three, populate `projected_impact` with a plain-English sentence describing the organizational risk if this finding remains unresolved for 30 days

**Projected impact language by finding type:**

| Finding type | Impact projection template |
|---|---|
| `rbac_pim_bypass` | "If unresolved for 30 days, this standing privileged assignment continues to bypass your just-in-time controls, increasing exposure in any incident or audit during that period." |
| `rbac_orphaned` | "If unresolved for 30 days, access belonging to a disabled account remains an active attack vector for credential-based entry into this role." |
| `service_principal_elevated` | "If unresolved for 30 days, a non-human identity with broad permissions continues to represent an unmonitored lateral movement risk across all resources in this scope." |
| `pim_stale` | "If unresolved for 30 days, elevated access that was intended as temporary becomes indistinguishable from a standing assignment, undermining the purpose of your PIM controls." |
| `rbac_new` (medium) | "If unresolved for 30 days, an unconfirmed access change will appear in your next compliance review without a documented business justification." |
| `pim_eligible_and_active` | "If unresolved for 30 days, this role is effectively ungoverned — the permanent active assignment bypasses the activation workflow that PIM was configured to enforce." |
| `pim_repeated` | "If unresolved for 30 days, the repeated activation pattern will continue to generate noise in the audit log, masking other changes that may require attention." |
| `pim_absent` | "Without PIM, all privileged access in this tenant operates on a standing basis. Every day without JIT controls is a day where over-provisioned access cannot be time-bounded or justified on demand." |

- For finding types not listed above, use: "If unresolved for 30 days, this finding will persist as an open risk item in future review cycles."
- Return the full finding list (all findings, with `priority_rank` and `priority_score` populated on every item, and `projected_impact` populated only on the top three)

---

### `src/action_generator.py`

Responsibilities:
- Populate `action_item`, `remediation_command`, and `recommended_owner` on each finding
- `action_item` is a plain-English sentence the manager can read and forward. No technical jargon, no internal type codes.
- `remediation_command` is a specific, copy-pasteable instruction for the Cloud Administrator. It should name the exact portal, navigation path, and action — not just describe the outcome.
- `recommended_owner` is one of: `Cloud Administrator`, `Security Team`, `Manager Review`, `IT Operations`

**Mapping:**

| Finding type | Action item | Remediation command | Owner |
|---|---|---|---|
| `rbac_pim_bypass` | "This privileged role was assigned directly, bypassing your just-in-time access controls. The assignment should be converted to a PIM-eligible assignment and the direct active assignment removed." | "In Entra PIM, navigate to Azure AD Roles > [role name] > Assignments. Add [principal] as Eligible with max activation duration 4 hours and justification required. Then remove the Active assignment for the same principal." | Cloud Administrator |
| `rbac_orphaned` | "This role assignment belongs to an account that has been disabled. It should be removed immediately as it represents an access vector that no active user controls." | "In Entra portal, navigate to Roles and Administrators > [role name]. Find and remove the assignment for principal ID [principal_id]. Confirm the account is disabled in Users before removing." | Cloud Administrator |
| `service_principal_elevated` | "A service principal holds a broad role that may exceed what the application actually requires. The scope should be reviewed and reduced to the minimum necessary permissions." | "In Azure portal, navigate to the resource at [scope] > Access Control (IAM). Remove the [role] assignment for [principal_display_name]. Create a custom role scoped to only the operations this application requires and reassign." | Security Team |
| `pim_stale` | "A PIM activation is still active beyond its expected window. Confirm whether the access is still needed and deactivate it if not." | "In Entra PIM, navigate to Azure AD Roles > Active Assignments. Locate [principal_display_name] in [role_definition_name] and select Deactivate. If access is still required, have the user re-activate with a new justification and appropriate duration." | Manager Review |
| `pim_eligible_and_active` | "This principal has both a PIM-eligible assignment and a permanent active assignment for the same role. The permanent assignment defeats the purpose of PIM and should be removed." | "In Entra PIM, navigate to Azure AD Roles > [role name] > Assignments. Under Active assignments, remove the permanent assignment for [principal_display_name]. The Eligible assignment should remain." | Cloud Administrator |
| `rbac_new` (any age) | "A new role assignment was created recently and has not been confirmed as intentional. Verify the business justification before the next review cycle." | "In Entra portal, navigate to Roles and Administrators > [role name]. Confirm the assignment for [principal_display_name] was authorized. Document the business justification in your access review log." | Manager Review |
| `pim_no_justification` | "A PIM activation was made without a documented justification. Follow up with the user to understand the reason for the activation." | "In Entra PIM, navigate to the audit log and locate the activation event for [principal_display_name] in [role_definition_name]. Contact the user to document the reason. Consider enabling justification as a required field in the PIM role settings." | IT Operations |
| `pim_repeated` | "The same user has activated this privileged role multiple times in the past week. Evaluate whether repeated activation justifies making this role permanently eligible or whether a process gap exists." | "In Entra PIM, navigate to Azure AD Roles > [role name] > Settings. Review the activation policy. If frequent access is legitimate, consider increasing max activation duration. If the pattern is unexpected, review the user's recent activity in the audit log." | Security Team |
| `pim_absent` | "Privileged Identity Management is not configured in this tenant. All privileged access is currently standing rather than just-in-time, which increases exposure." | "In Entra portal, navigate to Privileged Identity Management. Enable PIM for Azure AD Roles. Begin by assigning the highest-privilege roles (Global Administrator, Privileged Role Administrator) as Eligible-only. Schedule a follow-up to extend PIM coverage to all privileged roles within 30 days." | Security Team |
| `rbac_removed` | "A role assignment was removed. Confirm this removal was intentional and that it occurred as part of a planned offboarding or role change." | "In Entra portal, navigate to the audit log and locate the removal event for [principal_display_name] in [role_definition_name]. Confirm the removal was authorized. No further action required if intentional." | IT Operations |

For `pim_repeated`, replace `activation_count` placeholder with the actual count from the finding: "activated [n] times in the past 7 days."

---

### `src/report_compiler.py`

Responsibilities:
- Accept the `DiffResult`, `DataQuality`, `PreflightResult`, and current snapshot metadata
- Compute overall risk score: any high finding = HIGH, any medium (no high) = MEDIUM, low or none = LOW
- Render `templates/report.html.j2` with all data
- Write output to `/reports/iam_digest_{ISO_date}.html`
- The report must be fully self-contained with all styles in a `<style>` block. No external dependencies.

---

### `templates/report.html.j2`

Build a clean, professional HTML report with five sections in this order:

**Section 0: Decision Summary**

Appears only when findings exist and is not a baseline run. Contains exactly three items — the top three findings from the priority engine.

For each of the three, display:
- A numbered rank badge (01, 02, 03) in a large muted format
- The principal name and role in bold
- The `action_item` text
- The `projected_impact` text in a muted italic style below the action
- The `recommended_owner` label in a pill on the right

Header of this section: "Start here. These are the three findings that matter most this week."

**Section 1: Executive Summary**

- Overall risk score as a large colored badge (red = HIGH, amber = MEDIUM, green = LOW)
- Scan date and period covered
- Three metric cards: total findings, high-severity count, actions required
- One plain-English sentence summarizing the most critical finding, or "No access drift detected in this review period" if clean
- If `is_baseline_run` is True: a prominent notice that this is a baseline run and explains that drift comparison begins on the next run
- Data Quality Notice: if any `DataQuality` field is non-nominal, render a bordered notice block listing which signals were unavailable or degraded and what that means for coverage. Use neutral language — this is transparency, not an error.

**Section 2: What Changed**

Chronological table with columns: Principal, Role, Scope, Change Type (human-readable, not the internal type code), Detected At, Severity badge.

Human-readable change type labels:

| Internal type | Display label |
|---|---|
| `rbac_new` | New Assignment |
| `rbac_removed` | Assignment Removed |
| `rbac_escalated` | Scope Escalated |
| `rbac_orphaned` | Orphaned Access |
| `rbac_pim_bypass` | PIM Bypass |
| `pim_stale` | Stale PIM Activation |
| `pim_no_justification` | Unjustified Activation |
| `pim_repeated` | Repeated Activations |
| `pim_eligible_and_active` | Duplicate Assignment |
| `pim_absent` | PIM Not Configured |
| `service_principal_elevated` | Elevated Service Principal |

If no findings: display "No changes detected since the last review."

**Section 3: Prioritized Action Items**

Numbered list of all high and medium findings, sorted by priority rank ascending.

Each item displays:
- Priority rank number (if in top 3, show the rank badge prominently)
- Severity badge
- Principal name and role in bold
- `action_item` text
- `remediation_command` in a monospace-styled block, visually distinct, preceded by the label "How to fix:"
- `recommended_owner` in a muted right-aligned label

Low-severity findings appear in a collapsed `<details>` block below, labeled "Low priority items ([count])".

**Section 4: Full Audit Log**

Complete table of all findings including low severity. Columns: Principal, Type, Role, Scope, Severity, Detected At, Age, Owner, Action.

A notice at the top: "This log contains a complete record of all access changes detected in this review period. It is suitable for use as compliance evidence and access review documentation."

All datetime fields formatted as: "15 Jan 2025, 10:42 UTC"

**Styling rules:**

- System font stack (no external fonts)
- White background, light gray section borders
- Severity colors: HIGH = #DC2626, MEDIUM = #D97706, LOW = #16A34A
- Priority rank badges: large (2rem), muted gray numerals
- Remediation command blocks: `font-family: monospace`, `background: #f8f8f8`, `border-left: 3px solid #D97706`, `padding: 12px`
- Fully print-safe (no fixed positioning, no heavy backgrounds that break PDF export)
- Readable without JavaScript

---

### `run_digest.py`

Entry point. Orchestrates the full execution pipeline:

1. Load `.env` with `python-dotenv`
2. Parse CLI args with `argparse`:
   - `--run-now`: immediate one-off run
   - `--schedule`: start weekly scheduler
   - `--verbose`: set logging to DEBUG
   - Default (no flags): print usage
3. On execution:
   - Run preflight — halt on failure
   - Pull from `graph_client` and `arm_client`
   - Load previous snapshot via `snapshot.py`
   - Save current snapshot
   - Run `diff_engine` — receive `DiffResult` and `DataQuality`
   - Run `risk_scorer`
   - Run `priority_engine`
   - Run `action_generator`
   - Run `report_compiler` — write HTML
   - Print path to report and finding summary
4. All exceptions caught at top level with clear messages. No silent failures.

---

## Edge Cases

**No previous snapshot (first run)**
- `load_latest_snapshot()` returns None
- `DiffResult` returns empty with `is_baseline_run = True`
- Report renders baseline notice in Section 0 (suppressed) and Section 1
- Sections 2, 3, 4 show current state inventory with a label clarifying it is not a diff

**PIM not configured**
- `pim_configured = False` from preflight
- `diff_engine` adds a single `pim_absent` finding at medium severity
- All PIM-specific finding types are skipped without error
- `DataQuality.pim_data_available = False`
- Section 1 Data Quality Notice explains PIM data was unavailable

**ARM subscription not configured**
- `AZURE_SUBSCRIPTION_ID` is empty
- `arm_client` returns empty list silently
- `DataQuality.arm_data_available = False`
- Section 1 Data Quality Notice notes ARM RBAC was not collected

**No changes detected**
- `DiffResult` has empty lists, `is_baseline_run = False`
- Report renders with LOW risk score, green badge, "No access drift detected" in all sections
- Section 0 is suppressed (no top-three to show)
- Report is still written to `/reports` as a governance artifact

**Service principals in assignments**
- Label as "(Service Principal)" next to display name everywhere in the report
- Apply `service_principal_elevated` detection regardless of Graph or ARM source

**Principal with no display name**
- Fall back to showing `principal_id`
- Do not skip the finding or raise an error

**Signal conflict detected**
- Role appears removed in RBAC snapshot but still active in PIM activation log
- Increment `DataQuality.signal_conflict_count`
- Surface both findings independently — do not suppress either
- Section 1 Data Quality Notice lists the count of conflicts detected

**Graph audit log delay**
- Compare latest audit event timestamp against current UTC
- If gap exceeds 2 hours, set `DataQuality.event_delay_detected = True` and record `event_delay_hours`
- Section 1 Data Quality Notice states: "Graph API audit events are currently [N] hours behind real time. Findings from the past [N] hours may not be reflected in this report."

---

## Constraints

- No credentials, tenant IDs, or subscription IDs hardcoded anywhere in source
- No writes outside `/snapshots` and `/reports`
- Read-only: no write, update, or delete calls to Graph API or ARM
- Use Python `logging` module throughout — no bare `print()` inside modules
- All datetime comparisons must be timezone-aware. All API datetimes parsed as UTC. No naive/aware mixing.
- HTML report renders correctly in Chrome, Firefox, and Safari without JavaScript
- `requirements.txt` must pin exact versions for all dependencies

---

## Expected Output on Successful Run

```
[INFO] Preflight validation passed. PIM: configured. ARM: not configured.
[INFO] Pulled 47 Graph RBAC assignments, 12 PIM activations.
[INFO] Loaded previous snapshot: snapshots/snapshot_2025-01-08T10:00:00Z.json
[INFO] Data quality: PIM available, ARM not configured, 0 signal conflicts, no event delay.
[INFO] Diff complete: 3 high, 2 medium, 4 low findings.
[INFO] Priority engine: top 3 selected and ranked.
[INFO] Report written to: reports/iam_digest_2025-01-15.html
Summary: 9 findings | 3 HIGH | 2 MEDIUM | 4 LOW | Actions required: 5
```