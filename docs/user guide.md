# IAM Risk Digest — user guide

How to configure, run, and interpret the tool. For **why** design choices exist, see [Product thinking.md](Product thinking.md).

---

## Prerequisites

- Python **3.10+**
- An **Entra ID app registration** (client credentials) with network access to `login.microsoftonline.com` and `graph.microsoft.com`.

### Microsoft Graph — application permissions

Grant **application** permissions and **admin consent**:

| Permission | Purpose |
|------------|---------|
| **Directory.Read.All** | `/organization` preflight; `$expand=principal` on role assignments |
| **RoleManagement.Read.Directory** | Directory role assignments, PIM schedule instances, role definitions (friendly role names) |

**Not used in code today:** `AuditLog.Read.All`. “Event delay” in the report uses the latest assignment timestamps as a **heuristic**, not the audit log API.

### Azure ARM (optional)

If `AZURE_SUBSCRIPTION_ID` is set to a **subscription GUID**:

- Grant the app’s service principal at least **Reader** on that subscription (IAM at subscription scope).
- ARM RBAC assignments are read at subscription scope only.

If the variable is empty or only whitespace, ARM is skipped and the data-quality notice says ARM was not collected—**this is normal**, not an error.

---

## Environment variables

Copy `.env.example` to `.env`.

| Variable | Required | Meaning |
|----------|----------|---------|
| `AZURE_TENANT_ID` | Yes | Entra tenant ID |
| `AZURE_CLIENT_ID` | Yes | App (client) ID |
| `AZURE_CLIENT_SECRET` | Yes | Client secret |
| `AZURE_SUBSCRIPTION_ID` | No | Subscription GUID for ARM RBAC (omit for directory-only) |
| `STALE_PIM_THRESHOLD_HOURS` | No (default `24`) | Active PIM assignment treated as **stale** after this many hours (no/future end) |
| `STALE_RBAC_THRESHOLD_HOURS` | No (default `48`) | See **Standing RBAC** below |
| `REPORT_CADENCE_DAYS` | No (default `7`) | Used by `--schedule` only |

### Why `STALE_RBAC_THRESHOLD_HOURS` “did nothing” before

Earlier code **never read** this variable. It is now used for:

1. **`rbac_new` severity** — same assignment age **≥ threshold** → **medium**; below → **low** (first-match rules in `risk_scorer.py`).
2. **`rbac_stale` findings** — standing **tier-0 style directory roles** whose `createdDateTime` age is **greater than** this threshold (and which were **not** created this diff cycle). Implemented in `diff_engine.py`.

If you never see `rbac_stale`, typical reasons: baseline-only runs; role display names are still **GUIDs** (missing role-definition read); or no assignment matches the **review role list** in `src/diff_engine.py` (`_STANDING_RBAC_REVIEW_ROLE_NAMES`).

### `STALE_PIM` and unjustified activations

The window for **`pim_no_justification`** is **[`STALE_PIM_THRESHOLD_HOURS`, 2× that value]** hours after activation start, with an empty justification—so it scales if you change the PIM threshold.

---

## Verify connectivity

```bash
python test_connection.py
```

There is no `test_auth.py` in this repo.

---

## Run

```bash
pip install -r requirements.txt
python run_digest.py --run-now
python run_digest.py --run-now --verbose
python run_digest.py --schedule   # foreground weekly loop; see docs/scheduling.md
```

### Baseline vs drift

- **First run** (no prior `snapshots/snapshot_*.json`): **baseline** — no drift findings, but an **HTML report is still written** (executive baseline notice, empty “what changed” style messaging).
- **Second and later runs**: compare to the **latest** snapshot file; findings reflect **delta + standing RBAC review** rules.

To re-baseline in a test environment, archive or remove existing `snapshots/snapshot_*.json` (do **not** do this in production without a backup).

---

## Finding type: `rbac_stale`

| Aspect | Detail |
|--------|--------|
| **When** | Non-baseline run; assignment **not** new this cycle; role display name in the internal tier-0 list; `createdDateTime` **older than** `STALE_RBAC_THRESHOLD_HOURS` |
| **Severity** | **Medium** by default; **high** if standing age ≥ **168** hours (~7 days) |
| **Intent** | Surfaces “this powerful role has been standing longer than policy” even when nothing changed week-to-week |

---

## Testing that the report shows something

1. Complete one digest run (creates baseline snapshot).
2. In **Entra** → **Roles and administrators**, add a **Directory Readers** (or similar low-risk) assignment for a test user, **or** remove an assignment that existed in the last snapshot.
3. Wait a few minutes for Graph consistency.
4. Run again — expect **`rbac_new`** or **`rbac_removed`** for directory roles.

For **PIM**-shaped findings you need PIM enabled and the same Graph permissions; use test activations in a sandbox tenant.

For **ARM** findings, set `AZURE_SUBSCRIPTION_ID` + subscription Reader and change a subscription IAM role between runs.

---

## Troubleshooting

| Symptom | Check |
|---------|--------|
| Role names are GUIDs | Grant **RoleManagement.Read.Directory** + admin consent |
| ARM note / 400 | Subscription id must be a **bare GUID**; see `src/subscription_util.py` |
| No findings after change | Ensure two snapshots exist; confirm change is directory **role assignment**, not only group membership |
| “Assignment timestamps … stale” in Data Quality | Expected **heuristic** (newest `createdDateTime` vs scan time), not Graph audit log lag; optional future: grant `AuditLog.Read.All` if we add real audit queries |

---

## Scheduling

See [scheduling.md](scheduling.md).
