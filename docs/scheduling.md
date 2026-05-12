# Scheduling the IAM Risk Digest

The digest is designed to run weekly so that drift between snapshots stays
within a window that a manager can reasonably review. There are three
supported scheduling models, listed from simplest to most production-ready.

---

## Option 1 — Built-in scheduler

The CLI ships with a foreground scheduler powered by the `schedule` library.
This is the easiest to start and is fine for a workstation or a long-lived
VM.

```bash
python run_digest.py --schedule
```

Behavior:

- Reads `REPORT_CADENCE_DAYS` from `.env` (default `7`).
- Runs the digest immediately at startup, then every `N` days thereafter.
- Logs each run to stdout. Failures are caught so a single bad run does not
  stop the scheduler.
- Press `Ctrl+C` to stop.

This option requires the process to remain running. If the host reboots, the
scheduler stops. For unattended environments, prefer Options 2 or 3.

---

## Option 2 — Windows Task Scheduler

For a Windows host (laptop, file server, jump box) without a service manager,
a scheduled task is the most reliable option.

1. Open **Task Scheduler** > **Create Basic Task**.
2. Name: `IAM Risk Digest`.
3. Trigger: **Weekly**, choose a day and time outside business hours.
4. Action: **Start a program**.
5. Program/script: full path to your virtual environment's Python, e.g.

   ```
   C:\Users\talki\IAM\.venv\Scripts\python.exe
   ```

6. Add arguments:

   ```
   run_digest.py --run-now
   ```

7. Start in:

   ```
   C:\Users\talki\IAM
   ```

8. Under the task's **Settings** tab, enable **Run task as soon as possible
   after a scheduled start is missed** so a powered-off laptop catches up on
   its next boot.

The task will load `.env` from the project directory, write a snapshot, and
emit the HTML report into `reports/` on each run.

---

## Option 3 — cron (Linux / macOS)

On a Unix-like host:

```
0 6 * * 1  cd /opt/iam-risk-digest && /opt/iam-risk-digest/.venv/bin/python run_digest.py --run-now >> logs/digest.log 2>&1
```

This runs the digest every Monday at 06:00 local time and appends stdout and
stderr to a log file. Make sure the `logs/` directory exists or replace the
redirection with the path of your choice.

---

## Option 4 — GitHub Actions / Azure DevOps

For an enterprise rollout, run the digest in CI on a schedule and publish the
HTML artifact:

```yaml
# .github/workflows/digest.yml
name: IAM Risk Digest
on:
  schedule:
    - cron: "0 6 * * 1"   # every Monday 06:00 UTC
  workflow_dispatch:
jobs:
  digest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - run: python run_digest.py --run-now
        env:
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
          AZURE_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      - uses: actions/upload-artifact@v4
        with:
          name: iam-digest
          path: reports/
```

Notes:

- Persist `snapshots/` between runs (cache, blob storage, or a long-lived
  branch) so each run has a previous snapshot to diff against. Without
  persistence every run will be a baseline run.
- Email or Slack the artifact link to the recipient list. The HTML file is
  fully self-contained and can be opened from any browser.

---

## Recommendations

- Run weekly. The action items reference 30-day projection windows and a
  weekly cadence keeps the backlog actionable.
- Treat the report directory as an audit artifact: keep at least one year of
  output for compliance review.
- Rotate the app registration secret at least every 180 days. The tool will
  surface an `AuthenticationError` clearly when the secret expires.
