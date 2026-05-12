"""Quick connectivity check for the IAM Risk Digest.

Run with:

    python test_connection.py

The script:
  1. Loads ``.env``.
  2. Acquires a token for Microsoft Graph using the client credentials flow.
  3. Probes the three endpoints the digest actually depends on.

It does NOT save snapshots or write a report — it is purely a smoke test for
the app registration's credentials and permissions.
"""

from __future__ import annotations

import os
import sys

import msal
import requests
from dotenv import load_dotenv

GRAPH_SCOPE = "https://graph.microsoft.com/.default"

# Each entry: (label, url, required permission, required for digest to run?)
# Role definitions are "optional": the digest gracefully falls back to raw
# role IDs (GUIDs) when this endpoint is denied, so we warn instead of fail.
ENDPOINTS: list[tuple[str, str, str, bool]] = [
    (
        "organization",
        "https://graph.microsoft.com/v1.0/organization",
        "Directory.Read.All",
        True,
    ),
    (
        "role assignments",
        "https://graph.microsoft.com/v1.0/roleManagement/directory/"
        "roleAssignments?$top=1&$expand=principal",
        "RoleManagement.Read.Directory",
        True,
    ),
    (
        "role definitions (optional, for friendly role names)",
        "https://graph.microsoft.com/v1.0/roleManagement/directory/"
        "roleDefinitions?$top=1",
        "RoleManagement.Read.Directory",
        False,
    ),
]


def main() -> int:
    load_dotenv()

    tenant_id = os.getenv("AZURE_TENANT_ID", "").strip()
    client_id = os.getenv("AZURE_CLIENT_ID", "").strip()
    client_secret = os.getenv("AZURE_CLIENT_SECRET", "").strip()

    missing = [
        name
        for name, value in (
            ("AZURE_TENANT_ID", tenant_id),
            ("AZURE_CLIENT_ID", client_id),
            ("AZURE_CLIENT_SECRET", client_secret),
        )
        if not value
    ]
    if missing:
        print(f"ERROR: missing env vars: {', '.join(missing)}")
        print("Copy .env.example to .env and fill in the values.")
        return 1

    app = msal.ConfidentialClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret,
    )

    print("Step 1: acquiring Graph token...")
    result = app.acquire_token_for_client(scopes=[GRAPH_SCOPE])
    if "access_token" not in result:
        print(
            "  FAILED: "
            f"{result.get('error', 'unknown_error')} - "
            f"{result.get('error_description', 'no description')}"
        )
        return 1
    token = result["access_token"]
    print("  OK (token acquired)")

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    failures: list[str] = []
    warnings: list[str] = []

    for name, url, required_permission, required in ENDPOINTS:
        print(f"Step: probing {name}...")
        try:
            response = requests.get(url, headers=headers, timeout=30)
        except requests.RequestException as exc:
            msg = f"network error: {exc}"
            print(f"  {'FAILED' if required else 'WARN'}: {msg}")
            (failures if required else warnings).append(name)
            continue

        if response.status_code == 200:
            try:
                count = len(response.json().get("value", []) or [])
                print(f"  OK (HTTP 200, {count} record(s) returned)")
            except ValueError:
                print("  OK (HTTP 200)")
            continue

        if response.status_code in (401, 403):
            label = "FAILED" if required else "WARN"
            print(
                f"  {label}: HTTP {response.status_code}. "
                f"Grant the '{required_permission}' application permission "
                "and ensure admin consent is granted."
            )
            (failures if required else warnings).append(name)
            continue

        body = (response.text or "")[:300]
        label = "FAILED" if required else "WARN"
        print(f"  {label}: HTTP {response.status_code}: {body}")
        (failures if required else warnings).append(name)

    print()
    if failures:
        print(f"Connection test FAILED on: {', '.join(failures)}")
        return 1
    if warnings:
        print(f"Connection test PASSED with warnings on: {', '.join(warnings)}")
        print(
            "  The digest will still run, but some role names may appear as "
            "GUIDs instead of friendly names like 'Global Administrator'."
        )
    else:
        print("Connection test PASSED.")
    print("Next: python run_digest.py --run-now")
    return 0


if __name__ == "__main__":
    sys.exit(main())
