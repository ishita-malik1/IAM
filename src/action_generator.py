"""Generate plain-language action items, owner assignments, and remediation
commands for every finding.

The mapping table is exactly the one documented in the project README. The
generator only fills in placeholders — ``[principal]``, ``[role name]`` and so
on — and never invents new wording.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


_OWNER_CLOUD_ADMIN = "Cloud Administrator"
_OWNER_SECURITY = "Security Team"
_OWNER_MANAGER = "Manager Review"
_OWNER_IT_OPS = "IT Operations"


_TEMPLATES: dict[str, dict[str, str]] = {
    "rbac_pim_bypass": {
        "action_item": (
            "This privileged role was assigned directly, bypassing your "
            "just-in-time access controls. The assignment should be "
            "converted to a PIM-eligible assignment and the direct active "
            "assignment removed."
        ),
        "remediation_command": (
            "In Entra PIM, navigate to Azure AD Roles > {role} > "
            "Assignments. Add {principal} as Eligible with max activation "
            "duration 4 hours and justification required. Then remove the "
            "Active assignment for the same principal."
        ),
        "owner": _OWNER_CLOUD_ADMIN,
    },
    "rbac_orphaned": {
        "action_item": (
            "This role assignment belongs to an account that has been "
            "disabled. It should be removed immediately as it represents an "
            "access vector that no active user controls."
        ),
        "remediation_command": (
            "In Entra portal, navigate to Roles and Administrators > {role}. "
            "Find and remove the assignment for principal ID {principal_id}. "
            "Confirm the account is disabled in Users before removing."
        ),
        "owner": _OWNER_CLOUD_ADMIN,
    },
    "service_principal_elevated": {
        "action_item": (
            "A service principal holds a broad role that may exceed what "
            "the application actually requires. The scope should be "
            "reviewed and reduced to the minimum necessary permissions."
        ),
        "remediation_command": (
            "In Azure portal, navigate to the resource at {scope} > Access "
            "Control (IAM). Remove the {role} assignment for {principal}. "
            "Create a custom role scoped to only the operations this "
            "application requires and reassign."
        ),
        "owner": _OWNER_SECURITY,
    },
    "pim_stale": {
        "action_item": (
            "A PIM activation is still active beyond its expected window. "
            "Confirm whether the access is still needed and deactivate it "
            "if not."
        ),
        "remediation_command": (
            "In Entra PIM, navigate to Azure AD Roles > Active Assignments. "
            "Locate {principal} in {role} and select Deactivate. If access "
            "is still required, have the user re-activate with a new "
            "justification and appropriate duration."
        ),
        "owner": _OWNER_MANAGER,
    },
    "pim_eligible_and_active": {
        "action_item": (
            "This principal has both a PIM-eligible assignment and a "
            "permanent active assignment for the same role. The permanent "
            "assignment defeats the purpose of PIM and should be removed."
        ),
        "remediation_command": (
            "In Entra PIM, navigate to Azure AD Roles > {role} > "
            "Assignments. Under Active assignments, remove the permanent "
            "assignment for {principal}. The Eligible assignment should "
            "remain."
        ),
        "owner": _OWNER_CLOUD_ADMIN,
    },
    "rbac_new": {
        "action_item": (
            "A new role assignment was created recently and has not been "
            "confirmed as intentional. Verify the business justification "
            "before the next review cycle."
        ),
        "remediation_command": (
            "In Entra portal, navigate to Roles and Administrators > {role}. "
            "Confirm the assignment for {principal} was authorized. "
            "Document the business justification in your access review log."
        ),
        "owner": _OWNER_MANAGER,
    },
    "pim_no_justification": {
        "action_item": (
            "A PIM activation was made without a documented justification. "
            "Follow up with the user to understand the reason for the "
            "activation."
        ),
        "remediation_command": (
            "In Entra PIM, navigate to the audit log and locate the "
            "activation event for {principal} in {role}. Contact the user "
            "to document the reason. Consider enabling justification as a "
            "required field in the PIM role settings."
        ),
        "owner": _OWNER_IT_OPS,
    },
    "pim_repeated": {
        "action_item": (
            "The same user has activated this privileged role multiple "
            "times in the past week. Evaluate whether repeated activation "
            "justifies making this role permanently eligible or whether a "
            "process gap exists. The user activated {n} times in the past "
            "7 days."
        ),
        "remediation_command": (
            "In Entra PIM, navigate to Azure AD Roles > {role} > Settings. "
            "Review the activation policy. If frequent access is "
            "legitimate, consider increasing max activation duration. If "
            "the pattern is unexpected, review the user's recent activity "
            "in the audit log."
        ),
        "owner": _OWNER_SECURITY,
    },
    "pim_absent": {
        "action_item": (
            "Privileged Identity Management is not configured in this "
            "tenant. All privileged access is currently standing rather "
            "than just-in-time, which increases exposure."
        ),
        "remediation_command": (
            "In Entra portal, navigate to Privileged Identity Management. "
            "Enable PIM for Azure AD Roles. Begin by assigning the highest-"
            "privilege roles (Global Administrator, Privileged Role "
            "Administrator) as Eligible-only. Schedule a follow-up to "
            "extend PIM coverage to all privileged roles within 30 days."
        ),
        "owner": _OWNER_SECURITY,
    },
    "rbac_removed": {
        "action_item": (
            "A role assignment was removed. Confirm this removal was "
            "intentional and that it occurred as part of a planned "
            "offboarding or role change."
        ),
        "remediation_command": (
            "In Entra portal, navigate to the audit log and locate the "
            "removal event for {principal} in {role}. Confirm the removal "
            "was authorized. No further action required if intentional."
        ),
        "owner": _OWNER_IT_OPS,
    },
    "rbac_escalated": {
        "action_item": (
            "An existing assignment was escalated from a resource group "
            "scope to subscription scope. Confirm this expansion was "
            "intentional and aligns with the principle of least privilege."
        ),
        "remediation_command": (
            "In Azure portal, navigate to the subscription > Access "
            "Control (IAM). Review the {role} assignment for {principal}. "
            "If the broader scope is not required, remove it and reinstate "
            "the assignment at the original resource group scope."
        ),
        "owner": _OWNER_MANAGER,
    },
    "rbac_stale": {
        "action_item": (
            "This privileged directory role has been assigned as a standing "
            "assignment longer than your configured review threshold. "
            "Confirm it is still required, documented, and appropriate for "
            "least privilege."
        ),
        "remediation_command": (
            "In Entra portal, navigate to Roles and Administrators > {role}. "
            "Review the assignment for {principal}. If the access is still "
            "needed, document the business justification and next review "
            "date. If PIM is enabled for this role, convert the assignment "
            "to Eligible-only and remove the permanent Active assignment."
        ),
        "owner": _OWNER_MANAGER,
    },
}


def _format(template: str, finding: dict[str, Any]) -> str:
    return template.format(
        principal=finding.get("principal_display_name") or "the principal",
        principal_id=finding.get("principal_id") or "(unknown)",
        role=finding.get("role_definition_name") or "the role",
        scope=finding.get("scope") or "the scope",
        n=finding.get("activation_count") or 0,
    )


def _default(finding: dict[str, Any]) -> dict[str, str]:
    return {
        "action_item": (
            "An access change was detected that does not match a known "
            "category. Review the principal and role manually."
        ),
        "remediation_command": (
            "In Azure portal, locate the assignment for "
            f"{finding.get('principal_display_name') or 'the principal'} "
            f"in {finding.get('role_definition_name') or 'the role'} at "
            f"{finding.get('scope') or 'the scope'} and confirm whether it "
            "is intentional."
        ),
        "owner": _OWNER_MANAGER,
    }


def generate_actions(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Populate ``action_item``, ``remediation_command``, and
    ``recommended_owner`` on every finding."""

    for finding in findings:
        template = _TEMPLATES.get(finding.get("finding_type", ""))
        if template is None:
            fallback = _default(finding)
            finding["action_item"] = fallback["action_item"]
            finding["remediation_command"] = fallback["remediation_command"]
            finding["recommended_owner"] = fallback["owner"]
            continue
        finding["action_item"] = _format(template["action_item"], finding)
        finding["remediation_command"] = _format(
            template["remediation_command"], finding
        )
        finding["recommended_owner"] = template["owner"]
    return findings
