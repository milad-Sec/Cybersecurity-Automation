#!/usr/bin/env python3
"""
Azure AD (Microsoft Entra ID) Privilege Review Automation
- Enumerates directory roles and exports:
  * Active (current) assignments (including PIM-activated JIT)
  * Eligible assignments via PIM
- Outputs CSVs for auditors:
    role_assignments_active.csv
    role_assignments_eligible.csv

Auth: MSAL Device Code (delegated)
Required delegated permissions (admin-consented):
  - RoleManagement.Read.Directory
  - Directory.Read.All
Optional:
  - AuditLog.Read.All   # if enable_last_signin_enrichment = True
"""

import csv
import time
import sys
from typing import Dict, List, Any
import requests
import msal
from dateutil import parser as dtparser

# ----------------- CONFIG -----------------
TENANT_ID = "<YOUR_TENANT_ID>"
CLIENT_ID = "<YOUR_APP_CLIENT_ID>"
# Toggle to enrich with each user's last sign-in (slower; needs AuditLog.Read.All)
ENABLE_LAST_SIGNIN_ENRICHMENT = False
# ------------------------------------------

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["https://graph.microsoft.com/.default"]  # we'll request app's delegated scopes (admin consented)

GRAPH = "https://graph.microsoft.com/v1.0"

session = requests.Session()
session.headers.update({"Content-Type": "application/json"})

def get_token_interactive() -> str:
    app = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY)
    # Use device flow; admin should already have consented to the delegated scopes
    flow = app.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        print("Failed to create device flow. Check CLIENT_ID/TENANT_ID and app configuration.", file=sys.stderr)
        sys.exit(1)
    print(f"\n==> To sign in, visit {flow['verification_uri']} and enter code: {flow['user_code']}\n")
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        print(f"Authentication failed: {result}", file=sys.stderr)
        sys.exit(1)
    return result["access_token"]

def graph_get(url: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
    r = session.get(url, params=params)
    if r.status_code >= 400:
        raise RuntimeError(f"Graph GET {url} failed: {r.status_code} {r.text}")
    return r.json()

def graph_paged(url: str, params: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    items = []
    while url:
        data = graph_get(url, params=params)
        items.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        params = None  # nextLink already contains the query
    return items

def attach_bearer(token: str):
    session.headers["Authorization"] = f"Bearer {token}"

# --------- Helpers to fetch roles and assignments ----------

def get_directory_roles() -> List[Dict[str, Any]]:
    """
    Returns roles (only those with at least one member are materialized by directoryRoles).
    We will also use role definitions to ensure complete mapping.
    """
    # Role definitions (all) – covers full catalog; used to label results
    role_defs = graph_paged(f"{GRAPH}/roleManagement/directory/roleDefinitions?$top=999")
    role_defs_by_id = {rd["id"]: rd for rd in role_defs}

    # Active/presented roles in directoryRoles (historically needed for member listing)
    dir_roles = graph_paged(f"{GRAPH}/directoryRoles?$top=999")
    # Map roleTemplateId → display name (templateId exists on directoryRoles)
    template_to_name = {}
    for dr in dir_roles:
        tmpl = dr.get("roleTemplateId")
        if tmpl:
            template_to_name[tmpl] = dr.get("displayName")

    return role_defs, role_defs_by_id, template_to_name

def get_active_assignments() -> List[Dict[str, Any]]:
    """
    Active assignments, including PIM-activated (JIT) instances:
      GET /roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal,roleDefinition,activatedUsing
    """
    url = f"{GRAPH}/roleManagement/directory/roleAssignmentScheduleInstances"
    expand = "$expand=principal,roleDefinition,activatedUsing"
    select = "$select=id,principalId,roleDefinitionId,startDateTime,endDateTime,memberType,assignmentType"
    items = graph_paged(f"{url}?{expand}&{select}&$top=999")
    return items

def get_eligible_assignments() -> List[Dict[str, Any]]:
    """
    Eligible assignments (PIM eligibility):
      GET /roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal,roleDefinition
    """
    url = f"{GRAPH}/roleManagement/directory/roleEligibilityScheduleInstances"
    expand = "$expand=principal,roleDefinition"
    select = "$select=id,principalId,roleDefinitionId,startDateTime,endDateTime,memberType"
    items = graph_paged(f"{url}?{expand}&{select}&$top=999")
    return items

def try_parse_dt(s: str) -> str:
    if not s:
        return ""
    try:
        return dtparser.parse(s).isoformat()
    except Exception:
        return s

# --------- Optional: last sign-in enrichment ---------

def get_last_signin_for_user(user_id: str) -> str:
    """
    Returns ISO timestamp of user's most recent sign-in (if any).
    Requires AuditLog.Read.All and sign-in logging enabled.
    """
    # New signIn logs can be large; pull just the latest
    url = f"{GRAPH}/auditLogs/signIns?$top=1&$orderby=createdDateTime desc&$filter=userId eq '{user_id}'"
    try:
        data = graph_get(url)
        val = data.get("value", [])
        if val:
            return val[0].get("createdDateTime", "")
    except Exception:
        return ""
    return ""

# ----------------- Main -----------------

def main():
    token = get_token_interactive()
    attach_bearer(token)

    print("Fetching role catalog and mappings...")
    role_defs, role_defs_by_id, template_to_name = get_directory_roles()

    # Build a lookup for roleDefinitionId → display name
    role_name_by_def_id = {}
    for rd in role_defs:
        # Prefer displayName; if templateId maps to a friendly name from directoryRoles use that
        disp = rd.get("displayName")
        tmpl = rd.get("templateId")
        if tmpl and tmpl in template_to_name:
            disp = template_to_name[tmpl] or disp
        role_name_by_def_id[rd["id"]] = disp

    print("Fetching ACTIVE (including PIM-activated) assignments...")
    active = get_active_assignments()

    print("Fetching ELIGIBLE (PIM) assignments...")
    eligible = get_eligible_assignments()

    # Prepare CSVs
    active_rows = []
    eligible_rows = []

    def principal_fields(principal) -> Dict[str, str]:
        if not principal:
            return {"principalType": "", "principalDisplayName": "", "principalUPN": ""}
        odata_type = principal.get("@odata.type", "")
        # user or servicePrincipal or group
        pdn = principal.get("displayName", "")
        upn = principal.get("userPrincipalName", "") if "user" in odata_type.lower() else principal.get("appId", "")
        ptype = odata_type.split(".")[-1]
        return {"principalType": ptype, "principalDisplayName": pdn, "principalUPN": upn}

    # Build maps for optional last sign-in to avoid repeated API calls per user
    last_signin_cache: Dict[str, str] = {}

    # ACTIVE
    for a in active:
        rd = a.get("roleDefinition") or {}
        role_def_id = a.get("roleDefinitionId")
        role_name = role_name_by_def_id.get(role_def_id, rd.get("displayName", ""))

        principal = a.get("principal") or {}
        pfields = principal_fields(principal)
        pid = a.get("principalId", "")

        last_signin = ""
        if ENABLE_LAST_SIGNIN_ENRICHMENT and pfields.get("principalType", "").lower() == "user":
            if pid not in last_signin_cache:
                last_signin_cache[pid] = get_last_signin_for_user(pid)
                # be polite to API / avoid throttling
                time.sleep(0.1)
            last_signin = last_signin_cache[pid]

        row = {
            "roleName": role_name,
            "roleDefinitionId": role_def_id,
            "assignmentId": a.get("id", ""),
            "principalId": pid,
            **pfields,
            "assignmentType": a.get("assignmentType", ""),  # e.g., "Activated" (PIM) vs "Assigned"
            "memberType": a.get("memberType", ""),          # e.g., "Direct" or "Inherited"
            "startDateTime": try_parse_dt(a.get("startDateTime", "")),
            "endDateTime": try_parse_dt(a.get("endDateTime", "")),
            "lastSignIn": try_parse_dt(last_signin),
        }
        active_rows.append(row)

    # ELIGIBLE
    for e in eligible:
        rd = e.get("roleDefinition") or {}
        role_def_id = e.get("roleDefinitionId")
        role_name = role_name_by_def_id.get(role_def_id, rd.get("displayName", ""))

        principal = e.get("principal") or {}
        pfields = principal_fields(principal)
        pid = e.get("principalId", "")

        row = {
            "roleName": role_name,
            "roleDefinitionId": role_def_id,
            "eligibilityId": e.get("id", ""),
            "principalId": pid,
            **pfields,
            "memberType": e.get("memberType", ""),          # "Direct" or "Inherited"
            "startDateTime": try_parse_dt(e.get("startDateTime", "")),
            "endDateTime": try_parse_dt(e.get("endDateTime", "")),
        }
        eligible_rows.append(row)

    # Write CSVs
    def write_csv(path: str, rows: List[Dict[str, Any]]):
        if not rows:
            print(f"No data for {path}")
            return
        cols = list(rows[0].keys())
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)
        print(f"Wrote {path} ({len(rows)} rows)")

    write_csv("role_assignments_active.csv", active_rows)
    write_csv("role_assignments_eligible.csv", eligible_rows)

    print("\nDone. Files created:")
    print(" - role_assignments_active.csv")
    print(" - role_assignments_eligible.csv")
    print("\nTip: commit these CSVs or feed them to your Access Review process / dashboards.")

if __name__ == "__main__":
    main()
