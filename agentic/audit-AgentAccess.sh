#!/usr/bin/env bash
# audit-AgentAccess.sh <agent-identity-object-id>
#
# Read-only check of one Microsoft Entra agent identity:
#   blueprint link (publisher, secrets and certificates when the blueprint
#   application is in this tenant), linked agent user, API permissions (direct + inherited),
#   groups, Entra roles, Azure RBAC and Defender URBAC for BOTH principals.
#
# Needs: az (logged in), jq. Defender URBAC additionally needs pwsh with the
# Microsoft.Graph.Authentication module (the az token cannot read that scope).
# Optional: SKIP_URBAC=1 to skip it, AZ_SUBS="<id> <id>" to limit Azure RBAC,
# AUDIT_AUTH=auto|browser|devicecode for sign-in (auto: browser, device code in WSL/SSH).
# Signs in to az (and Graph PowerShell for URBAC) only when no usable session exists.
set -uo pipefail

AGENT_ID="${1:-}"
[[ "$AGENT_ID" =~ ^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$ ]] ||
  { echo "usage: $0 <agent identity object ID>" >&2; exit 2; }
for c in az jq; do command -v "$c" >/dev/null || { echo "missing tool: $c" >&2; exit 2; }; done

G=https://graph.microsoft.com
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
FLAGS=()

if [[ -t 1 ]]; then B=$'\e[1m'; D=$'\e[2m'; C=$'\e[36m'; Y=$'\e[33m'; N=$'\e[0m'
else B=; D=; C=; Y=; N=; fi

section() { printf '\n%s== %s ==%s\n' "$B$C" "$1" "$N"; }
group()   { printf '\n%s%s%s\n' "$B$C" "$1" "$N"; }
label()   { printf '\n  %s%s%s\n' "$B" "$1" "$N"; }
kv()      { printf '  %-22s %s\n' "$1" "$2"; }
none()    { printf '    %snone found%s\n' "$D" "$N"; }
items()   { local o; o=$(cat); if [[ -z "$o" ]]; then none; else sed 's/^/    - /' <<<"$o"; fi; }
flag()    { FLAGS+=("$1"); }

# GET, return JSON or empty on error
gget() { az rest --method get --url "$1" -o json 2>/dev/null; }
# GET all pages, return one JSON array of .value items
gall() {
  local url="$1" out='[]' page
  while [[ -n "$url" ]]; do
    page=$(az rest --method get --url "$url" --headers "ConsistencyLevel=eventual" -o json 2>/dev/null) || { echo "$out"; return 1; }
    out=$(jq -c --argjson p "$page" '. + ($p.value // [])' <<<"$out")
    url=$(jq -r '."@odata.nextLink" // empty' <<<"$page")
  done
  echo "$out"
}

# service principal display name and appRoles, cached in $T
spname() {
  [[ -f "$T/n_$1" ]] || gget "$G/v1.0/servicePrincipals/$1?\$select=displayName" | jq -r '.displayName // "unknown resource"' >"$T/n_$1"
  cat "$T/n_$1"
}
rolename() { # resourceId appRoleId
  if [[ "$2" == 00000000-0000-0000-0000-000000000000 ]]; then echo "default access"; return; fi
  [[ -f "$T/r_$1" ]] || gget "$G/v1.0/servicePrincipals/$1?\$select=appRoles" | jq -c '.appRoles // []' >"$T/r_$1"
  jq -r --arg a "$2" 'map(select(.id==$a)) | .[0].value // $a' "$T/r_$1"
}

show_approles() { # JSON array of appRoleAssignment, prints names, flags broad/write scopes
  local n=0 rid aid name
  while IFS=$'\t' read -r rid aid; do
    name="$(spname "$rid"): $(rolename "$rid" "$aid")"
    echo "$name"
    [[ "$name" =~ (ReadWrite|\.Write) ]] && flag "write-capable API permission: $name"
  done < <(jq -r '.[] | [.resourceId, .appRoleId] | @tsv' <<<"$1") | sort | items
}
show_grants() { # JSON array of oAuth2PermissionGrant
  local rid ct sc
  while IFS=$'\t' read -r rid ct sc; do
    sc="${sc# }"; echo "$(spname "$rid"): ${sc:-<no scope>} ${D}($ct)${N}"
  done < <(jq -r '.[] | [.resourceId, .consentType, (.scope // "")] | @tsv' <<<"$1") | items
}

# ---------------------------------------------------------------- sign-in
# AUDIT_AUTH=auto (default) | browser | devicecode
# auto opens the browser, but uses device code in WSL, over SSH or without a display.
want_devicecode() {
  case "${AUDIT_AUTH:-auto}" in devicecode) return 0 ;; browser) return 1 ;; esac
  [[ -n "${WSL_DISTRO_NAME:-}" || -n "${WSL_INTEROP:-}" ]] && return 0
  grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null && return 0
  [[ -n "${SSH_CONNECTION:-}" ]] && return 0
  [[ "$(uname -s)" == Linux && -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]] && return 0
  return 1
}
if ! az account show >/dev/null 2>&1; then
  if want_devicecode; then
    echo "Azure CLI is not signed in. Using device code sign-in..." >&2
    az login --use-device-code --allow-no-subscriptions >/dev/null
  else
    echo "Azure CLI is not signed in. Opening the browser..." >&2
    az login --allow-no-subscriptions >/dev/null ||
      { echo "Browser sign-in failed, falling back to device code..." >&2; az login --use-device-code --allow-no-subscriptions >/dev/null; }
  fi
  az account show >/dev/null 2>&1 || { echo "Azure CLI sign-in failed." >&2; exit 1; }
fi
want_devicecode && export AUDIT_DEVICECODE=1

# ---------------------------------------------------------------- agent identity
section "Agent identity"
IDENT=$(gget "$G/v1.0/servicePrincipals/$AGENT_ID/microsoft.graph.agentIdentity?\$select=id,displayName,accountEnabled,createdDateTime,agentIdentityBlueprintId")
if [[ -z "$IDENT" ]] || ! jq -e '.id' >/dev/null <<<"$IDENT"; then
  echo "Could not read $AGENT_ID as an agent identity (wrong ID, not an agent identity, or missing permission)." >&2
  exit 1
fi
NAME=$(jq -r '.displayName' <<<"$IDENT"); BPID=$(jq -r '.agentIdentityBlueprintId // empty' <<<"$IDENT")
kv "Name" "$NAME"
kv "Object ID" "$AGENT_ID"
kv "Enabled" "$(jq -r '.accountEnabled' <<<"$IDENT")"
kv "Created" "$(jq -r '.createdDateTime' <<<"$IDENT")"

# ---------------------------------------------------------------- blueprint
section "Blueprint"
if [[ -z "$BPID" ]]; then
  none
else
  MYTENANT=$(az account show --query tenantId -o tsv 2>/dev/null)
  BPP=$(gall "$G/v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal?\$filter=appId eq '$BPID'&\$select=id,displayName,appOwnerOrganizationId,createdDateTime")
  BPP_NAME=$(jq -r '.[0].displayName // empty' <<<"$BPP")
  OWNER=$(jq -r '.[0].appOwnerOrganizationId // empty' <<<"$BPP")
  kv "Blueprint app ID" "$BPID"
  kv "Name" "${BPP_NAME:-unknown}"
  kv "Principal in tenant" "$(jq -r 'if length>0 then .[0].id else "not found" end' <<<"$BPP")"
  kv "Principal created" "$(jq -r '.[0].createdDateTime // "n/a"' <<<"$BPP")"
  if [[ -n "$OWNER" ]]; then
    case "$OWNER" in
      f8cdef31-a31e-4b4a-93e4-5f571e91255a) kv "Published by" "$OWNER (Microsoft)";;
      "$MYTENANT") kv "Published by" "$OWNER (this tenant)";;
      *) kv "Published by" "$OWNER (another tenant)";;
    esac
    [[ "$OWNER" != "$MYTENANT" && "$OWNER" != f8cdef31-a31e-4b4a-93e4-5f571e91255a ]] && flag "blueprint is published by another tenant ($OWNER); its credentials are outside your control"
  fi
  BP=$(gall "$G/v1.0/applications/microsoft.graph.agentIdentityBlueprint?\$filter=appId eq '$BPID'&\$select=id,displayName,signInAudience,passwordCredentials,keyCredentials")
  if [[ "$(jq 'length' <<<"$BP")" -gt 0 ]]; then
    kv "Blueprint application" "in this tenant ($(jq -r '.[0].signInAudience' <<<"$BP"))"
    NSEC=$(jq '.[0].passwordCredentials | length' <<<"$BP"); NCERT=$(jq '.[0].keyCredentials | length' <<<"$BP")
    kv "Client secrets" "$NSEC"
    jq -r '.[0].passwordCredentials[] | "    secret \(.displayName // "(no name)"), expires \(.endDateTime)"' <<<"$BP"
    kv "Certificates" "$NCERT"
    jq -r '.[0].keyCredentials[] | "    certificate \(.displayName // "(no name)"), expires \(.endDateTime)"' <<<"$BP"
    ((NSEC > 0)) && flag "blueprint has $NSEC client secret(s); a blueprint credential can authenticate all its agent identities, prefer certificates or federated credentials"
  else
    kv "Blueprint application" "not in this tenant (only the principal is)"
    kv "Blueprint credentials" "held by the publishing tenant, not visible here"
  fi
  SIB=$(gall "$G/v1.0/servicePrincipals/microsoft.graph.agentIdentity?\$filter=agentIdentityBlueprintId eq '$BPID'&\$select=id" | jq 'length')
  kv "Agent identities" "$SIB in this tenant from this blueprint (1:N)"
fi

# ---------------------------------------------------------------- agent user
section "Linked agent user"
AU=$(gall "$G/v1.0/users/microsoft.graph.agentUser?\$filter=identityParentId eq '$AGENT_ID'&\$select=id,displayName,userPrincipalName,accountEnabled,assignedLicenses,createdDateTime")
USER_ID=$(jq -r '.[0].id // empty' <<<"$AU")
if [[ -z "$USER_ID" ]]; then
  echo "  NO AGENT USER linked to this agent identity."
  flag "no agent user (only the agent identity can hold access)"
else
  kv "Name" "$(jq -r '.[0].displayName' <<<"$AU")"
  kv "UPN" "$(jq -r '.[0].userPrincipalName' <<<"$AU")"
  kv "Object ID" "$USER_ID"
  kv "Enabled" "$(jq -r '.[0].accountEnabled' <<<"$AU")"
  kv "Licenses" "$(jq -r '.[0].assignedLicenses | length' <<<"$AU")"
  [[ "$(jq -r '.[0].assignedLicenses | length' <<<"$AU")" != 0 ]] && flag "agent user has assigned licenses"
fi

# ---------------------------------------------------------------- Defender URBAC (pwsh)
URBAC='[]'
if [[ "${SKIP_URBAC:-0}" != 1 ]]; then
  if command -v pwsh >/dev/null; then
    cat >"$T/urbac.ps1" <<'PS'
param($Ids, $Out)
$scope = 'RoleManagement.Read.Defender'
$ctx = Get-MgContext
if (-not $ctx -or $ctx.Scopes -notcontains $scope) {
  if ($env:AUDIT_DEVICECODE -eq '1') { Connect-MgGraph -Scopes $scope -UseDeviceCode -NoWelcome }
  else {
    try { Connect-MgGraph -Scopes $scope -NoWelcome -ErrorAction Stop }
    catch { Write-Warning 'Browser sign-in failed, falling back to device code.'; Connect-MgGraph -Scopes $scope -UseDeviceCode -NoWelcome }
  }
}
$b = 'https://graph.microsoft.com/beta/roleManagement/defender'
function All($u) { $r = @(); while ($u) { $p = Invoke-MgGraphRequest -Uri $u; $r += $p.value; $u = $p.'@odata.nextLink' }; $r }
$ids = $Ids -split ','; $defs = @{}
All "$b/roleDefinitions" | ForEach-Object { $defs[$_.id] = $_ }
$res = foreach ($a in (All "$b/roleAssignments")) { foreach ($i in $ids) {
  if ($a.principalId -eq $i -or $a.principalIds -contains $i) { $d = $defs[$a.roleDefinitionId]
    [pscustomobject]@{ principalId = $i; role = $d.displayName; appScopeIds = @($a.appScopeIds)
      actions = @($d.rolePermissions.allowedResourceActions | Sort-Object -Unique) } } } }
ConvertTo-Json -InputObject @($res) -Depth 5 | Set-Content $Out
PS
    echo "${D}Reading Defender URBAC via Microsoft Graph PowerShell (a sign-in prompt may appear)...${N}" >&2
    pwsh -NoProfile -File "$T/urbac.ps1" -Ids "$AGENT_ID,${USER_ID:-none}" -Out "$T/urbac.json" >&2 || true
    [[ -s "$T/urbac.json" ]] && URBAC=$(cat "$T/urbac.json") || URBAC='null'
  else
    URBAC='null'
  fi
fi

# ---------------------------------------------------------------- per-principal audit
if [[ -n "${AZ_SUBS:-}" ]]; then read -ra SUBS <<<"$AZ_SUBS"
else mapfile -t SUBS < <(az account list --query "[?state=='Enabled'].id" -o tsv 2>/dev/null); fi

audit() { # kind id title
  local kind="$1" id="$2" title="$3" j
  section "$title"

  group "API permissions"
  label "App roles (direct)"
  j=$(gall "$G/v1.0/$kind/$id/appRoleAssignments"); show_approles "$j"

  if [[ "$kind" == servicePrincipals ]]; then
    label "Delegated grants (direct)"
    j=$(gall "$G/v1.0/servicePrincipals/$id/oauth2PermissionGrants"); show_grants "$j"

    label "App roles inherited from blueprint (beta)"
    j=$(gall "$G/beta/servicePrincipals/microsoft.graph.agentIdentity/$id/inheritedAppRoleAssignments"); show_approles "$j"

    label "Delegated grants inherited from blueprint (beta)"
    j=$(gall "$G/beta/servicePrincipals/microsoft.graph.agentIdentity/$id/inheritedOauth2PermissionGrants"); show_grants "$j"
  fi

  group "Entra ID"
  label "Groups and directory objects"
  j=$(gall "$G/v1.0/$kind/$id/transitiveMemberOf")
  jq -r '.[] | "\(.displayName // .id)  \(."@odata.type" | sub("#microsoft.graph.";""))"' <<<"$j" | items
  [[ "$kind" == users ]] && jq -e 'any(.[]; .displayName=="All Users")' >/dev/null <<<"$j" &&
    flag "agent user is in 'All Users' (anything shared with that group is inherited)"

  label "Directory roles"
  j=$(gall "$G/v1.0/roleManagement/directory/roleAssignments?\$filter=principalId eq '$id'&\$expand=roleDefinition")
  jq -r '.[] | "\(.roleDefinition.displayName) @ \(.directoryScopeId)"' <<<"$j" | items

  group "Azure"
  label "Role assignments (${#SUBS[@]} subscriptions checked)"
  local extra=() s role scope
  [[ "$kind" == users ]] && extra=(--include-groups)
  for s in "${SUBS[@]}"; do
    az role assignment list --subscription "$s" --all --include-inherited "${extra[@]}" --assignee "$id" \
      --query '[].[roleDefinitionName, scope]' -o tsv 2>/dev/null |
      while IFS=$'\t' read -r role scope; do echo "$role @ ${scope/\/subscriptions\/$s/<sub:${s:0:8}>}"; done
  done | items

  group "Defender XDR"
  label "Unified RBAC (URBAC)"
  if [[ "$URBAC" == null ]]; then
    printf '    %snot checked (needs pwsh with Microsoft.Graph.Authentication, or SKIP_URBAC was set)%s\n' "$Y" "$N"
  else
    j=$(jq -c --arg i "$id" '[.[] | select(.principalId==$i)]' <<<"$URBAC")
    if [[ "$(jq 'length' <<<"$j")" == 0 ]]; then none; else
      jq -r '.[] | "    - \(.role)  [scope: \(.appScopeIds | join(","))]\n        \(.actions | join("\n        "))"' <<<"$j"
    fi
    jq -r '.[].actions[]' <<<"$j" | grep -q '/manage$' && flag "$title: URBAC role with write-capable (manage) actions"
    jq -r '.[].actions[]' <<<"$j" | grep -q 'rawdata/' && flag "$title: URBAC role can read raw data (for example email content)"
  fi
}

audit servicePrincipals "$AGENT_ID" "Access held by the agent identity"
[[ -n "$USER_ID" ]] && audit users "$USER_ID" "Access held by the agent user"

# ---------------------------------------------------------------- summary
section "Flags"
if ((${#FLAGS[@]})); then printf '  ! %s\n' "${FLAGS[@]}"; else none; fi
printf '\n%sNot covered: PIM-eligible roles, access packages, Conditional Access policies, Foundry or Copilot Studio RBAC.%s\n' "$D" "$N"
