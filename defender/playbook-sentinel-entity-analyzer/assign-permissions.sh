#!/usr/bin/env bash
# Assign the playbook managed identity the roles the Entity Analyzer playbooks need.
#
#   Microsoft Sentinel Responder  -> write incident comments (Microsoft.SecurityInsights/incidents/*)
#   Security Reader (Entra role)  -> Sentinel MCP / Entity Analyzer data access
#   Security Copilot Contributor  -> MANUAL portal assignment; gates SCU-backed analysis
#
# Idempotent: every assignment is checked before it is created. Nothing is ever removed.
# Run with --dry-run first; it prints exactly what it would do and changes nothing.
set -euo pipefail

PRINCIPAL_ID=""
PLAYBOOK_NAME=""
PLAYBOOK_RESOURCE_GROUP=""
SUBSCRIPTION_ID=""
WORKSPACE_RESOURCE_ID=""
SCOPE_LEVEL="resourcegroup"
ASSIGN_ENTRA_SECURITY_READER=true
DRY_RUN=false

die() { echo "ERROR: $*" >&2; exit 2; }

usage() {
  cat <<'USAGE'
Usage: ./assign-permissions.sh --workspace-resource-id <id> (--principal-id <guid>
                               | --playbook-name <name> --playbook-resource-group <rg>) [options]

Required:
  --workspace-resource-id <id>    ARM ID of the Sentinel-enabled Log Analytics workspace.
                                  All role scopes are derived from this, including its
                                  subscription - not from --subscription-id.

Identify the managed identity, one of:
  --principal-id <guid>           Object ID of the identity. No lookup performed.
  --playbook-name <name>          Logic app name, plus:
  --playbook-resource-group <rg>  its resource group. Add --subscription-id when the
                                  logic app lives in a different subscription than
                                  the workspace.

Options:
  --subscription-id <guid>        Subscription holding the LOGIC APP, used only to look
                                  the identity up. Defaults to the workspace subscription.
  --scope-level <level>           resourcegroup (default, recommended) or workspace.
                                  workspace also scopes the SecurityInsights solution
                                  resource, which Sentinel requires alongside it.
  --skip-entra-security-reader    Do not add the identity to the Entra directory role
                                  "Security Reader". MCP Entity Analyzer requires this
                                  role for data access; use this only when it is already
                                  granted through another controlled path.
  --dry-run                       Print planned changes, make none.
  -h, --help                      This text.

Example:
  ./assign-permissions.sh \
    --principal-id <MANAGED-IDENTITY-OBJECT-ID> \
    --workspace-resource-id "/subscriptions/<sub>/resourcegroups/<rg>/providers/microsoft.operationalinsights/workspaces/<ws>" \
    --dry-run

Note: Azure RBAC "Security Reader" is a DIFFERENT role - Defender for Cloud only. The
Security Reader required by Sentinel MCP is the Microsoft Entra directory role. This script
does not assign the unnecessary Microsoft Sentinel Reader role for Entity Analyzer data access.
USAGE
}

need_value() { [ "$2" -ge 2 ] || die "$1 requires a value"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --principal-id)            need_value "$1" $#; PRINCIPAL_ID="$2"; shift 2 ;;
    --principal-id=*)          PRINCIPAL_ID="${1#*=}"; shift ;;
    --playbook-name)           need_value "$1" $#; PLAYBOOK_NAME="$2"; shift 2 ;;
    --playbook-name=*)         PLAYBOOK_NAME="${1#*=}"; shift ;;
    --playbook-resource-group) need_value "$1" $#; PLAYBOOK_RESOURCE_GROUP="$2"; shift 2 ;;
    --playbook-resource-group=*) PLAYBOOK_RESOURCE_GROUP="${1#*=}"; shift ;;
    --subscription-id)         need_value "$1" $#; SUBSCRIPTION_ID="$2"; shift 2 ;;
    --subscription-id=*)       SUBSCRIPTION_ID="${1#*=}"; shift ;;
    --workspace-resource-id)   need_value "$1" $#; WORKSPACE_RESOURCE_ID="$2"; shift 2 ;;
    --workspace-resource-id=*) WORKSPACE_RESOURCE_ID="${1#*=}"; shift ;;
    --scope-level)             need_value "$1" $#; SCOPE_LEVEL="$2"; shift 2 ;;
    --scope-level=*)           SCOPE_LEVEL="${1#*=}"; shift ;;
    --skip-entra-security-reader) ASSIGN_ENTRA_SECURITY_READER=false; shift ;;
    --assign-entra-security-reader) echo "WARNING: --assign-entra-security-reader is now the default; use --skip-entra-security-reader to opt out." >&2; shift ;;
    --dry-run)                 DRY_RUN=true; shift ;;
    -h|--help)                 usage; exit 0 ;;
    --)                        shift; break ;;
    -*)                        usage >&2; die "unknown option '$1'" ;;
    *)  usage >&2
        die "unexpected argument '$1' - every value must follow its flag, e.g. --principal-id $1" ;;
  esac
done

[ -n "$WORKSPACE_RESOURCE_ID" ] || { usage >&2; die "--workspace-resource-id is required"; }

# ---------------------------------------------------------------------------
# Workspace: parse case-insensitively, real resource IDs are often all-lowercase
# ---------------------------------------------------------------------------
WS_SUB=$(awk -F/ '{for(i=1;i<=NF;i++) if(tolower($i)=="subscriptions") print $(i+1)}' <<<"$WORKSPACE_RESOURCE_ID")
WS_RG=$(awk -F/  '{for(i=1;i<=NF;i++) if(tolower($i)=="resourcegroups") print $(i+1)}' <<<"$WORKSPACE_RESOURCE_ID")
WS_NAME="${WORKSPACE_RESOURCE_ID##*/}"
[ -n "$WS_SUB" ] && [ -n "$WS_RG" ] && [ -n "$WS_NAME" ] || \
  die "cannot parse --workspace-resource-id (need /subscriptions/<id>/resourceGroups/<rg>/.../workspaces/<name>)"
: "${SUBSCRIPTION_ID:=$WS_SUB}"
echo "workspace = $WS_NAME  (resource group $WS_RG, subscription $WS_SUB)"

# ---------------------------------------------------------------------------
# Managed identity
# ---------------------------------------------------------------------------
if [ -z "$PRINCIPAL_ID" ]; then
  [ -n "$PLAYBOOK_NAME" ] && [ -n "$PLAYBOOK_RESOURCE_GROUP" ] || \
    die "pass --principal-id, or both --playbook-name and --playbook-resource-group"
  PRINCIPAL_ID=$(az resource show \
    --subscription "$SUBSCRIPTION_ID" \
    --resource-group "$PLAYBOOK_RESOURCE_GROUP" \
    --resource-type "Microsoft.Logic/workflows" \
    --name "$PLAYBOOK_NAME" \
    --query "identity.principalId" -o tsv --only-show-errors 2>/dev/null || true)
  [ -n "$PRINCIPAL_ID" ] && [ "$PRINCIPAL_ID" != "null" ] || \
    die "$PLAYBOOK_NAME has no system-assigned identity. Deploy with identity.type=SystemAssigned first."
fi
echo "managed identity principalId = $PRINCIPAL_ID"

# ---------------------------------------------------------------------------
# Scopes
# ---------------------------------------------------------------------------
SCOPES=()
case "$SCOPE_LEVEL" in
  resourcegroup)
    SCOPES+=("/subscriptions/$WS_SUB/resourceGroups/$WS_RG")
    ;;
  workspace)
    SCOPES+=("$WORKSPACE_RESOURCE_ID")
    # Workspace-scoped Sentinel assignments are incomplete alone: the docs require the
    # same roles on the SecurityInsights solution resource as well.
    SI_ID=$(az resource list \
      --subscription "$WS_SUB" \
      --resource-group "$WS_RG" \
      --resource-type "Microsoft.OperationsManagement/solutions" \
      --query "[?starts_with(name, 'SecurityInsights')].id | [0]" -o tsv --only-show-errors)
    if [ -n "$SI_ID" ] && [ "$SI_ID" != "null" ]; then
      SCOPES+=("$SI_ID")
      echo "note: also scoping to the SecurityInsights solution resource"
    else
      echo "WARNING: no SecurityInsights solution resource found in $WS_RG."
      echo "         Workspace-scoped Sentinel roles may be incomplete. Prefer --scope-level resourcegroup."
    fi
    ;;
  *) die "--scope-level must be 'resourcegroup' or 'workspace'" ;;
esac

# ---------------------------------------------------------------------------
# Azure RBAC
# ---------------------------------------------------------------------------
assign_role() {
  local role="$1" scope="$2" existing
  existing=$(az role assignment list \
    --subscription "$WS_SUB" \
    --scope "$scope" \
    --query "[?principalId=='$PRINCIPAL_ID' && roleDefinitionName=='$role'].id | [0]" \
    -o tsv --only-show-errors)
  if [ -n "$existing" ] && [ "$existing" != "null" ]; then
    echo "  = already assigned : $role"
    return 0
  fi
  if [ "$DRY_RUN" = "true" ]; then
    echo "  + WOULD assign      : $role"
    return 0
  fi
  az role assignment create \
    --subscription "$WS_SUB" \
    --assignee-object-id "$PRINCIPAL_ID" \
    --assignee-principal-type ServicePrincipal \
    --role "$role" \
    --scope "$scope" \
    --output none --only-show-errors
  echo "  + assigned          : $role"
}

for scope in "${SCOPES[@]}"; do
  echo "scope $scope"
  assign_role "Microsoft Sentinel Responder" "$scope"   # incident comments (implies read)
done

# ---------------------------------------------------------------------------
# Entra directory role "Security Reader" - required for MCP, tenant-wide
# ---------------------------------------------------------------------------
if [ "$ASSIGN_ENTRA_SECURITY_READER" = "true" ]; then
  echo
  echo "Entra directory role 'Security Reader' (tenant-wide, all data lake workspaces)"
  ROLE_ID=$(az rest --method GET \
    --url "https://graph.microsoft.com/v1.0/directoryRoles?\$filter=displayName eq 'Security Reader'" \
    --query "value[0].id" -o tsv --only-show-errors 2>/dev/null || true)

  if [ -z "$ROLE_ID" ] || [ "$ROLE_ID" = "null" ]; then
    echo "  role not activated in this tenant; activating from its template"
    TEMPLATE_ID=$(az rest --method GET \
      --url "https://graph.microsoft.com/v1.0/directoryRoleTemplates?\$filter=displayName eq 'Security Reader'" \
      --query "value[0].id" -o tsv --only-show-errors)
    if [ "$DRY_RUN" = "true" ]; then
      echo "  + WOULD activate role template $TEMPLATE_ID"
      ROLE_ID=""
    else
      ROLE_ID=$(az rest --method POST \
        --url "https://graph.microsoft.com/v1.0/directoryRoles" \
        --headers "Content-Type=application/json" \
        --body "{\"roleTemplateId\":\"$TEMPLATE_ID\"}" \
        --query id -o tsv --only-show-errors)
    fi
  fi

  if [ -n "$ROLE_ID" ]; then
    MEMBER=$(az rest --method GET \
      --url "https://graph.microsoft.com/v1.0/directoryRoles/$ROLE_ID/members" \
      --query "value[?id=='$PRINCIPAL_ID'].id | [0]" -o tsv --only-show-errors 2>/dev/null || true)
    if [ -n "$MEMBER" ] && [ "$MEMBER" != "null" ]; then
      echo "  = already a member"
    elif [ "$DRY_RUN" = "true" ]; then
      echo "  + WOULD add the managed identity as a member"
    else
      az rest --method POST \
        --url "https://graph.microsoft.com/v1.0/directoryRoles/$ROLE_ID/members/\$ref" \
        --headers "Content-Type=application/json" \
        --body "{\"@odata.id\":\"https://graph.microsoft.com/v1.0/directoryObjects/$PRINCIPAL_ID\"}" \
        --output none --only-show-errors
      echo "  + added as a member"
    fi
  fi
else
  echo
  echo "Skipped the required Entra 'Security Reader' directory role (--skip-entra-security-reader)."
  echo "  Confirm it is already granted through another controlled path before using Sentinel MCP."
fi

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
echo
echo "Azure RBAC assignments now held by this identity:"
for scope in "${SCOPES[@]}"; do
  az role assignment list --subscription "$WS_SUB" --scope "$scope" \
    --query "[?principalId=='$PRINCIPAL_ID'].{role:roleDefinitionName, scope:scope}" \
    -o table --only-show-errors
done

cat <<'NOTE'

Still required, and NOT assignable with Azure RBAC:

  Security Copilot Contributor - the Entity Analyzer consumes SCUs, and that role gates it.
    Security Copilot RBAC is managed inside Security Copilot, not Entra or Azure. Its documented
    assignment flow accepts users and groups only, so add this managed identity's service
    principal to a Microsoft Entra security group and assign that group the role:
      Security Copilot portal > Role assignment > Add members > pick the group > Copilot contributor
    Microsoft does not document service principal support here - confirm the member picker
    accepts the group, and that the first analyzer run succeeds, before relying on it.
NOTE
