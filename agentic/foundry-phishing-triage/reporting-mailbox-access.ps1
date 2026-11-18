<#
.SYNOPSIS
  Lets the Function managed identity read ONLY the Defender reporting mailbox (Exchange Application RBAC).

.DESCRIPTION
  Preview by default; -Apply makes the changes. Registers the Function identity in Exchange, creates a
  management scope for the reporting mailbox and assigns 'Application Mail.Read' limited to that scope.
  Never grants tenant-wide Graph Mail.Read.

.PARAMETER FunctionPrincipalId
  Object ID of the Function managed identity. Optional: defaults to FUNCTION_PRINCIPAL_ID from deployment.env.

.PARAMETER MailboxUpn
  Reporting mailbox. Defaults to the mailbox configured in Defender user reported settings (SentTo).

.PARAMETER ControlMailboxUpn
  Optional. Any OTHER existing Exchange Online mailbox in the tenant (a colleague, shared or test
  mailbox). If omitted, the script picks one automatically (first other user or shared mailbox). Used only as a negative test: after the grant, the script checks that the Function can
  NOT read this mailbox, proving the scope works. Nothing is granted on it and nothing in it is read.
  Find candidates with: Get-EXOMailbox -ResultSize 10 | Select-Object PrimarySmtpAddress

.PARAMETER Apply
  Make the changes. Without it, the script only previews.

.PARAMETER UseDeviceCode
  Device-code sign-in for Exchange Online. Interactive sign-in is the default; it falls back to device code
  automatically when interactive sign-in fails. Set EXO_USE_DEVICE_CODE=1 to always use device code (e.g. lab hosts).

.EXAMPLE
  ./reporting-mailbox-access.ps1
  Preview using the configured reporting mailbox.

.EXAMPLE
  ./reporting-mailbox-access.ps1 -Apply
  Apply; the control mailbox is picked automatically (or pass -ControlMailboxUpn).
#>
param(
  # Default: FUNCTION_PRINCIPAL_ID from deployment.env.
  [string]$FunctionPrincipalId,
  # Defaults to the reporting mailbox configured in Defender user reported settings (SentTo).
  [string]$MailboxUpn,
  # Any OTHER mailbox, used only to verify the Function can NOT read it. Auto-selected if omitted.
  [string]$ControlMailboxUpn,
  [switch]$Apply,
  # Fallback for hosts where no browser can open (e.g. WSL). Interactive sign-in is the default.
  [switch]$UseDeviceCode
)
$ErrorActionPreference = 'Stop'
# Without -FunctionPrincipalId, take the Function managed identity from deployment.env (written by deploy.ps1).
if (-not $FunctionPrincipalId) {
  $envFile = Join-Path $PSScriptRoot 'deployment.env'
  if (Test-Path -LiteralPath $envFile) {
    $line = Get-Content -LiteralPath $envFile | Where-Object { $_ -match '^\s*FUNCTION_PRINCIPAL_ID=(.+)$' } | Select-Object -First 1
    if ($line -match '^\s*FUNCTION_PRINCIPAL_ID=(.+)$') { $FunctionPrincipalId = $Matches[1].Trim() }
  }
  if (-not $FunctionPrincipalId) { throw 'No -FunctionPrincipalId given and no FUNCTION_PRINCIPAL_ID in deployment.env - run deploy.ps1 first or pass the object ID.' }
  Write-Host "Function managed identity from deployment.env: $FunctionPrincipalId" -ForegroundColor DarkGray
}

# Run as an Exchange Online administrator. This creates Exchange Application RBAC only;
# it deliberately does NOT assign Microsoft Graph Mail.Read in Entra, which would bypass
# the mailbox scope. Default behavior is preview-only; pass -Apply to make the grants.
# Graph lookups use the current Azure CLI login (az rest); Exchange needs ExchangeOnlineManagement.

function Write-Step([string]$Text) { Write-Host ''; Write-Host $Text -ForegroundColor Magenta }
function Write-Ok([string]$Text) { Write-Host '  [+] ' -ForegroundColor Green -NoNewline; Write-Host $Text }
function Write-Same([string]$Text) { Write-Host '  [=] ' -ForegroundColor DarkGray -NoNewline; Write-Host $Text -ForegroundColor DarkGray }
function Write-Plan([string]$Text) { Write-Host '  [~] ' -ForegroundColor Cyan -NoNewline; Write-Host $Text }
function Write-Warn([string]$Text) { Write-Host '  [!] ' -ForegroundColor Yellow -NoNewline; Write-Host $Text -ForegroundColor Yellow }

$graph = 'https://graph.microsoft.com/v1.0'
function Invoke-Graph([string]$Url) {
  $out = az rest --method GET --url $Url --output json --only-show-errors
  if ($LASTEXITCODE -ne 0) { throw "Graph GET $Url failed." }
  ($out -join "`n") | ConvertFrom-Json
}

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
  Write-Host "Installing required PowerShell module 'ExchangeOnlineManagement' for the current user..."
  Install-Module -Name ExchangeOnlineManagement -Repository PSGallery -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

$account = az account show --query user.name --output tsv --only-show-errors
if ($LASTEXITCODE -ne 0) { throw 'Not logged in to Azure CLI. Run az login first.' }
Write-Host 'Azure CLI login (Graph): ' -NoNewline; Write-Host $account -ForegroundColor Cyan

# Exchange sessions live only in the current PowerShell process. Reuse one only if it is
# actually connected; a broken/expired connection object otherwise fails on first cmdlet.
$exo = Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Connected' -and $_.TokenStatus -eq 'Active' } | Select-Object -First 1
if (-not $exo) {
  Get-ConnectionInformation -ErrorAction SilentlyContinue | ForEach-Object { Disconnect-ExchangeOnline -ConnectionId $_.ConnectionId -Confirm:$false -ErrorAction SilentlyContinue }
  # Interactive by default; device code with -UseDeviceCode or EXO_USE_DEVICE_CODE=1, and as automatic
  # fallback when the interactive sign-in fails (no browser, e.g. WSL / lab hosts).
  $useDevice = $UseDeviceCode -or $env:EXO_USE_DEVICE_CODE -in '1', 'true', 'yes'
  if ($useDevice) {
    Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
  } else {
    try { Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop }
    catch {
      Write-Host "  Interactive sign-in failed ($($_.Exception.Message.Split([Environment]::NewLine)[0])) - falling back to device code." -ForegroundColor Yellow
      Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
    }
  }
  $exo = Get-ConnectionInformation | Where-Object { $_.State -eq 'Connected' } | Select-Object -First 1
}
if (-not $exo) { throw 'Exchange Online sign-in did not complete.' }
Write-Host 'Exchange Online:         ' -NoNewline; Write-Host "$($exo.UserPrincipalName) ($($exo.TenantID))" -ForegroundColor Cyan

# --- Defender user reported settings: which reporting mailbox is configured?
Write-Step 'Defender user reported settings'
$policy = Get-ReportSubmissionPolicy -ErrorAction SilentlyContinue
$rule = Get-ReportSubmissionRule -ErrorAction SilentlyContinue
$configured = if ($rule -and $rule.SentTo) { @($rule.SentTo)[0].ToString() } else { '' }
if (-not $policy) {
  Write-Warn 'No report submission policy. Open https://security.microsoft.com/securitysettings/userSubmission once to create it.'
} elseif (-not $policy.ReportPhishToCustomizedAddress) {
  Write-Warn 'Reported phish is not sent to a reporting mailbox (Microsoft only).'
}
if ($configured) {
  Write-Ok "Reporting mailbox: $configured (rule $($rule.Name), state $($rule.State))"
} else {
  Write-Warn 'No reporting mailbox rule. Blank means the global admin mailbox is used; configure a dedicated mailbox instead.'
}
if ([string]::IsNullOrWhiteSpace($MailboxUpn)) {
  if (-not $configured) { throw 'No -MailboxUpn given and no reporting mailbox configured in Defender.' }
  $MailboxUpn = $configured
  Write-Plan "Using configured reporting mailbox: $MailboxUpn"
} elseif ($configured -and $MailboxUpn -ne $configured) {
  Write-Warn "-MailboxUpn '$MailboxUpn' differs from the Defender reporting mailbox '$configured'."
}

# --- Function identity and guard against tenant-wide Graph mail roles (via az rest).
Write-Step 'Function identity'
$mi = Invoke-Graph "$graph/servicePrincipals/$FunctionPrincipalId`?`$select=id,appId,displayName"
if (-not $mi) { throw "Function managed-identity service principal not found: $FunctionPrincipalId" }
Write-Ok "$($mi.displayName) (appId $($mi.appId))"
$mailbox = Get-EXOMailbox -Identity $MailboxUpn -Properties PrimarySmtpAddress
if (-not $mailbox) { throw "Reporting mailbox not found: $MailboxUpn" }
if ([string]::IsNullOrWhiteSpace($ControlMailboxUpn)) {
  # Auto-pick another user/shared mailbox as the negative test. Nothing is granted on it or read from it.
  $candidate = Get-EXOMailbox -ResultSize 50 -RecipientTypeDetails UserMailbox,SharedMailbox -Properties PrimarySmtpAddress |
    Where-Object { $_.PrimarySmtpAddress -ne $mailbox.PrimarySmtpAddress } | Select-Object -First 1
  if ($candidate) {
    $ControlMailboxUpn = $candidate.PrimarySmtpAddress.ToString()
    Write-Plan "Control mailbox (auto-selected, negative test only): $ControlMailboxUpn"
  } elseif ($Apply) {
    throw ("-Apply needs a control mailbox: any OTHER existing mailbox, used only to verify the Function can NOT read it. " +
           "None was found automatically; pass -ControlMailboxUpn.")
  }
}

# An Entra Graph mail app role would bypass Exchange Application RBAC scoping.
$filterQuery = [uri]::EscapeDataString("appId eq '00000003-0000-0000-c000-000000000000'")
$graphApi = @((Invoke-Graph "$graph/servicePrincipals?`$filter=$filterQuery&`$select=id,appRoles").value) | Select-Object -First 1
if (-not $graphApi) { throw 'Microsoft Graph service principal was not found; cannot check for broad mail permissions.' }
$broadMailRoleIds = @($graphApi.appRoles | Where-Object {
  $_.value -in @('Mail.Read','Mail.ReadBasic.All','Mail.ReadWrite','Mail.ReadWrite.All') -and $_.allowedMemberTypes -contains 'Application'
} | ForEach-Object { $_.id })
$broadMailAssignments = @((Invoke-Graph "$graph/servicePrincipals/$FunctionPrincipalId/appRoleAssignments").value | Where-Object {
  $_.resourceId -eq $graphApi.id -and $_.appRoleId -in $broadMailRoleIds
})
if ($broadMailAssignments.Count -gt 0) {
  throw 'The Function identity already has a tenant-wide Microsoft Graph mail application role. Remove that grant before enabling reporting-mailbox access; Exchange RBAC scope cannot constrain it.'
}
Write-Ok 'No tenant-wide Graph mail roles on the Function identity.'

# --- Exchange Application RBAC scoped to the reporting mailbox.
Write-Step 'Exchange Application RBAC'
$scopeName = 'PhishingTriage-ReportingMailbox'
$assignmentName = 'PhishingTriage-ReportingMailbox-MailRead'
$smtpAddress = $mailbox.PrimarySmtpAddress.ToString().Replace("'", "''")
$filter = "PrimarySmtpAddress -eq '$smtpAddress'"

# Exchange Get-ServicePrincipal has no -ResultSize; look up by AppId and treat "not found" as $null.
# Never pass an empty Identity: Exchange then returns all service principals.
function Get-ExoServicePrincipal([string]$AppId) {
  if ([string]::IsNullOrWhiteSpace($AppId)) { throw 'AppId is empty.' }
  try { Get-ServicePrincipal -Identity $AppId -ErrorAction Stop } catch { $null }
}
$exoSp = Get-ExoServicePrincipal $mi.appId
if ($exoSp) {
  Write-Same 'Function identity already registered in Exchange.'
} else {
  Write-Plan "Register Function identity in Exchange: AppId=$($mi.appId), ObjectId=$($mi.id)"
  if ($Apply) {
    New-ServicePrincipal -AppId $mi.appId -ObjectId $mi.id -DisplayName "Phishing Triage Function ($($mi.displayName))" | Out-Null
    $exoSp = Get-ExoServicePrincipal $mi.appId
    Write-Ok 'Registered.'
  }
}

$scope = Get-ManagementScope -Identity $scopeName -ErrorAction SilentlyContinue
if ($scope) {
  if ($scope.RecipientFilter -ne $filter) { throw "Scope '$scopeName' already exists with a different recipient filter; inspect it and resolve manually." }
  Write-Same "Scope '$scopeName' already exists and matches: $filter"
} else {
  Write-Plan "Create scope '$scopeName' with recipient filter: $filter"
  if ($Apply) { $scope = New-ManagementScope -Name $scopeName -RecipientRestrictionFilter $filter; Write-Ok 'Scope created.' }
}

$assignment = Get-ManagementRoleAssignment -Identity $assignmentName -ErrorAction SilentlyContinue
if ($assignment) {
  if ($assignment.CustomResourceScope -ne $scopeName -or $assignment.Role -ne 'Application Mail.Read') {
    throw "Role assignment '$assignmentName' already exists with unexpected role/scope; inspect manually."
  }
  Write-Same 'Scoped Application Mail.Read assignment already exists.'
} else {
  Write-Plan "Assign 'Application Mail.Read' to the Function service principal, scoped to '$scopeName'."
  if ($Apply) {
    if (-not $exoSp) { throw 'Exchange service principal registration was not created.' }
    New-ManagementRoleAssignment -Name $assignmentName -Role 'Application Mail.Read' -App $exoSp.Identity -CustomResourceScope $scopeName | Out-Null
    Write-Ok 'Role assigned.'
  }
}

Write-Host ''
if ($Apply) {
  Write-Step 'Validation'
  $targetCheck = Test-ServicePrincipalAuthorization -Identity $mi.appId -Resource $mailbox.PrimarySmtpAddress
  $targetCheck | Format-Table RoleName,GrantedPermissions,AllowedResourceScope,InScope -AutoSize
  $mailReadTarget = $targetCheck | Where-Object { $_.RoleName -eq 'Application Mail.Read' -and $_.InScope -eq $true }
  if (-not $mailReadTarget) { throw 'Exchange authorization check did not show Application Mail.Read in scope for the reporting mailbox.' }
  Write-Ok "Application Mail.Read in scope for $($mailbox.PrimarySmtpAddress)"
  if (-not [string]::IsNullOrWhiteSpace($ControlMailboxUpn)) {
    $control = Get-EXOMailbox -Identity $ControlMailboxUpn -Properties PrimarySmtpAddress
    if ($control.PrimarySmtpAddress -eq $mailbox.PrimarySmtpAddress) { throw 'ControlMailboxUpn must be different from the reporting mailbox.' }
    $controlCheck = Test-ServicePrincipalAuthorization -Identity $mi.appId -Resource $control.PrimarySmtpAddress
    $controlCheck | Format-Table RoleName,GrantedPermissions,AllowedResourceScope,InScope -AutoSize
    if ($controlCheck | Where-Object { $_.RoleName -eq 'Application Mail.Read' -and $_.InScope -eq $true }) {
      throw 'Application Mail.Read is unexpectedly in scope for the control mailbox; review all Exchange and Entra grants.'
    }
    Write-Ok "Control mailbox $($control.PrimarySmtpAddress) is out of scope."
  }
  Write-Host 'Allow time for Exchange RBAC propagation (30 min to 2 h). No Entra Graph Mail.Read app role was assigned.' -ForegroundColor Yellow
  Write-Host "Set REPORTING_MAILBOX_UPN=$($mailbox.PrimarySmtpAddress) and redeploy so the Function uses this mailbox." -ForegroundColor Yellow
} else {
  Write-Host 'Preview only. Review the exact mailbox/scope, then rerun with -Apply.' -ForegroundColor Yellow
}
