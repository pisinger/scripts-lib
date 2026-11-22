# Hunting Microsoft Entra agent identities with KQL

Queries for Defender Advanced Hunting that give visibility into Microsoft Entra Agent ID activity: which agents are active, what they reach, what they change, and when they fail. Every query in this file ran against my own tenant with recently created agents, and the findings and sample output come from there. Names and IDs in the sample output are generalized.

## How the agents show up in telemetry

| Table | What it tells you about agents | Where it lives |
| --- | --- | --- |
| `AADServicePrincipalSignInLogs` | Agent identity token requests. The `Agent` column marks them with `agentType = agenticAppInstance` and `parentAppId` = the blueprint app ID. | Sentinel workspace table |
| `AADNonInteractiveUserSignInLogs` | Agent user sign-ins. The `Agent` column carries `agentSubjectType = agentIDuser` and `agentSubjectParentId` = the parent agent identity. | Sentinel workspace table |
| `GraphAPIAuditEvents` | Every Graph call: method, URI, status (string), scopes, caller (`ApplicationId` / `ServicePrincipalId` for agent identities, `AccountObjectId` for agent users). Used by queries 8 to 10, 38 and 39. | Defender XDR |
| `MicrosoftGraphActivityLogs` | Same Graph calls in the Sentinel workspace (`AppId`, `UserId`, numeric `ResponseStatusCode`, `TimeGenerated`). Fallback only; coverage matched `GraphAPIAuditEvents`. | Sentinel workspace table |
| `EntraIdSpnSignInEvents` | Agent identity sign-ins in the Defender XDR schema. No agent marker, and `ServicePrincipalId` is a `\|\|` joined string whose first element is the object ID. Also shows the AI gateway path: tokens requested for `Azure AI Gateway`, and the gateway's managed identity calling the model backend (query 55). | Defender XDR |
| `EntraIdSignInEvents` | Agent user sign-ins in the Defender XDR schema. No agent marker. | Defender XDR |
| `CloudAppEvents` | Agent lifecycle audit events, permission grants, Azure role assignment writes, Security Copilot tool runs, and Agent 365 runtime events for Foundry, Copilot Studio and Security Copilot agents: `InvokeAgent` (caller, target agent, content filter result), `ExecuteToolBySDK` / `ExecuteToolByGateway` (tool, tool type), `InferenceCall` (model; a gateway-routed call names it `<gateway>/<backend>/<deployment>`), `AISpanOutput`, and `CopilotInteraction` (Copilot turns, the files and sites agents read with their sensitivity label, jailbreak verdicts). `AgentPlatform` names the host. | Defender XDR |
| `AADManagedIdentitySignInLogs` | Foundry project managed identities (`<account>/projects/<project>`), which carry the outbound calls of agents that do not use their own agent identity. | Sentinel workspace table |
| `AlertInfo`, `AlertEvidence` | Alerts that involve agents: `EntityType == "AIAgent"` with `AgentId`, `AgentName` and `HostingPlatformType` in `AdditionalFields`, agent users as account evidence, MITRE ATLAS techniques in `AttackTechniques`. Defender for AI Services alerts (Prompt Shields, ASCII smuggling) name the model account as `CloudResource` evidence instead of the agent (query 56). First choice for alert hunting. No alert status. | Defender XDR |
| `SecurityCaseEvent` | Change log of Defender incident cases: every created case, property change (status, classification, determination, assignment, tags, closing notes) and comment, with previous and new values and who made the change. The case's `Create` event carries the Defender incident ID. `EventTime` is when the change happened, `TimeGenerated` when it was ingested. [Reference](https://learn.microsoft.com/azure/azure-monitor/reference/tables/securitycaseevent) | Sentinel workspace table (SecurityInsights solution) |
| `SecurityAlert`, `SecurityIncident` | Alert and incident status (New, Resolved, Closed), classification, who closed it, and timestamps. `SecurityIncident` stores several versions per incident. | Sentinel workspace table |
| `BehaviorAnalytics`, `Anomalies` | UEBA. Agent identity logons appear as "Service Principal" logons with first-time-country, first-time-ISP and first-time-action flags. The agent ID sits in `UsersInsights`. | Sentinel workspace table |
| `BehaviorInfo`, `BehaviorEntities` | Defender behaviors (aggregated product detections), including Prompt Shield jailbreak blocks on AI agents. The agent is named in `BehaviorInfo.AdditionalFields`; there is no agent entity type. | Defender XDR |
| `AADRiskyAgents`, `AADAgentRiskEvents` | Entra ID Protection agent risk: risk level, risk state, risk detail, and the individual detections. | Sentinel workspace table (needs the Entra risk diagnostic setting) |
| `AgentsInfo` | Defender's AI agent inventory. `RiskIndicators` holds the active risk indicators with severity. `EntraAgentID` joins to the agent identity. Replaces `AIAgentsInfo`. | Defender XDR |
| `IdentityInfo` | Account-level `RiskLevel`, `RiskScore` and `CriticalityLevel`. | Defender XDR |

The tables `AADRiskyServicePrincipals` and `AADServicePrincipalRiskEvents` had no agent rows: agent risk is in `AADRiskyAgents` and `AADAgentRiskEvents`. `CopilotActivity` existed in the workspace but held no rows at all, because its Sentinel connector was not sending data; the Copilot interactions were in `CloudAppEvents` (`ActionType == "CopilotInteraction"`) instead. 

## Run the queries

- Advanced Hunting (Defender portal) or `POST /v1.0/security/runHuntingQuery` (`ThreatHunting.Read.All`).
- Prefer Defender XDR tables (`AlertInfo`, `AlertEvidence`, `GraphAPIAuditEvents`, `CloudAppEvents`) where they hold the data. Workspace tables (`AAD*`, `MicrosoftGraphActivityLogs`, `SecurityAlert`, `SecurityIncident`) only work when the Sentinel workspace is connected to Defender. They use `TimeGenerated`. Defender XDR tables use `Timestamp`.
- Advanced Hunting keeps 30 days. The hunting API throttles at 45 calls per minute per tenant.
- Replace the `<...>` placeholders.
- For a complementary, investigation-oriented take on the same agent runtime data, including prompt and reply content from the Agent 365 observability data lake table, see the [ai-agent-activity skill](https://github.com/SCStelz/security-investigator/blob/main/.github/skills/ai-agent-activity/SKILL.md) in SCStelz's security-investigator repository. To get agent identity and agent user object IDs, run `audit-AgentAccess.sh` or the Graph list calls from the blog post.

---

## A. Find the agents

### 1. Agent identities seen signing in

Every agent identity that requested a token, with its blueprint, sign-in volume, number of distinct resources and IPs, and failures.

```kql
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(30d)
| extend A = todynamic(Agent)
| where A.agentType == "agenticAppInstance"
| summarize SignIns = count(), Resources = dcount(ResourceDisplayName), ResourceNames = make_set(ResourceDisplayName, 10),
    IPs = dcount(IPAddress), Failures = countif(ResultType != "0"), LastSeen = max(TimeGenerated)
    by ServicePrincipalName, AgentId = ServicePrincipalId, BlueprintAppId = tostring(A.parentAppId)
| order by SignIns desc
```

Look for: agents you did not expect, blueprints with many instances, a high `IPs` count for a single agent, and resources that do not match the agent's purpose. `ResourceNames` lists up to 10 resources each agent identity requested tokens for. Raise the limit in `make_set` if an agent touches more.

Sample output:

```text
ServicePrincipalName   AgentId       BlueprintAppId  SignIns  Resources  ResourceNames                                                                  IPs  Failures
Contoso Recon Agent    11111111-...  22222222-...    23       7          ["Microsoft Graph","Azure Resource Manager","Azure Key Vault","Azure Storage",...]  1    0
Contoso Triage Agent   11111111-...  22222222-...    22       1          ["AAD Token Exchange Endpoint: Public"]                                        4    0
Contoso HR Helper      11111111-...  22222222-...    2        1          ["Bot Framework"]                                                              1    2
```

### 2. Agent users seen signing in

Agent users sign in non-interactively and far more often than their identities. Their volume is the first thing to look at.

```kql
let identityNames = AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(30d)
    | extend A = todynamic(Agent)
    | where A.agentType == "agenticAppInstance"
    | summarize SignInName = take_any(ServicePrincipalName) by ParentAgentId = ServicePrincipalId;
let inventoryNames = AgentsInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp, Name) by ParentAgentId = EntraAgentID
    | project ParentAgentId, InventoryName = Name;
let failures = AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(14d)
    | extend A = todynamic(Agent)
    | where A.agentSubjectType == "agentIDuser" and ResultType != "0"
    | summarize Count = count(), LastFailure = max(TimeGenerated)
        by AgentUserId = UserId, Code = ResultType, FailedResource = ResourceDisplayName,
           App = AppDisplayName, Reason = substring(tostring(ResultDescription), 0, 110)
    | order by Count desc
    | summarize FailureDetails = make_list(bag_pack("code", Code, "resource", FailedResource, "app", App,
        "count", Count, "last", LastFailure, "reason", Reason), 5) by AgentUserId;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d)
| extend A = todynamic(Agent)
| where A.agentSubjectType == "agentIDuser"
| summarize SignIns = count(), Resources = dcount(ResourceDisplayName), ResourceNames = make_set(ResourceDisplayName, 10),
    IPs = dcount(IPAddress), Failures = countif(ResultType != "0"), LastSeen = max(TimeGenerated)
    by UserPrincipalName, AgentUserId = UserId, ParentAgentId = tostring(A.agentSubjectParentId)
| join kind=leftouter identityNames on ParentAgentId
| join kind=leftouter inventoryNames on ParentAgentId
| join kind=leftouter failures on AgentUserId
| project AgentName = coalesce(SignInName, InventoryName, "(name not found)"), ParentAgentId,
    UserPrincipalName, AgentUserId, SignIns, Resources, ResourceNames, IPs, Failures, FailureDetails, LastSeen
| order by Failures desc, SignIns desc
```

`FailureDetails` holds up to 5 failure groups per agent user, biggest first. Each group says which error code (`code`), which resource the token request was for (`resource`), which app made the request (`app`), how often (`count`), when it last happened (`last`), and the error text (`reason`). The failure count from `Failures` equals the sum of the `count` values across all groups, so a user with more than 5 groups shows only the top 5. For one row per failure that is easier to sort and filter, use query 2b.

`AgentName` is the display name of the parent agent identity. The sign-in logs only carry the parent ID on the agent user's side, so the query looks the name up in two places: the agent identity's own sign-ins (`AADServicePrincipalSignInLogs`) and the Defender agent inventory (`AgentsInfo`, joined on `EntraAgentID`). The inventory is the fallback for agents whose identity did not sign in during the last 30 days. If neither has the agent, the name shows `(name not found)`, and the parent ID still lets you look it up with the Graph calls from the blog post.

`ResourceNames` lists up to 10 of the resources each agent user requested tokens for, so you can see what it reached and not only how many. Raise the limit in `make_set` if an agent touches more.

Sample output:

```text
AgentName            ParentAgentId  UserPrincipalName               AgentUserId   SignIns  Resources  ResourceNames                                                                       IPs  Failures
Contoso Triage Agent 11111111-...   agentuser-aaaa@contoso.example  44444444-...  61581    11         ["Microsoft Graph","Azure Purview","WindowsDefenderATP","Security Copilot API",...]  5    35
Contoso Recon Agent  11111111-...   agentuser-bbbb@contoso.example  44444444-...  14632    11         ["Azure Purview","WindowsDefenderATP","Sentinel Platform Services",...]             1    0
Contoso Main Agent   11111111-...   agentuser-cccc@contoso.example  44444444-...  7098     2          ["Azure Purview","Security Copilot API"]                                            1    0
```

### 2b. Why and where agent users fail

One row per agent user, error code, resource and app, with a plain-language `Meaning` column for the common codes. This answers what failed (the resource and the app) and why (the code, the meaning and the raw reason), not only how many.

```kql
let identityNames = AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(30d)
    | extend A = todynamic(Agent)
    | where A.agentType == "agenticAppInstance"
    | summarize SignInName = take_any(ServicePrincipalName) by ParentAgentId = ServicePrincipalId;
let inventoryNames = AgentsInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp, Name) by ParentAgentId = EntraAgentID
    | project ParentAgentId, InventoryName = Name;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d)
| extend A = todynamic(Agent)
| where A.agentSubjectType == "agentIDuser" and ResultType != "0"
| summarize Failures = count(), FirstFailure = min(TimeGenerated), LastFailure = max(TimeGenerated), IPs = dcount(IPAddress)
    by UserPrincipalName, ParentAgentId = tostring(A.agentSubjectParentId), ResultType,
       FailedResource = ResourceDisplayName, App = AppDisplayName, Reason = substring(tostring(ResultDescription), 0, 140)
| join kind=leftouter identityNames on ParentAgentId
| join kind=leftouter inventoryNames on ParentAgentId
| extend Meaning = case(
    ResultType == "65001", "Consent missing: an admin must grant consent, retrying will not help",
    ResultType == "700081", "Refresh token reached its maximum lifetime: the agent must sign in again",
    ResultType == "53003", "Blocked by Conditional Access",
    ResultType in ("50076", "50079", "50074"), "MFA required: an agent cannot answer an MFA prompt",
    ResultType == "50055", "Password expired",
    ResultType == "50057", "Account disabled",
    ResultType == "50126", "Invalid credentials",
    strcat("See https://login.microsoftonline.com/error?code=", ResultType))
| project AgentName = coalesce(SignInName, InventoryName, "(name not found)"), UserPrincipalName, ResultType, Meaning,
    FailedResource, App, Failures, FirstFailure, LastFailure, IPs, Reason
| order by Failures desc
```

Sample output:

```text
AgentName             ResultType  Meaning                                                          FailedResource              Failures  FirstFailure          LastFailure
Contoso Helper Agent  65001       Consent missing: an admin must grant consent, retrying will...   SecOps for Security Copilot 382       2026-10-28T09:21:17Z  2026-11-04T09:46:47Z
Contoso Helper Agent  65001       Consent missing: an admin must grant consent, retrying will...   Microsoft Graph             304       2026-10-28T09:21:22Z  2026-11-04T09:39:42Z
Contoso Triage Agent  700081      Refresh token reached its maximum lifetime: the agent must...    Security Copilot API        35        2026-10-27T06:08:31Z  2026-11-03T10:55:15Z
```

Notes on reading it:

- `FailedResource` is the API the token was requested for. `App` is the application making the request, which for agents is usually the agent's own app. In the sample, one agent was blocked from two resources for the same reason.
- `Reason` is the error text from the log. Entra often leaves placeholders such as `{identifier}` or `{issueDate}` unfilled, so it explains the category but not the specific value. The code and the resource carry the useful detail.
- The `Meaning` mapping covers the codes I saw (`65001`, `700081`) plus common authentication codes. The codes `53003`, `50076`, `50079`, `50074`, `50055`, `50057` and `50126` did not occur, so those mappings are not exercised there. Extend the `case` for codes you see.
- A steady count for one code, resource and agent is an operational fault. A sudden spread of different codes or resources for one agent is the pattern to investigate.

### 3. Agent identity, agent user and blueprint from telemetry alone

A full outer join, so an agent identity with no agent user (and the reverse) shows up as a blank column.

```kql
let identities = AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(30d)
    | extend A = todynamic(Agent)
    | where A.agentType == "agenticAppInstance"
    | summarize IdentitySignIns = count(), IdentityLast = max(TimeGenerated)
        by AgentName = ServicePrincipalName, AgentId = ServicePrincipalId, BlueprintAppId = tostring(A.parentAppId);
let users = AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(30d)
    | extend A = todynamic(Agent)
    | where A.agentSubjectType == "agentIDuser"
    | summarize UserSignIns = count(), UserLast = max(TimeGenerated)
        by AgentUserUpn = UserPrincipalName, ParentAgentId = tostring(A.agentSubjectParentId);
identities
| join kind=fullouter users on $left.AgentId == $right.ParentAgentId
| project AgentName, AgentId = coalesce(AgentId, ParentAgentId), BlueprintAppId, AgentUserUpn,
    IdentitySignIns, UserSignIns, IdentityLast, UserLast
| order by coalesce(IdentitySignIns, 0) + coalesce(UserSignIns, 0) desc
```

The agent user had hundreds to thousands of times more sign-ins than its agent identity (for example 22 identity sign-ins against about 149,000 user sign-ins). Hunting on the identity alone would miss almost all the activity.

### 4. Defender XDR schema fallback

Use this when the workspace tables are not available. The XDR table has no agent marker, so it needs a list of known agent identity object IDs. Do not detect agents by `\|\|` in `ServicePrincipalId`: managed identities use the same format.

```kql
let agentIds = dynamic(["<agent identity object ID>"]);
EntraIdSpnSignInEvents
| where Timestamp > ago(30d)
| extend AgentId = tostring(split(ServicePrincipalId, "||")[0])
| where AgentId in (agentIds)
| summarize SignIns = count(), Resources = make_set(ResourceDisplayName, 6), LastSeen = max(Timestamp)
    by ServicePrincipalName, AgentId
| order by SignIns desc
```

---

## B. What agents reach and where they fail

### 5. Resources an agent requested for the first time

A baseline comparison for established agents, covering both the agent identity and the agent user. Tune `window` and `baseline`; keep them within the 30 days the hunting API keeps. A new resource is the earliest sign that an agent started doing something different, such as a newly granted role or a changed task. Agents with no history before the window are skipped, because everything a new agent does is new.

Both principals matter. The agent user produced almost all of the sign-ins, and a version of this query that only looked at the agent identity missed an agent user that started using five new resources.

```kql
let window = 7d;
let baseline = 23d;
let agentSignIns = union
    (AADServicePrincipalSignInLogs
        | where TimeGenerated > ago(window + baseline)
        | extend A = todynamic(Agent)
        | where A.agentType == "agenticAppInstance"
        | project TimeGenerated, AgentId = ServicePrincipalId, AgentName = ServicePrincipalName, Principal = "identity", ResourceDisplayName),
    (AADNonInteractiveUserSignInLogs
        | where TimeGenerated > ago(window + baseline)
        | extend A = todynamic(Agent)
        | where A.agentSubjectType == "agentIDuser"
        | project TimeGenerated, AgentId = tostring(A.agentSubjectParentId), AgentName = "", Principal = "user", ResourceDisplayName);
let known = agentSignIns
    | where TimeGenerated < ago(window)
    | distinct AgentId, Principal, ResourceDisplayName;
let established = known | summarize by AgentId, Principal;
let names = AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(window + baseline)
    | summarize AgentName = take_any(ServicePrincipalName) by AgentId = ServicePrincipalId;
agentSignIns
| where TimeGenerated >= ago(window)
| join kind=inner established on AgentId, Principal
| join kind=leftanti known on AgentId, Principal, ResourceDisplayName
| summarize FirstSeen = min(TimeGenerated), SignIns = count() by AgentId, Principal, ResourceDisplayName
| join kind=leftouter names on AgentId
| project AgentName = coalesce(AgentName, "(name not found)"), AgentId, Principal, ResourceDisplayName, FirstSeen, SignIns
| order by FirstSeen asc
```

Sample output:

```text
AgentName             AgentId       Principal  ResourceDisplayName                 FirstSeen             SignIns
Contoso Triage Agent  11111111-...  user       Microsoft Exchange Online Protection  2026-11-06T08:40:07Z  14
Contoso Triage Agent  11111111-...  user       M365 Label Analytics                  2026-11-06T08:40:28Z  24
Contoso Triage Agent  11111111-...  user       Microsoft Defender Hunting            2026-11-06T08:41:00Z  68
Contoso Triage Agent  11111111-...  user       Log Analytics API                     2026-11-06T08:42:02Z  26
Contoso Triage Agent  11111111-...  user       Sentinel Platform Services            2026-11-06T08:42:14Z  18
```

All five new resources appeared within about two minutes. The audit trail shows no grant or configuration change at that time. What happened was a real triage job: mail access events (`AdminMailAccess`, `MailItemsAccessed`) and 28 Security Copilot tool runs started minutes earlier, the agent user's daily resource count went from 6 to 11 for that one day, and it fell back to 6 the next day.

So a new resource is a lead, not a verdict. It can be a permission change, a new task or a compromise. Correlate it with the audit events (queries 11 to 13), the tool runs (query 14) and the agent's other signals (query 43) before you decide.

### 6. Failed token requests for agents

Covers agent identities and agent users. The failures were operational, not malicious, and each result type has a different fix.

```kql
union AADServicePrincipalSignInLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(30d)
| extend A = todynamic(Agent)
| where A.agentType == "agenticAppInstance" or A.agentSubjectType == "agentIDuser"
| where ResultType != "0"
| summarize Failures = count(), LastSeen = max(TimeGenerated)
    by Principal = coalesce(ServicePrincipalName, UserPrincipalName), ResultType, ResultDescription, ResourceDisplayName
| order by Failures desc
```

What the codes meant:

| Code | Meaning | Action |
| --- | --- | --- |
| `700081` | The agent user's refresh token expired at its maximum lifetime | The agent stops working until it signs in again. Plan for re-authentication. |
| `65001` | Missing consent for the application | An admin has to consent. Do not retry. |
| `53003` | Blocked by Conditional Access | See query 7. Expected if you built a block policy. |

### 7. Conditional Access impact on agents

Shows which agent sign-ins were evaluated by Conditional Access and which were blocked. This is how you confirm that a policy covers the principal you intended: agent identity policies do not cover agent users.

```kql
union AADServicePrincipalSignInLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(30d)
| extend A = todynamic(Agent)
| where A.agentType == "agenticAppInstance" or A.agentSubjectType == "agentIDuser"
| where ConditionalAccessStatus != "notApplied" or ResultType == "53003"
| summarize SignIns = count(), Blocked = countif(ResultType == "53003"), LastSeen = max(TimeGenerated)
    by Principal = coalesce(ServicePrincipalName, UserPrincipalName), ConditionalAccessStatus, ResourceDisplayName
| order by Blocked desc, SignIns desc
```

Sample output:

```text
Principal            ConditionalAccessStatus  ResourceDisplayName  SignIns  Blocked
Contoso HR Helper    failure                  Bot Framework        2        2
Contoso Recon Agent  success                  Azure Resource Manager  8     0
Contoso Recon Agent  success                  Microsoft Graph      4        0
```

---

## C. What agents do on Microsoft Graph

These queries use the Defender XDR table `GraphAPIAuditEvents`, which is high volume. Keep the time filter. To run them against the Sentinel table `MicrosoftGraphActivityLogs` instead, swap `ApplicationId` for `AppId`, `AccountObjectId` for `UserId` and `Timestamp` for `TimeGenerated`, and drop the `toint()` around `ResponseStatusCode`.

### 8. Graph calls by agent identity

```kql
let agentApps = AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(30d)
    | extend A = todynamic(Agent)
    | where A.agentType == "agenticAppInstance"
    | distinct AppId;
GraphAPIAuditEvents
| where Timestamp > ago(30d)
| where ApplicationId in (agentApps)
| extend Family = extract(@"/(?:v1\.0|beta)/+([^/?]+)", 1, RequestUri)
| summarize Calls = count(), Failed = countif(toint(ResponseStatusCode) >= 400), LastCall = max(Timestamp)
    by AppId = ApplicationId, RequestMethod, Family
| order by Calls desc
```

Sample output:

```text
AppId         RequestMethod  Family            Calls  Failed
11111111-...  GET            servicePrincipals 1263   7
11111111-...  POST           directoryObjects  134    1
11111111-...  GET            roleManagement    24     2
```

The regex tolerates a double slash (`v1.0//servicePrincipals`), which some agent clients send. A regex that expects a single slash puts those calls in an empty family and hides them; for one agent that was 238 of its 1,745 calls. Compare the call families with the permissions the agent holds. An agent that mostly reads `servicePrincipals` and `roleManagement` matches a reconnaissance or posture role. Calls outside its stated purpose are the finding.

### 9. Graph calls by agent user

Agent users call Graph as a user, so they appear under `UserId`. Failure rates and status codes show quota problems and probing.

```kql
let agentUsers = AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(30d)
    | extend A = todynamic(Agent)
    | where A.agentSubjectType == "agentIDuser"
    | distinct UserId;
GraphAPIAuditEvents
| where Timestamp > ago(30d)
| where AccountObjectId in (agentUsers)
| summarize Calls = count(), Failed = countif(toint(ResponseStatusCode) >= 400),
    StatusCodes = make_set(ResponseStatusCode, 6), LastCall = max(Timestamp) by UserId = AccountObjectId
| order by Failed desc
```

Sample output:

```text
UserId        Calls  Failed  StatusCodes
44444444-...  910    162     [429,200,400,500,502,504]
44444444-...  1207   29      [200,404]
44444444-...  11706  7       [200,401,429]
```

A `429` run on `security/runHuntingQuery` is throttling, not an attack. A burst of `401` and `403` across many different paths is worth a closer look.

### 10. Write operations by agents

Everything an agent changed through Graph, by identity or user. The writes were hunting API calls and a read-style batch call, not directory changes.

```kql
let agentApps = AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(30d)
    | extend A = todynamic(Agent)
    | where A.agentType == "agenticAppInstance"
    | distinct AppId;
let agentUsers = AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(30d)
    | extend A = todynamic(Agent)
    | where A.agentSubjectType == "agentIDuser"
    | distinct UserId;
GraphAPIAuditEvents
| where Timestamp > ago(30d)
| where ApplicationId in (agentApps) or AccountObjectId in (agentUsers)
| where RequestMethod in ("POST", "PUT", "PATCH", "DELETE")
| extend Path = extract(@"/(?:v1\.0|beta)/+([^?]+)", 1, RequestUri)
| summarize Calls = count(), Failed = countif(toint(ResponseStatusCode) >= 400), LastCall = max(Timestamp)
    by Caller = iff(isnotempty(AccountObjectId), AccountObjectId, ApplicationId), RequestMethod, Path
| order by Calls desc
```

Sample output:

```text
Caller        RequestMethod  Path                          Calls  Failed
44444444-...  POST           security/runHuntingQuery      412    156
11111111-...  POST           directoryObjects/getByIds     134    1
44444444-...  POST           $batch                        143    0
```

Alert on any write to `servicePrincipals`, `applications`, `groups`, `roleManagement` or `users` by an agent that is not supposed to administer the directory.

---

## D. Lifecycle, permission changes and runtime events (CloudAppEvents)

### 11. Agent lifecycle and access events

Who created the agent, added its user and sponsor, assigned roles, and added group memberships. `RawEventData has_any` is needed because these events carry the agent ID inside the audit payload.

```kql
let agentIds = dynamic(["<agent identity or agent user object ID>"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("Add service principal.", "Add user.", "Add user sponsor.",
    "Add app role assignment to service principal.", "Add member to group.", "Write RoleAssignments")
| where RawEventData has_any (agentIds)
| summarize Events = count(), First = min(Timestamp), Last = max(Timestamp), Actors = make_set(AccountDisplayName, 3)
    by ActionType
| order by First asc
```

Sample output:

```text
ActionType                                        Events  First                 Actors
Add service principal.                            8       2026-11-04T09:26:06Z  ["Security Copilot Agent Management"]
Add user sponsor.                                 15      2026-11-04T09:26:06Z  ["Security Copilot Agent Management"]
Add user.                                         7       2026-11-04T09:26:06Z  ["Security Copilot Agent Management"]
Write RoleAssignments                             34      2026-11-04T09:26:22Z  ["MTP Unified RBAC","Admin User"]
Add app role assignment to service principal.     8       2026-11-04T11:58:11Z  ["Admin User"]
```

The `Write RoleAssignments` rows from "MTP Unified RBAC" show where Defender created Azure roles on Sentinel workspaces for the agent user during setup (see query 13).

### 12. Which permissions were granted to an agent, and by whom

Resolves each app role assignment to the permission name.

```kql
let agentIds = dynamic(["<agent identity object ID>"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "Add app role assignment to service principal."
| extend Mods = parse_json(RawEventData).ModifiedProperties
| mv-apply m = Mods on (summarize Props = make_bag(bag_pack(tostring(m.Name), tostring(m.NewValue))))
| where tostring(Props["ServicePrincipal.ObjectID"]) in (agentIds)
| project Timestamp, GrantedBy = AccountDisplayName,
    Agent = tostring(Props["ServicePrincipal.DisplayName"]), Permission = tostring(Props["AppRole.Value"])
| order by Timestamp asc
```

Sample output:

```text
Timestamp             GrantedBy    Agent                Permission
2026-11-04T11:58:11Z  Admin User   Contoso Recon Agent  User.Read.All
2026-11-04T11:58:12Z  Admin User   Contoso Recon Agent  Organization.Read.All
2026-11-04T11:58:12Z  Admin User   Contoso Recon Agent  RoleManagement.Read.Directory
2026-11-04T11:58:14Z  Admin User   Contoso Recon Agent  DelegatedPermissionGrant.Read.All
```

Pair this with query 8: the grants say what an agent may call, the Graph activity says what it did call. This only sees grants made inside the 30-day hunting window. Grants older than that do not appear, so for an older agent compare with the live assignments from the audit script.

### 13. Azure role assignment writes touching an agent

Shows the scope where an agent identity or agent user received an Azure role.

```kql
let agentIds = dynamic(["<agent identity or agent user object ID>"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "Write RoleAssignments"
| where RawEventData has_any (agentIds)
| extend Scope = tostring(parse_json(tostring(parse_json(RawEventData).authorization)).scope)
| extend Scope = tostring(split(Scope, "/providers/Microsoft.Authorization")[0])
| summarize Writes = count(), LastWrite = max(Timestamp), Writers = make_set(AccountDisplayName, 3) by Scope
| order by Writes desc
```

Sample output:

```text
Scope                                                                                     Writes  Writers
/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<ws>  5  ["MTP Unified RBAC"]
/subscriptions/<sub>                                                                      4       ["Admin User"]
```

### 14. Security Copilot tool runs by agent

What tools agents run, how often they fail, and why. This also shows agent users and human users side by side in one table.

```kql
let agentUpns = AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(30d)
    | extend A = todynamic(Agent)
    | where A.agentSubjectType == "agentIDuser"
    | distinct UserPrincipalName;
let agentNames = AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(30d)
    | extend A = todynamic(Agent)
    | where A.agentType == "agenticAppInstance"
    | distinct ServicePrincipalName;
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "SentinelAIToolRunCompleted"
| extend R = parse_json(RawEventData)
| extend FailureCode = extract(@'"code":"([^"]+)"', 1, tostring(R.FailureReason))
| extend CallerKind = case(AccountDisplayName in~ (agentUpns), "agent user",
    AccountDisplayName in (agentNames), "agent identity", "human or other")
| summarize Runs = count(), Failed = countif(isnotempty(tostring(R.FailureReason))), LastRun = max(Timestamp),
    FailureCodes = make_set_if(FailureCode, isnotempty(FailureCode), 4)
    by Caller = AccountDisplayName, CallerKind, Tool = tostring(R.ToolName)
| extend FailurePct = round(100.0 * Failed / Runs, 0)
| order by Runs desc
```

Sample output:

```text
Caller                Tool                     Runs  Failed  FailureCodes                                          FailurePct
Contoso Hunting Agent RunAdvancedHuntingQuery  307   114     ["CpuQuotaExceeded","BadRequest","TooManyRequests"]    37
agentuser-aaaa@...    RunAdvancedHuntingQuery  76    36      ["CpuQuotaExceeded","BadRequest"]                      47
Admin User            query_lake               70    11      ["SemanticError","UserError","SensitiveOperator"]      16
```

`CallerKind` separates agent identities and agent users from people and unnamed callers, because this table also records human tool runs. Hunting agents were the heaviest users and hit hunting CPU quota in a large share of runs. `SensitiveOperator` failures on a human caller are guardrails working.

### 15. Copilot Studio and platform agent runtime events

Agent invocations and the tools they execute (SharePoint search, mail tools, MCP tools). `AgentBlueprintId` ties each event to a blueprint.

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("InvokeAgent", "ExecuteToolBySDK", "ExecuteToolByGateway")
| extend R = parse_json(RawEventData)
| summarize Events = count(), LastSeen = max(Timestamp),
    Tools = make_set(tostring(R.ToolName), 5), Channels = make_set(tostring(R.ChannelName), 3)
    by ActionType, AgentId = tostring(R.AgentId), AgentName = tostring(R.AgentName),
       BlueprintId = tostring(R.AgentBlueprintId)
| order by Events desc
```

Sample output:

```text
ActionType        AgentId       AgentName          Events  Tools                                         Channels
ExecuteToolBySDK  33333333-...  Contoso HR Helper  146     ["SharepointSiteSearch","mcp_MailTools",...]  ["M365 Copilot","Copilot Studio Test Pane"]
InvokeAgent       0000...0000                      85      [""]                                          ["M365Copilot","agent_service","Autonomous"]
```

Look for mail-sending tools (`SendEmailWithAttachments`) on agents that read untrusted content, and for events whose `AgentId` is the empty GUID (first-party agents that do not report an ID).

### 16. Alerts on AI agents

Security for AI raises alerts with `EntityType == "AIAgent"`, for example prompt injection (XPIA) against a Copilot Studio agent. `AdditionalFields` carries the agent ID and name.

```kql
AlertEvidence
| where Timestamp > ago(30d)
| where EntityType == "AIAgent"
| join kind=inner (AlertInfo | project AlertId, Title, Severity, Category, ServiceSource) on AlertId
| project Timestamp, Title, Severity, Category, ServiceSource, EvidenceRole, AdditionalFields
| order by Timestamp desc
```

Sample output:

```text
Timestamp             Title                                                              Severity       ServiceSource    EvidenceRole
2026-11-07T14:38:16Z  A cross or external prompt injection attack (XPIA) was detected... Informational  Security for AI  Impacted
```

---

## E. Alerts, incidents and closure

These queries answer a different question than the ones above: what Defender thinks is wrong with an agent. They start from the Defender XDR tables `AlertInfo` and `AlertEvidence`. With a connected Sentinel workspace the same alerts are also in `SecurityAlert`, but the XDR tables are the recommended first look: they hold the evidence entities, the agent fields and the techniques in the shape Defender itself uses. Alerts on agents carry an `AIAgent` evidence entity whose `AdditionalFields` holds `AgentId`, `AgentName` and `HostingPlatformType`, so queries 17 to 17c work per agent without any ID list.

Neither XDR table has alert status, classification or closure. Queries 18 to 22 add that from the Sentinel tables `SecurityAlert` and `SecurityIncident`. Use them as the second step, for status and closure, not as the starting point.

### Shared preamble: the set of agent object IDs

Queries 17, 18 to 25 and 31 begin with this block (17a to 17c do not need it). It builds the list of agent identity and agent user object IDs from sign-in telemetry, so you do not have to maintain a list. Paste it at the top of each query below.

```kql
let agentIds = toscalar(
    union
        (AADServicePrincipalSignInLogs
            | where TimeGenerated > ago(30d)
            | extend A = todynamic(Agent)
            | where A.agentType == "agenticAppInstance"
            | distinct Id = ServicePrincipalId),
        (AADNonInteractiveUserSignInLogs
            | where TimeGenerated > ago(30d)
            | extend A = todynamic(Agent)
            | where A.agentSubjectType == "agentIDuser"
            | distinct Id = UserId)
    | summarize make_set(Id));
```

An agent that never signed in during the last 30 days is not in this set, and that includes most Foundry and Copilot Studio agents (query 44). To include those agents, use this Defender XDR variant, or combine it with the one above. It collects agent IDs from Defender's agent inventory, agent alert evidence and agent runtime events, but it has no agent users:

```kql
let agentIds = toscalar(
    union
        (AgentsInfo
            | where isnotempty(EntraAgentID)
            | distinct Id = tostring(EntraAgentID)),
        (AlertEvidence
            | where Timestamp > ago(30d)
            | where EntityType == "AIAgent"
            | distinct Id = tostring(parse_json(AdditionalFields).AgentId)),
        (CloudAppEvents
            | where Timestamp > ago(30d)
            | where ActionType in ("InvokeAgent", "ExecuteToolBySDK", "InferenceCall")
            | extend R = parse_json(RawEventData)
            | distinct Id = coalesce(tostring(R.TargetAgentId), tostring(R.AgentId)))
    | where isnotempty(Id) and Id != "00000000-0000-0000-0000-000000000000"
    | summarize make_set(Id));
```

The XDR variant found 48 agent IDs. The sign-in variant found 16 agent identities and 11 agent users. Combine both when you have the workspace.

### 17. Alerts that involve agents, with statistics

Alerts where an agent is evidence: an `AIAgent` entity, an agent user as an account, or an agent ID in the evidence payload.

```kql
AlertEvidence
| where Timestamp > ago(30d)
| where EntityType == "AIAgent" or AccountObjectId in (agentIds) or OAuthApplicationId in (agentIds)
    or AdditionalFields has_any (agentIds)
| join kind=inner (AlertInfo | project AlertId, Title, Severity, Category, ServiceSource, DetectionSource) on AlertId
| summarize Alerts = dcount(AlertId), FirstAlert = min(Timestamp), LastAlert = max(Timestamp),
    EvidenceRoles = make_set(EvidenceRole, 3), EntityTypes = make_set(EntityType, 4)
    by Title, Severity, ServiceSource, DetectionSource
| order by Alerts desc
```

Sample output:

```text
Title                                               Severity       ServiceSource                    Alerts  EvidenceRoles   EntityTypes
A cross or external prompt injection attack (XPIA)  Informational  Security for AI                  18      ["Impacted"]    ["AIAgent"]
Purview IRM Risky AI Usage - Demo                   Low            Insider Risk Management          1       ["Impacted"]    ["User"]
```

### 17a. Alerts per agent

One row per agent with its alert count, titles, severities, and on how many days it raised alerts. The agent comes from the `AIAgent` evidence, so no ID list is needed.

```kql
let agentAlerts = AlertEvidence
    | where Timestamp > ago(30d)
    | where EntityType == "AIAgent"
    | extend AF = parse_json(AdditionalFields)
    | project AlertId, AgentId = tostring(AF.AgentId), AgentName = tostring(AF.AgentName), Platform = tostring(AF.HostingPlatformType);
agentAlerts
| join kind=inner (AlertInfo | where Timestamp > ago(30d) | summarize arg_min(Timestamp, Title, Severity, Category) by AlertId) on AlertId
| summarize Alerts = dcount(AlertId), Titles = make_set(Title, 5), Severities = make_set(Severity), Categories = make_set(Category),
    ActiveDays = dcount(bin(Timestamp, 1d)), First = min(Timestamp), Last = max(Timestamp)
    by AgentName, AgentId, Platform
| order by Alerts desc
```

Look for: agents with alerts on many separate days (a recurring problem, not one test), a severity above Informational, and agents in production that show up here at all.

Sample output:

```text
AgentName             Platform                Alerts  Titles                                                 Categories     ActiveDays  Last
Contoso HR Helper     MicrosoftCopilotStudio  22      ["A cross or external prompt Injection attack (XPIA)..."]  ["Execution"]  7           2026-11-20
contoso-phish-triage  MicrosoftFoundry        3       ["AI agent reconnaissance activity was detected"]      ["Discovery"]  1           2026-11-18
Contoso HR Autonom    MicrosoftCopilotStudio  4       ["A cross or external prompt Injection attack (XPIA)..."]  ["Execution"]  1           2026-10-26
```

### 17b. Who and what shows up next to the agent in its alerts

The other evidence in alerts that name an agent: the users who talked to it, the IPs, and any devices, mails, URLs, files or apps. This is the pivot from "the agent was attacked" to "by whom, from where".

```kql
let agentAlerts = AlertEvidence
    | where Timestamp > ago(30d)
    | where EntityType == "AIAgent"
    | extend AF = parse_json(AdditionalFields)
    | distinct AlertId, AgentName = tostring(AF.AgentName);
AlertEvidence
| where Timestamp > ago(30d)
| where EntityType != "AIAgent"
| join kind=inner agentAlerts on AlertId
| extend Entity = case(
    EntityType == "User", coalesce(AccountUpn, AccountObjectId, AccountName),
    EntityType == "Ip", RemoteIP,
    EntityType == "Machine", DeviceName,
    EntityType == "Url", RemoteUrl,
    EntityType == "MailMessage", EmailSubject,
    EntityType in ("CloudApplication", "OAuthApplication"), coalesce(Application, tostring(OAuthApplicationId)),
    EntityType == "File", FileName,
    tostring(AdditionalFields))
| summarize Alerts = dcount(AlertId), Agents = make_set(AgentName, 5), Roles = make_set(EvidenceRole), Last = max(Timestamp)
    by EntityType, Entity
| order by Alerts desc
```

Look for: one user who appears across many alerts or several agents, IPs outside your corporate egress, and evidence types other than `User` and `Ip`, which mean the alert reached further than the conversation.

Sample output:

```text
EntityType  Entity               Alerts  Agents                                  Roles         Last
User        user2@contoso.com    17      ["Contoso HR Helper","Contoso HR Demo"]  ["Impacted"]  2026-11-20
Ip          203.0.113.158        12      ["Contoso HR Helper"]                    ["Related"]   2026-11-20
User        analyst@contoso.com  3       ["contoso-phish-triage"]                 ["Impacted"]  2026-11-18
```

### 17c. Attack techniques and repeat alerts per agent

The techniques Defender mapped to each agent's alerts. Security for AI uses MITRE ATLAS IDs (`AML.T....`) rather than ATT&CK. `AlertsLast7d` shows whether the pattern is still active.

```kql
let agentAlerts = AlertEvidence
    | where Timestamp > ago(30d)
    | where EntityType == "AIAgent"
    | extend AF = parse_json(AdditionalFields)
    | distinct AlertId, AgentName = tostring(AF.AgentName);
AlertInfo
| where Timestamp > ago(30d)
| summarize arg_min(Timestamp, Title, Category, AttackTechniques, DetectionSource) by AlertId
| join kind=inner agentAlerts on AlertId
| mv-expand Technique = iff(AttackTechniques == "" or AttackTechniques == "[]", dynamic(["(none)"]), parse_json(AttackTechniques)) to typeof(string)
| summarize Alerts = dcount(AlertId), Titles = make_set(Title, 3), AlertsLast7d = dcountif(AlertId, Timestamp > ago(7d))
    by AgentName, Category, Technique, DetectionSource
| order by Alerts desc
```

Look for: techniques other than prompt injection (`AML.T0051`), reconnaissance (`AML.T0063`, `AML.T0069`) against agents with tool or data access, and `AlertsLast7d` close to `Alerts`, which means the attack is current.

Sample output:

```text
AgentName             Category   Technique      DetectionSource  Alerts  AlertsLast7d
Contoso HR Helper     Execution  AML.T0051.001  Security for AI  22      9
contoso-phish-triage  Discovery  AML.T0063      Security for AI  3       3
contoso-phish-triage  Discovery  AML.T0069      Security for AI  3       3
```

### Second step: status and closure from the Sentinel tables

Start with queries 17 to 17c. Queries 18 to 22b then add what the Defender XDR alert tables lack: alert status, incident status, classification, closing time and who closed. For who changed what over time, prefer `SecurityCaseEvent` (21b, 22b) over the `SecurityIncident` snapshots. They match agents by ID in the alert payload, so they use the sign-in preamble.

### 18. Status of those alerts: resolved, dismissed, new

Counts the latest status per alert, so resolved and closed alerts are included next to open ones. Alerts update over time, so `arg_max` keeps only the newest version.

```kql
SecurityAlert
| where TimeGenerated > ago(30d)
| where tostring(pack_all()) has_any (agentIds)
| summarize arg_max(TimeGenerated, Status, AlertSeverity) by SystemAlertId, AlertName, ProviderName
| summarize Alerts = count(), Latest = max(TimeGenerated) by Status, AlertSeverity, AlertName, ProviderName
| order by Alerts desc
```

Sample output:

```text
Status    AlertSeverity  AlertName                                          ProviderName                         Alerts
Resolved  Informational  A cross or external prompt injection attack (XPIA)  Security for AI                     13
New       Medium         Purview IRM Risky AI Usage - Demo                  Office 365 Security and Compliance   1
New       Low            Purview IRM Test Risky AI usage                    Office 365 Security and Compliance   1
```

Thirteen prompt-injection alerts were Resolved and the Insider Risk alerts were still New. A pile of `New` alerts about agents is a triage gap.

### 19. Incidents that contain agent alerts

The latest version of each incident that contains an agent alert, with status, classification, who last changed it, and when it closed.

```kql
let agentAlerts = SecurityAlert
    | where TimeGenerated > ago(30d)
    | where tostring(pack_all()) has_any (agentIds)
    | distinct SystemAlertId;
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds to typeof(string)
| where AlertId in (agentAlerts)
| summarize AgentAlerts = dcount(AlertId), LastModified = max(LastModifiedTime)
    by IncidentNumber, Title, Severity, Status, Classification, ClassificationReason, ClosedTime, ModifiedBy
| order by LastModified desc
```

Sample output:

```text
IncidentNumber  Title                                   Severity       Status  Classification  ClassificationReason    ModifiedBy
1401            XPIA detected on an AI agent ...        Informational  Closed  BenignPositive  SuspiciousButExpected   External application - SOAR
1388            XPIA detected on an AI agent ...        Informational  Closed  Undetermined                            Playbook - Add comment to incident
584             Suspicious activity incident ...        Medium         New                                             External application - hunting
```

`SecurityIncident` keeps one row per change, which is why the query takes the latest version per `IncidentNumber`.

### 20. Time to close agent-related incidents

Open versus closed counts and how long closure took, by incident type and classification.

```kql
let agentAlerts = SecurityAlert
    | where TimeGenerated > ago(30d)
    | where tostring(pack_all()) has_any (agentIds)
    | distinct SystemAlertId;
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds to typeof(string)
| where AlertId in (agentAlerts)
| distinct IncidentNumber, Title, Severity, Status, Classification, CreatedTime, ClosedTime
| extend TimeToClose = iff(Status == "Closed", ClosedTime - CreatedTime, timespan(null))
| summarize Incidents = count(), Open = countif(Status != "Closed"), Closed = countif(Status == "Closed"),
    MedianTimeToClose = percentile(TimeToClose, 50), P90TimeToClose = percentile(TimeToClose, 90)
    by Title, Severity, Classification
| order by Incidents desc
```

Sample output:

```text
Title                              Severity       Classification  Incidents  Open  Closed  MedianTimeToClose
XPIA detected on an AI agent ...   Informational  Undetermined    5          0     5       P7DT7H32M
XPIA detected on an AI agent ...   Informational  BenignPositive  1          0     1       P1DT18H31M
Suspicious activity incident ...   Medium                         2          2     0       {}
```

Most prompt-injection incidents closed as `Undetermined` after about a week. Closing without a classification hides whether the detections are useful.

### 21. Who closes incidents: agent, playbook, application or human

Splits closed incidents by the kind of principal that last modified them. This is how you see how much alert handling already runs through agents.

```kql
let agentUpns = AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(30d)
    | extend A = todynamic(Agent)
    | where A.agentSubjectType == "agentIDuser"
    | distinct UserPrincipalName;
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status == "Closed"
| extend ClosedBy = tostring(ModifiedBy)
| extend ClosedByKind = case(
    ClosedBy in~ (agentUpns), "agent user",
    ClosedBy startswith "Playbook", "playbook",
    ClosedBy startswith "External application", "application",
    ClosedBy contains "@", "human",
    "other")
| summarize Incidents = count(), FirstClosed = min(ClosedTime), LastClosed = max(ClosedTime), Examples = make_set(ClosedBy, 3)
    by ClosedByKind
| order by Incidents desc
```

Sample output:

```text
ClosedByKind  Incidents  FirstClosed           LastClosed            Examples
application   28         2026-10-20T13:56:29Z  2026-11-05T09:37:34Z  ["External application - hunting","External application - SOAR"]
other         22         2026-10-13T15:08:38Z  2026-11-06T13:01:17Z  ["Microsoft Defender XDR - alert correlation","Admin User"]
human         13         2026-10-10T18:59:29Z  2026-11-06T17:31:55Z  ["analyst@contoso.example"]
agent user    4          2026-11-06T08:29:45Z  2026-11-06T13:32:16Z  ["agentuser-aaaa@contoso.example"]
playbook      2          2026-11-02T20:52:51Z  2026-11-02T20:53:20Z  ["Playbook - Add comment to incident"]
```

### 22. What agent-closed incidents look like

Detail for the incidents an agent user closed, including the closing comment.

```kql
let agentUpns = AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(30d)
    | extend A = todynamic(Agent)
    | where A.agentSubjectType == "agentIDuser"
    | distinct UserPrincipalName;
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status == "Closed" and tostring(ModifiedBy) in~ (agentUpns)
| project ClosedTime, IncidentNumber, Title, Severity, Classification, ClassificationReason,
    Comment = substring(tostring(ClassificationComment), 0, 160), ClosedBy = tostring(ModifiedBy)
| order by ClosedTime desc
```

Sample output:

```text
ClosedTime            IncidentNumber  Title                                       Classification  Comment
2026-11-06T13:32:16Z  1422            Email reported by user as malware or phish  Undetermined    Incident automatically resolved as all alerts in the incident were resolved.
2026-11-06T09:36:42Z  1412            Email reported by user as malware or phish  Undetermined    Incident automatically resolved as all alerts in the incident were resolved.
```

The agent user did not classify these incidents. The incident closed automatically because every alert inside it had been resolved, and the agent user is recorded as the last modifier. Do not read `ClosedBy` alone as "the agent made the call": check the comment and the classification, and cross-check the alert-level resolution in query 18.

### 21b. Who changes cases: agent, playbook, application or human

`SecurityIncident` stores snapshots, and `ModifiedBy` there is only the last modifier. `SecurityCaseEvent` is the change log of Defender incident cases: one row per created case, changed property or comment, with `PreviousValues`, `NewValues` and `ModifiedBy`. That shows every change and who made it, not just the final state. It is a Sentinel workspace table ([reference](https://learn.microsoft.com/azure/azure-monitor/reference/tables/securitycaseevent)); filter on `TimeGenerated`, but read `EventTime` for when the change happened. Operations are `Create`, `Update`, `Delete`, `Link` and `Unlink`. Status changes appear as `caseStatus.statusName`, comments as `EntityType == "CaseComment"` with the case in `ParentEntityId`.

```kql
let agentUpns = AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(30d)
    | extend A = todynamic(Agent)
    | where A.agentSubjectType == "agentIDuser"
    | distinct UserPrincipalName;
SecurityCaseEvent
| where TimeGenerated > ago(30d)
| where EntityType in ("Case", "CaseComment")
| extend Property = iff(EntityType == "CaseComment", "comment", tostring(PropertyNames))
| extend Who = trim_start(@"User-|API-App:|Playbook-", ModifiedBy)
| extend WhoKind = case(
    Who in~ (agentUpns) or Who has "SecurityCopilotAgentUser", "agent user",
    ModifiedBy startswith "Playbook-", "playbook",
    ModifiedBy startswith "API-App:", "application",
    Who has "@", "human",
    "Defender or automation")
| summarize Changes = count(), Cases = dcount(coalesce(ParentEntityId, EntityId)), Properties = make_set(Property, 8),
    Examples = make_set(ModifiedBy, 3), Last = max(EventTime)
    by WhoKind, OperationName
| order by Changes desc
```

Look for: agent users that change `caseStatus`, `classification` or `determination` rather than only tags or comments, and applications or playbooks that close cases without a `closingNotes` entry.

Sample output:

```text
WhoKind                 OperationName  Changes  Cases  Properties                                                              Examples
Defender or automation  Update         753      80     ["slaPolicies","priorityScore","systemTags","closingNotes",...]        ["Case Management Engine","Microsoft 365 Defender-CaseManagement"]
human                   Update         104      24     ["assignedTo","closingNotes","caseStatus.statusName","tags",...]       ["User-analyst@contoso.com"]
application             Update         55       16     ["assignedTo","classification","closingNotes","caseStatus.statusName"] ["API-App:Contoso SOAR"]
agent user              Update         8        8      ["tags"]                                                                ["User-agentuser-aaaa@contoso.com"]
playbook                Update         7        7      ["tags"]                                                                ["Playbook-Add_comment_to_incident"]
```

The Security Copilot agent user only added an `Agent` tag to the cases it worked on. Status and classification were set by the SOAR application or by Defender's own automation, which confirms the reading of query 22.

### 22b. Case decisions made by agents and automation

Status, classification, determination, closing notes, severity, assignment and tag changes made by agent users, applications, playbooks or `Automation`, with the Defender incident ID and title taken from the case's `Create` event. In that event `PropertyNames` and `NewValues` are parallel arrays, so the query zips them into one bag.

```kql
let cases = SecurityCaseEvent
    | where TimeGenerated > ago(30d)
    | where EntityType == "Case" and OperationName == "Create"
    | extend P = parse_json(tostring(PropertyNames)), V = parse_json(tostring(NewValues))
    | mv-apply i = range(0, array_length(P) - 1) on (
        summarize Bag = make_bag(bag_pack(tostring(P[toint(i)]), V[toint(i)])))
    | project CaseId = EntityId, IncidentId = tostring(Bag.incidentId), Title = tostring(Bag.displayName);
SecurityCaseEvent
| where TimeGenerated > ago(30d)
| where EntityType == "Case" and OperationName == "Update"
| extend Property = tostring(PropertyNames)
| where Property in ("caseStatus.topLevelStatusName", "caseStatus.statusName", "classification", "determination",
    "closingNotes", "severity", "assignedTo", "tags")
| where ModifiedBy has "AgentUser" or ModifiedBy startswith "API-App:" or ModifiedBy startswith "Playbook-" or ModifiedBy == "Automation"
| join kind=leftouter cases on $left.EntityId == $right.CaseId
| project EventTime, CaseId = EntityId, IncidentId, Title, ModifiedBy, Property,
    From = substring(tostring(PreviousValues), 0, 60), To = substring(tostring(NewValues), 0, 100)
| order by EventTime desc
```

Look for: `classification` or `caseStatus` changes by an agent or application on high-severity cases, `FalsePositive` set without closing notes, and `Automation` raising severity, which is often the first sign that Defender re-scored a case.

Sample output:

```text
EventTime             CaseId  IncidentId  Title                                         ModifiedBy                 Property               From     To
2026-11-17T19:10:46Z  2040    6847        Login from <user> detected ...                API-App:Contoso SOAR       classification         Unknown  BenignPositive
2026-11-17T19:10:46Z  2040    6847        Login from <user> detected ...                API-App:Contoso SOAR       caseStatus.statusName  New      Closed
2026-11-18T14:06:47Z  2044    6851        Suspicious number of resource creation ...    Automation                 severity               Medium   High
2026-11-20T14:17:23Z  2041    6848        Email reported by user as malware or phish    Playbook-autoEscalate      tags                   ["Agent"]  ["Agent","Credential Phish","escalated"]
```

---

## F. Behaviors and anomalies

Behavior tables aggregate signals into something closer to a verdict. For agents, the useful ones are UEBA (`BehaviorAnalytics`, `Anomalies`), which already treats agent identity logons as service principal logons, and the Defender behavior tables (`BehaviorInfo`, `BehaviorEntities`).

The two families do not overlap:

| | Sentinel UEBA: `BehaviorAnalytics`, `Anomalies` | Defender XDR: `BehaviorInfo`, `BehaviorEntities` |
| --- | --- | --- |
| What a row is | One enriched activity (sign-in, Entra audit, Azure operation), or one ML anomaly with a score | One product detection aggregated over a time span |
| Baseline per account | Yes: first-time country, ISP, action, resource; peer comparison; `InvestigationPriority`; anomaly `Score` and `AnomalyReasons` | No |
| Agent coverage seen | Agent identity logons as "Service Principal" logons (query 23); UEBA anomalous authentication (query 24) | Prompt Shield jailbreak blocks on Foundry agents, agent named in `AdditionalFields` (query 25) |
| Needs | UEBA enabled in the Sentinel workspace | Defender XDR |

Only UEBA gives a per-agent baseline, so queries 23 and 24 have no XDR equivalent. Without UEBA, the baseline queries in section H rebuild part of it from sign-ins. Only `BehaviorInfo` carries Prompt Shield blocks as a Defender signal.

### 23. UEBA view of agent logons

First-time country, ISP and action flags per agent. New agents set these flags on purpose, so the interesting rows are old agents that suddenly flip a flag, or any agent with a high `InvestigationPriority`.

```kql
BehaviorAnalytics
| where TimeGenerated > ago(30d)
| extend U = todynamic(UsersInsights), I = todynamic(ActivityInsights)
| where tostring(U.AccountObjectID) in (agentIds)
| summarize Logons = count(), MaxPriority = max(InvestigationPriority),
    NewCountry = countif(tostring(I.FirstTimeUserConnectedFromCountry) == "True"),
    NewIsp = countif(tostring(I.FirstTimeUserConnectedViaISP) == "True"),
    NewAction = countif(tostring(I.FirstTimeUserPerformedAction) == "True"),
    Resources = make_set(tostring(I.Resource), 5), Locations = make_set(tostring(SourceIPLocation), 3),
    Last = max(TimeGenerated)
    by AgentId = tostring(U.AccountObjectID)
| order by MaxPriority desc, Logons desc
```

Sample output:

```text
AgentId       Logons  MaxPriority  NewCountry  NewIsp  NewAction  Resources                                      Locations
11111111-...  2       8            0           0       0          ["Bot Framework"]                              [""]
11111111-...  24      2            0           0       0          ["AAD Token Exchange Endpoint: Public"]        ["city A","city B","city C"]
11111111-...  23      2            1           0       1          ["Microsoft Graph","Security Copilot API",...] ["city A"]
```

The one agent with priority 8 was the Copilot Studio agent whose sign-ins were blocked by Conditional Access (query 7). The recently created agents scored 2 and set first-time flags once.

### 24. UEBA anomalies on agents

Anomalies raised by Sentinel UEBA that name an agent. The agent ID shows up as the account in the description.

```kql
Anomalies
| where TimeGenerated > ago(30d)
| where Description has_any (agentIds) or tostring(Entities) has_any (agentIds)
| summarize Anomalies = count(), MaxScore = max(Score), LastSeen = max(TimeGenerated),
    SourceIps = make_set(SourceIpAddress, 4)
    by AnomalyTemplateName, Tactics = tostring(Tactics)
| order by Anomalies desc
```

Sample output:

```text
AnomalyTemplateName            Tactics           Anomalies  MaxScore  SourceIps
UEBA Anomalous Authentication  ["InitialAccess"] 3          0.2       ["203.0.113.10","203.0.113.20"]
```

### 25. Defender behaviors that involve agents

Defender behaviors (`BehaviorInfo`) are aggregated product detections, not UEBA baselines. Agent behaviors name the agent in `AdditionalFields` (`AgentName`, `AgentBlueprintID`, `HostingPlatformType`), not as an entity: `BehaviorEntities` only carries the user and IP involved. So the query matches either the agent fields or an agent ID anywhere in the entities.

This returned `BehaviorPromptShieldJailbreakBlock` ("AI agent interaction blocked by Microsoft Prompt Shield"), one row per blocked jailbreak prompt against a Foundry agent, matching query 47 one to one. It is the Defender XDR native way to see those blocks without parsing the content filter JSON.

```kql
let byFields = BehaviorInfo
    | where Timestamp > ago(30d)
    | extend AF = parse_json(AdditionalFields)
    | where isnotempty(AF.AgentName) or isnotempty(AF.AgentBlueprintID) or isnotempty(AF.AgentId)
    | project BehaviorId, Timestamp, ActionType, Description, ServiceSource, AccountUpn,
        Agent = tostring(AF.AgentName), Platform = tostring(AF.HostingPlatformType), BlueprintId = tostring(AF.AgentBlueprintID);
let byEntities = BehaviorEntities
    | where Timestamp > ago(30d)
    | where tostring(pack_all()) has_any (agentIds)
    | distinct BehaviorId
    | join kind=inner (BehaviorInfo | project BehaviorId, Timestamp, ActionType, Description, ServiceSource, AccountUpn) on BehaviorId
    | project BehaviorId, Timestamp, ActionType, Description, ServiceSource, AccountUpn, Agent = "", Platform = "", BlueprintId = "";
union byFields, byEntities
| summarize Behaviors = dcount(BehaviorId), Users = make_set(AccountUpn, 5), First = min(Timestamp), Last = max(Timestamp)
    by ActionType, Description, ServiceSource, Agent, Platform, BlueprintId
| order by Behaviors desc
```

Look for: Prompt Shield blocks against production agents, many blocks from one user, and any behavior type other than Prompt Shield that names an agent.

Sample output:

```text
ActionType                          Description                                                    Agent                 Platform        Behaviors  Users
BehaviorPromptShieldJailbreakBlock  AI agent interaction blocked by Microsoft Prompt Shield (preview)  contoso-phish-triage  AzureAIFoundry  16         ["analyst@contoso.com"]
BehaviorPromptShieldJailbreakBlock  AI agent interaction blocked by Microsoft Prompt Shield (preview)  contoso-agent-dev     AzureAIFoundry  10         ["analyst@contoso.com"]
```

---

## G. Agent risk: Entra ID Protection and Defender

There are two separate risk signals and they do not agree by design.

| | Entra ID Protection | Defender |
| --- | --- | --- |
| What it measures | Behavioral risk of the agent: unfamiliar resource access, sign-in spikes, failed access, admin confirmation | Posture risk of the agent: published, weak instructions, privileged data access, risky owner |
| Form | `riskLevel` (`low`, `medium`, `high`, `none`) and `riskState` (`atRisk`, `confirmedCompromised`, `dismissed`, ...) | Active risk indicators, each with a severity. The portal derives an overall risk level from them. |
| Where | `AADRiskyAgents`, `AADAgentRiskEvents`, Graph `riskyAgents` | `AgentsInfo.RiskIndicators`, AI Agents page in the Defender portal |

Neither source gives a numeric score for the agent. `IdentityInfo` has `RiskScore` and `RiskLevel` columns, but they were empty for the agent users I checked.

### 26. Entra risk state per agent

The latest risk level, state and detail for every agent that Entra ID Protection has flagged. Agents with no risk do not appear.

```kql
AADRiskyAgents
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by Id
| project RiskLastModified = RiskLastModifiedDateTime, AgentDisplayName, IdentityType, RiskLevel, RiskState, RiskDetail, IsEnabled, IsDeleted
| order by RiskLastModified desc
```

Sample output:

```text
RiskLastModified      AgentDisplayName   IdentityType   RiskLevel  RiskState  RiskDetail                    IsEnabled
2026-11-03T14:59:44Z  Contoso HR Helper  agentIdentity  low        atRisk     none                          true
2026-11-02T21:16:33Z  Contoso HR Draft   agentIdentity  none       dismissed  adminDismissedRiskForAgent    true
```

`RiskLevel` goes to `high` when an admin confirms compromise, which is what a risk-based Conditional Access policy for agents blocks on.

### 27. Entra risk detections for agents

The individual detections behind the risk state. These were AI compound account risk (low, offline or not defined) and one admin-confirmed compromise (high).

```kql
AADAgentRiskEvents
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by Id
| project DetectedDateTime, AgentDisplayName, IdentityType, RiskEventType, RiskLevel, RiskState, RiskDetail, DetectionTimingType
| order by DetectedDateTime desc
```

Sample output:

```text
DetectedDateTime      AgentDisplayName   RiskEventType                    RiskLevel  RiskState             DetectionTimingType
2026-11-03T14:59:44Z  Contoso HR Helper  aiCompoundAccountRisk            low        atRisk                notDefined
2026-11-03T14:42:25Z  Contoso HR Helper  adminConfirmedAgentCompromised   high       confirmedCompromised  offline
```

Risk detections are kept for up to 90 days in Entra, and the hunting window is 30 days.

### 28. Defender risk indicators across all agents

Which risk indicators are active and how many agents have each. `RiskIndicators` is a property bag keyed by indicator ID, and it is empty (`{}`) for some agents, so the query replaces an empty bag with a placeholder to keep those agents in the result.

```kql
AgentsInfo
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| extend RiskIndicators = iff(array_length(bag_keys(RiskIndicators)) == 0, dynamic({"none": {}}), RiskIndicators)
| mv-expand RI = RiskIndicators
| extend Key = tostring(bag_keys(RI)[0])
| extend Indicator = tostring(RI[Key]["title"]), Active = tobool(RI[Key]["isActive"]), Severity = tostring(RI[Key]["severity"])
| where Active
| summarize Agents = dcount(AgentId) by Indicator, Severity
| order by Agents desc
```

Sample output:

```text
Indicator                          Severity  Agents
Published Agent                    Low       406
Weak Instructions                  Medium    23
Privileged Business System Access  Medium    15
Privileged Data Access             Medium    9
Risky agent owner                  Medium    4
```

`Connection count: N` indicators carry no severity. They describe blast radius, not a finding.

### 29. Defender risk indicators per agent

Per-agent indicators with severities, for agents that have an Entra agent ID.

```kql
AgentsInfo
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted" and isnotempty(EntraAgentID)
| extend RiskIndicators = iff(array_length(bag_keys(RiskIndicators)) == 0, dynamic({"none": {}}), RiskIndicators)
| mv-expand RI = RiskIndicators
| extend Key = tostring(bag_keys(RI)[0])
| extend Indicator = tostring(RI[Key]["title"]), Active = tobool(RI[Key]["isActive"]), Severity = tostring(RI[Key]["severity"])
| summarize ActiveIndicators = countif(Active), Indicators = make_set_if(Indicator, Active, 6),
    Severities = make_set_if(Severity, Active, 4) by Name, Platform, EntraAgentID, PublishedStatus
| order by ActiveIndicators desc
```

Sample output:

```text
Name                Platform         PublishedStatus  ActiveIndicators  Indicators
Contoso File Agent  Copilot Studio   Draft            4                 ["Connection count: 4","Privileged Data Access","Data Exfiltration Exposure","Indirect Prompt Injection Exposure"]
Contoso RAG Agent   Microsoft Foundry Published       4                 ["Published Agent","Connection count: 2","High Autonomy","Risky agent owner"]
```

### 30. One scorecard: Entra risk and Defender risk per agent

Joins both sources on the Entra agent ID. `AgentsInfo` has no overall risk level column, so `DefenderRiskProxy` is the highest severity among the active indicators. It is a proxy for the level the Defender portal shows, not the same number.

```kql
let defender = AgentsInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp, *) by AgentId
    | where LifecycleStatus != "Deleted" and isnotempty(EntraAgentID)
    | extend RiskIndicators = iff(array_length(bag_keys(RiskIndicators)) == 0, dynamic({"none": {}}), RiskIndicators)
    | mv-expand RI = RiskIndicators
    | extend Key = tostring(bag_keys(RI)[0])
    | extend Indicator = tostring(RI[Key]["title"]), Active = tobool(RI[Key]["isActive"]), Severity = tostring(RI[Key]["severity"])
    | extend SeverityRank = case(Severity == "High", 3, Severity == "Medium", 2, Severity == "Low", 1, 0)
    | summarize ActiveIndicators = countif(Active), MaxSeverityRank = maxif(SeverityRank, Active),
        Indicators = make_set_if(Indicator, Active, 5) by Name, Platform, EntraAgentID;
let entra = AADRiskyAgents
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, RiskLevel, RiskState, RiskDetail) by EntraAgentID = Id;
let entraEvents = AADAgentRiskEvents
    | where TimeGenerated > ago(30d)
    | summarize EntraRiskEvents = count(), EntraEventTypes = make_set(RiskEventType, 4) by EntraAgentID = AgentId;
defender
| join kind=leftouter entra on EntraAgentID
| join kind=leftouter entraEvents on EntraAgentID
| extend DefenderRiskProxy = case(MaxSeverityRank == 3, "high", MaxSeverityRank == 2, "medium", MaxSeverityRank == 1, "low", "none")
| project Name, Platform, EntraAgentID, DefenderRiskProxy, ActiveIndicators, Indicators,
    EntraRiskLevel = coalesce(RiskLevel, "none"), EntraRiskState = coalesce(RiskState, "none"), EntraEventTypes
| order by case(DefenderRiskProxy == "high", 3, DefenderRiskProxy == "medium", 2, DefenderRiskProxy == "low", 1, 0) desc,
    case(EntraRiskLevel == "high", 3, EntraRiskLevel == "medium", 2, EntraRiskLevel == "low", 1, 0) desc
```

To scope it to specific agents, add a filter after `defender`, for example `defender | where EntraAgentID in (dynamic(["<agent identity object ID>"]))`. The query as written covers every agent with an Entra agent ID.

Sample output:

```text
Name                Platform        EntraAgentID  DefenderRiskProxy  ActiveIndicators  EntraRiskLevel  EntraRiskState
Contoso File Agent  Copilot Studio  55555555-...  high               4                 none            none
Contoso RAG Agent   Foundry         55555555-...  medium             3                 none            none
Contoso HR Helper   Copilot Studio  55555555-...  low                1                 low             atRisk
Contoso Recon Agent Perception      11111111-...  none               0                 none            none
```

How to read it:

- High in Defender and `none` in Entra is a posture problem with no suspicious behavior yet. Fix the configuration.
- `atRisk` or `confirmedCompromised` in Entra is a behavior problem. Investigate sign-ins and activity (sections A to C) before touching the configuration.
- `none` and `0` in both can mean "no findings" or "not evaluated". The Perception agents showed an empty indicator bag. Do not read an empty result as a clean bill of health.

### 31. Account-level risk and criticality for agent users

Defender's `IdentityInfo` holds an account risk score and a criticality level. The agent users had a `CriticalityLevel` but empty `RiskLevel` and `RiskScore`, so there is no account-level score to read for them. The scale of `CriticalityLevel` is not explained here; check the Defender documentation before alerting on it.

```kql
IdentityInfo
| where Timestamp > ago(30d)
| where AccountObjectId in (agentIds)
| summarize arg_max(Timestamp, *) by AccountObjectId
| project AccountUpn, CriticalityLevel, RiskLevel, RiskScore, RiskStatus, RiskLevelDetails, RiskScoreUpdateTime
```

Sample output:

```text
AccountUpn                        CriticalityLevel  RiskLevel  RiskScore  RiskStatus
agentuser-aaaa@contoso.example    4
agentuser-bbbb@contoso.example    4
```

### Live Entra risk through Microsoft Graph

The hunting tables above depend on the Entra risk diagnostic setting and on Sentinel ingestion. For the current state, read the risky agent objects from Graph (beta).

```bash
az rest --method get --url "https://graph.microsoft.com/beta/identityProtection/riskyAgents" \
  --query 'value[].{agent:agentDisplayName,id:id,level:riskLevel,state:riskState,detail:riskDetail,enabled:isEnabled}' -o table
az rest --method get --url "https://graph.microsoft.com/beta/identityProtection/agentRiskDetections" -o json
```

`riskyAgents` needs `IdentityRiskyAgent.Read.All`, and a delegated caller needs Global Reader, Security Reader, Security Operator or Security Administrator. My `az` token did not carry that scope and returned 403, so these two calls were not run here. Use `Connect-MgGraph -Scopes IdentityRiskyAgent.Read.All` or an app registration with that permission, and confirm the permission for `agentRiskDetections` in the Graph reference.

---

## H. Baselines and behavior analytics

Sections A to G answer "what is this agent and what did it do". This section answers "is that normal for this agent". Each query compares a recent `window` against the agent's own `baseline` and reports only what changed. They all follow the same rules, because agents break the usual assumptions:

- **Per agent, not per tenant.** An agent's normal is narrow and stable, so the baseline is the agent itself. A change that is invisible across 400 agents is obvious inside one.
- **Established agents only.** A new agent has no baseline, so everything it does is "new". Queries 5, 34, 36, 38, 40, 41 and 43 skip agents with no history before the window. Without this guard, the first run of any new agent floods the result. The guarded versions of queries 34, 36 and 38 returned no rows, because no established agent changed its IPs, volume or Graph calls in the last seven days. That is the expected result when nothing is wrong. Queries 40 and 41 did return rows (a new tool and new SDK versions).
- **Both principals.** Agent identity and agent user are joined to one agent ID, so a change on either side counts for the agent.
- **Tune the windows.** `window` is the period to inspect and `baseline` the period to learn from. The hunting API keeps 30 days, so keep `window + baseline` at or below 30d. For a longer baseline, persist the daily aggregates into a table first (see the end of this section).

### 32. Interactive sign-ins by agent users (should be empty)

Agent users authenticate through their agent identity and should never sign in interactively. Any row is a person, a script or an attacker using the agent user's account.

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| extend A = todynamic(Agent)
| where isnotempty(tostring(A.agentType)) and (A.agentType != "notAgentic" or A.agentSubjectType != "notAgentic")
| summarize InteractiveSignIns = count(), Apps = make_set(AppDisplayName, 5), IPs = make_set(IPAddress, 5),
    Countries = make_set(Location, 5), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by UserPrincipalName, ParentAgentId = tostring(A.agentSubjectParentId), ResultType
| order by LastSeen desc
```

This returned no rows, but that result is weak evidence. `SigninLogs` held no agent-marked sign-ins of any kind there (every row was `notAgentic`), so the filter could not be shown to match. The filter accepts any agent marker instead of one exact value for that reason. Before you rely on it, confirm in your tenant that an interactive agent user sign-in carries an agent marker in `Agent`, for example by testing with one controlled sign-in. Then make it a scheduled detection with a threshold of one.

### 33. How agent identities authenticate

Which credential type each agent identity used. Every agent identity used a federated identity credential, and the credential key ID was empty, so there is no key to compare over time. A secret or certificate appearing is the change to catch.

> **Note: what "federated identity credential" means.** `ClientCredentialType = federatedIdentityCredential` describes how an agent authenticates. It is not a kind of agent. A normal application proves its identity with something it holds, a client secret or a certificate. With a federated identity credential, Entra instead trusts a token from another issuer, such as an Azure managed identity, GitHub Actions or a Kubernetes cluster, and the workload exchanges that token for an Entra token. There is no secret to store, leak or rotate.
>
> For agents, the agent identity has no credentials of its own. The blueprint holds them, and Microsoft lists managed identities and federated identity credentials as supported credential types for blueprints. The blueprint then requests tokens on behalf of each agent identity, so the agent identity appears as the client in the sign-in log even though the blueprint performed the token exchange.
>
> Two consequences for hunting. First, `federatedIdentityCredential` is the safest value, and a secret or certificate appearing for an agent that used a federated credential before is a change worth investigating. Second, the trust sits at the blueprint: whoever controls the trusted issuer or the trust configuration can obtain tokens for every agent identity created from that blueprint. A changed credential type on one agent can therefore point to a changed blueprint.
{: .prompt-info}

```kql
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(30d)
| extend A = todynamic(Agent)
| where A.agentType == "agenticAppInstance"
| summarize SignIns = count(), CredentialTypes = make_set(ClientCredentialType, 4),
    CredentialKeys = make_set(ServicePrincipalCredentialKeyId, 4), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by ServicePrincipalName, AgentId = ServicePrincipalId
| extend KeyCount = array_length(CredentialKeys)
| order by KeyCount desc, SignIns desc
```

Sample output:

```text
ServicePrincipalName  AgentId       SignIns  CredentialTypes                  CredentialKeys  KeyCount
Contoso Recon Agent   11111111-...  23       ["federatedIdentityCredential"]  [""]            1
Contoso Triage Agent  11111111-...  22       ["federatedIdentityCredential"]  [""]            1
```

To alert, add `| where not(tostring(CredentialTypes) has "federatedIdentityCredential")`. Because all agent identities inherit their credentials from the blueprint, a changed credential type on one agent can also mean a changed blueprint.

### 34. New IP address for an established agent

IP addresses an established agent used in the window but never in the baseline, with country and ASN.

```kql
let window = 7d;
let baseline = 23d;
let agentActivity = union
    (AADServicePrincipalSignInLogs
        | where TimeGenerated > ago(window + baseline)
        | extend A = todynamic(Agent)
        | where A.agentType == "agenticAppInstance"
        | project TimeGenerated, AgentId = ServicePrincipalId, Principal = "identity", IPAddress, Location, AutonomousSystemNumber),
    (AADNonInteractiveUserSignInLogs
        | where TimeGenerated > ago(window + baseline)
        | extend A = todynamic(Agent)
        | where A.agentSubjectType == "agentIDuser"
        | project TimeGenerated, AgentId = tostring(A.agentSubjectParentId), Principal = "user", IPAddress, Location, AutonomousSystemNumber);
let known = agentActivity
    | where TimeGenerated < ago(window)
    | distinct AgentId, Principal, IPAddress;
let established = known | summarize by AgentId;
agentActivity
| where TimeGenerated >= ago(window)
| join kind=inner established on AgentId
| join kind=leftanti known on AgentId, Principal, IPAddress
| summarize NewIpSignIns = count(), FirstSeen = min(TimeGenerated), Countries = make_set(Location, 3), Asns = make_set(AutonomousSystemNumber, 3)
    by AgentId, Principal, IPAddress
| order by NewIpSignIns desc
```

Sample output (this is the unguarded form, which flags every new agent once; the guarded query above returned no rows):

```text
AgentId       Principal  IPAddress       NewIpSignIns  FirstSeen             Countries  Asns
11111111-...  user       203.0.113.10    14632         2026-11-04T09:53:32Z  ["NL"]     ["8075"]
11111111-...  user       203.0.113.10    7098          2026-11-04T09:53:27Z  ["NL"]     ["8075"]
```

ASN 8075 is Microsoft. For agents that run on Microsoft infrastructure, a new IP from the same ASN is routine and a new ASN is not. Rank new IPs by ASN first.

### 35. Activity outside an agent's usual hours

Hours of the day in which an agent was almost never active during the baseline (under 1% of its activity) but was active in the window. It needs at least 50 baseline events per agent to build a profile.

```kql
let window = 3d;
let baseline = 27d;
let minBaselineEvents = 50;
let agentSignIns = AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(window + baseline)
    | extend A = todynamic(Agent)
    | where A.agentSubjectType == "agentIDuser"
    | project TimeGenerated, AgentId = tostring(A.agentSubjectParentId), Hour = hourofday(TimeGenerated);
let profile = agentSignIns
    | where TimeGenerated < ago(window)
    | summarize BaselineEvents = count() by AgentId, Hour
    | join kind=inner (agentSignIns | where TimeGenerated < ago(window) | summarize Total = count() by AgentId) on AgentId
    | where Total >= minBaselineEvents
    | project AgentId, Hour, BaselineShare = round(100.0 * BaselineEvents / Total, 2);
agentSignIns
| where TimeGenerated >= ago(window)
| summarize RecentEvents = count() by AgentId, Hour
| join kind=leftouter profile on AgentId, Hour
| join kind=inner (profile | summarize by AgentId) on AgentId
| where isnull(BaselineShare) or BaselineShare < 1.0
| project AgentId, Hour, RecentEvents, BaselineShare = coalesce(BaselineShare, 0.0)
| order by RecentEvents desc
```

Sample output:

```text
AgentId       Hour  RecentEvents  BaselineShare
11111111-...  18    5962          0.0
11111111-...  17    4758          0.0
11111111-...  3     26            0.0
```

Agents with schedules or event triggers have sharp hour patterns, and agents that run on demand have none. Use this for the first group. Hours are UTC.

### 36. Daily sign-in volume anomalies

A time series of daily sign-ins per agent, with Kusto's built-in anomaly detection (`series_decompose_anomalies`) on the 30-day series. Reports spikes and drops in the last seven days for agents with at least 14 days of history.

```kql
let agentSignIns = union
    (AADServicePrincipalSignInLogs
        | where TimeGenerated > ago(30d)
        | extend A = todynamic(Agent)
        | where A.agentType == "agenticAppInstance"
        | project TimeGenerated, AgentId = ServicePrincipalId),
    (AADNonInteractiveUserSignInLogs
        | where TimeGenerated > ago(30d)
        | extend A = todynamic(Agent)
        | where A.agentSubjectType == "agentIDuser"
        | project TimeGenerated, AgentId = tostring(A.agentSubjectParentId));
agentSignIns
| make-series SignIns = count() default = 0 on TimeGenerated from startofday(ago(30d)) to startofday(now()) step 1d by AgentId
| extend (Flag, Score, Baseline) = series_decompose_anomalies(SignIns, 2.5, -1, "linefit")
| mv-expand TimeGenerated to typeof(datetime), SignIns to typeof(long), Flag to typeof(int), Score to typeof(double), Baseline to typeof(double)
| where Flag != 0 and TimeGenerated >= startofday(ago(7d))
| join kind=inner (agentSignIns | summarize FirstSeen = min(TimeGenerated) by AgentId | where FirstSeen < ago(14d) | project AgentId) on AgentId
| project Day = TimeGenerated, AgentId, SignIns, ExpectedSignIns = round(Baseline, 0), Score = round(Score, 1),
    Direction = iff(Flag > 0, "spike", "drop")
| order by abs(Score) desc
```

Sample output (unguarded, showing the first day of new agents):

```text
Day         AgentId       SignIns  ExpectedSignIns  Score  Direction
2026-11-04  11111111-...  3598     296              21.9   spike
2026-11-04  11111111-...  5242     432              21.9   spike
2026-11-06  11111111-...  21       2                17.6   spike
```

A drop matters as much as a spike: an agent that stops signing in has usually lost a credential, a trigger or a permission. Pair a drop with query 6.

### 37. Failure rate against the agent's own baseline

Failure rate in the window versus the baseline, for agents with at least 20 sign-ins. Ranked by change, so the top row is the agent that got worse. There is no fixed threshold because failure rates differ a lot between agents (one agent failed about half of its sign-ins all month, which is a fault, not a change).

```kql
let window = 7d;
let baseline = 23d;
let minSignIns = 20;
let signIns = union
    (AADServicePrincipalSignInLogs
        | where TimeGenerated > ago(window + baseline)
        | extend A = todynamic(Agent)
        | where A.agentType == "agenticAppInstance"
        | project TimeGenerated, AgentId = ServicePrincipalId, Failed = ResultType != "0"),
    (AADNonInteractiveUserSignInLogs
        | where TimeGenerated > ago(window + baseline)
        | extend A = todynamic(Agent)
        | where A.agentSubjectType == "agentIDuser"
        | project TimeGenerated, AgentId = tostring(A.agentSubjectParentId), Failed = ResultType != "0");
let baselineRate = signIns
    | where TimeGenerated < ago(window)
    | summarize BaselineSignIns = count(), BaselineFailRate = round(100.0 * countif(Failed) / count(), 1) by AgentId;
signIns
| where TimeGenerated >= ago(window)
| summarize RecentSignIns = count(), RecentFailures = countif(Failed), RecentFailRate = round(100.0 * countif(Failed) / count(), 1) by AgentId
| where RecentSignIns >= minSignIns
| join kind=leftouter baselineRate on AgentId
| project-away AgentId1
| extend BaselineFailRate = coalesce(BaselineFailRate, 0.0), BaselineSignIns = coalesce(BaselineSignIns, 0)
| extend RateChange = round(RecentFailRate - BaselineFailRate, 1)
| order by RateChange desc
```

Sample output:

```text
AgentId       RecentSignIns  RecentFailures  RecentFailRate  BaselineSignIns  BaselineFailRate  RateChange
11111111-...  555            292             52.6            1968             51.1              1.5
11111111-...  7099           0               0.0             0                0.0               0.0
```

For the reason behind the failures, continue with query 2b.

### 38. New Graph API families for an established agent

Graph endpoints (method plus the first two path segments, GUIDs replaced by `{id}`) that an established agent called in the window and never in the baseline. This is the most direct view of an agent doing something new.

```kql
let window = 7d;
let baseline = 23d;
let agentApps = AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(window + baseline)
    | extend A = todynamic(Agent)
    | where A.agentType == "agenticAppInstance"
    | distinct AppId;
let calls = GraphAPIAuditEvents
    | where Timestamp > ago(window + baseline)
    | where ApplicationId in (agentApps)
    | extend Family = extract(@"/(?:v1\.0|beta)/+([^/?]+(?:/+[^/?]+)?)", 1, RequestUri)
    | extend Family = replace_regex(Family, @"/+", "/")
    | extend Family = replace_regex(Family, @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "{id}")
    | project TimeGenerated = Timestamp, AppId = ApplicationId, RequestMethod, Family, ResponseStatusCode = toint(ResponseStatusCode);
let known = calls | where TimeGenerated < ago(window) | distinct AppId, RequestMethod, Family;
let established = known | summarize by AppId;
calls
| where TimeGenerated >= ago(window)
| join kind=inner established on AppId
| join kind=leftanti known on AppId, RequestMethod, Family
| summarize NewCalls = count(), Failed = countif(ResponseStatusCode >= 400), FirstSeen = min(TimeGenerated) by AppId, RequestMethod, Family
| order by NewCalls desc
```

Sample output (unguarded, a new agent's first run):

```text
AppId         RequestMethod  Family                     NewCalls  Failed  FirstSeen
11111111-...  GET            servicePrincipals/{id}     1161      7       2026-11-06T13:14:02Z
11111111-...  POST           directoryObjects/getByIds  134       1       2026-11-06T13:05:27Z
11111111-...  GET            groups/{id}                33        6       2026-11-06T13:13:58Z
```

A new `POST`, `PATCH`, `PUT` or `DELETE` family is a stronger signal than a new `GET` family, so filter on `RequestMethod` when you alert.

### 39. Granted permissions with no matching call

Compares the Graph application permissions that were granted to an agent identity with the permissions its API calls actually need. The mapping from path to permission is a heuristic that you extend for the permissions you grant. It is useful for least privilege: a permission with no matching call in 30 days is a candidate to remove.

```kql
let lookback = 30d;
let agentApps = AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(lookback)
    | extend A = todynamic(Agent)
    | where A.agentType == "agenticAppInstance"
    | distinct AppId;
let granted = CloudAppEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "Add app role assignment to service principal."
    | extend Mods = parse_json(RawEventData).ModifiedProperties
    | mv-apply m = Mods on (summarize Props = make_bag(bag_pack(tostring(m.Name), tostring(m.NewValue))))
    | where tostring(Props["ServicePrincipal.ObjectID"]) in (agentApps)
    | project AgentId = tostring(Props["ServicePrincipal.ObjectID"]), Agent = tostring(Props["ServicePrincipal.DisplayName"]),
        Permission = tostring(Props["AppRole.Value"]), GrantedAt = Timestamp;
// Heuristic: which permission does the called path need? Extend the case for the permissions you grant.
let needed = GraphAPIAuditEvents
    | where Timestamp > ago(lookback)
    | where ApplicationId in (agentApps) and toint(ResponseStatusCode) < 400
    | extend Uri = tolower(tostring(split(RequestUri, "?")[0]))
    | extend Permission = case(
        Uri contains "/auditlogs", "AuditLog.Read.All",
        Uri contains "/policies", "Policy.Read.All",
        Uri contains "/organization", "Organization.Read.All",
        Uri contains "/rolemanagement", "RoleManagement.Read.Directory",
        Uri contains "/oauth2permissiongrants", "DelegatedPermissionGrant.Read.All",
        Uri contains "/groups" and (Uri contains "/members" or Uri contains "/transitivemembers"), "GroupMember.Read.All",
        Uri contains "/serviceprincipals" or Uri contains "/applications", "Application.Read.All",
        Uri contains "/users", "User.Read.All",
        "")
    | where isnotempty(Permission)
    | summarize MatchingCalls = count(), LastMatch = max(Timestamp) by AgentId = ApplicationId, Permission;
granted
| join kind=leftouter needed on AgentId, Permission
| extend Status = iff(isnull(MatchingCalls), "granted, no matching call seen", "matching calls seen")
| project Agent, Permission, GrantedAt, Status, MatchingCalls, LastMatch
| order by Status desc, Agent asc, Permission asc
```

Sample output:

```text
Agent                Permission                          GrantedAt             Status                          MatchingCalls
Contoso Recon Agent  Application.Read.All                2026-11-04T11:58:15Z  matching calls seen             1518
Contoso Recon Agent  RoleManagement.Read.Directory       2026-11-04T11:58:12Z  matching calls seen             22
Contoso Recon Agent  AuditLog.Read.All                   2026-11-04T11:58:13Z  granted, no matching call seen
Contoso Recon Agent  Organization.Read.All               2026-11-04T11:58:12Z  granted, no matching call seen
Contoso Recon Agent  Policy.Read.All                     2026-11-04T11:58:12Z  granted, no matching call seen
```

Three of the eight permissions granted to one agent had no matching call. Do not use the `Scopes` column of `GraphAPIAuditEvents` (or `Roles` in `MicrosoftGraphActivityLogs`) for this: it lists every role present in the token on every call, so all eight permissions appeared on all 1,745 calls and it says nothing about which one a call needed.

### 40. New tools for an established agent

Tools (Security Copilot tools, Copilot Studio tool and MCP tool invocations) that an established agent ran in the window but never in the baseline.

```kql
let window = 7d;
let baseline = 23d;
let agentUpns = AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(window + baseline)
    | extend A = todynamic(Agent)
    | where A.agentSubjectType == "agentIDuser"
    | distinct UserPrincipalName;
let agentNames = AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(window + baseline)
    | extend A = todynamic(Agent)
    | where A.agentType == "agenticAppInstance"
    | distinct ServicePrincipalName;
let toolEvents = CloudAppEvents
    | where Timestamp > ago(window + baseline)
    | where ActionType in ("ExecuteToolBySDK", "ExecuteToolByGateway", "SentinelAIToolRunCompleted")
    // ExecuteTool* events always come from an agent. Tool runs also come from people, so keep agent callers only.
    | where ActionType != "SentinelAIToolRunCompleted" or AccountDisplayName in~ (agentUpns) or AccountDisplayName in (agentNames)
    | extend R = parse_json(RawEventData)
    | extend Agent = coalesce(tostring(R.AgentName), AccountDisplayName), Tool = tostring(R.ToolName)
    | where isnotempty(Agent) and isnotempty(Tool)
    | project Timestamp, Agent, Tool;
let known = toolEvents | where Timestamp < ago(window) | distinct Agent, Tool;
let agentsWithHistory = known | summarize by Agent;
toolEvents
| where Timestamp >= ago(window)
| join kind=inner agentsWithHistory on Agent
| join kind=leftanti known on Agent, Tool
| summarize Runs = count(), FirstSeen = min(Timestamp) by Agent, Tool
| order by FirstSeen desc
```

Sample output:

```text
Agent               Tool                                           Runs  FirstSeen
Contoso Query Agent mcp_SentinelData.get_graph_context             1     2026-11-06T17:17:11Z
```

New tools that send mail, write files or call external services are the ones to review first.

### 41. New client library or runtime for an agent user

User-agent strings that an established agent user used in the window but never before. For agents this is usually an SDK or runtime upgrade. It can also be someone using the agent user's credentials from a different client.

```kql
let window = 7d;
let baseline = 23d;
let agentUserSignIns = AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(window + baseline)
    | extend A = todynamic(Agent)
    | where A.agentSubjectType == "agentIDuser"
    | project TimeGenerated, AgentId = tostring(A.agentSubjectParentId), UserPrincipalName, AppDisplayName, UserAgent, ClientAppUsed;
let known = agentUserSignIns | where TimeGenerated < ago(window) | distinct AgentId, UserAgent;
let agentsWithHistory = known | summarize by AgentId;
agentUserSignIns
| where TimeGenerated >= ago(window)
| join kind=inner agentsWithHistory on AgentId
| join kind=leftanti known on AgentId, UserAgent
| summarize SignIns = count(), FirstSeen = min(TimeGenerated), Apps = make_set(AppDisplayName, 3) by AgentId, UserPrincipalName, UserAgent
| order by SignIns desc
```

Sample output:

```text
AgentId       UserPrincipalName               UserAgent                                                       SignIns  FirstSeen
11111111-...  agentuser-aaaa@contoso.example  azsdk-net-Identity/1.17.1 (.NET 10.0.14; Azure Linux 3.0)       158      2026-11-04T09:32:07Z
11111111-...  agentuser-bbbb@contoso.example  azsdk-net-Identity/1.13.2 (.NET 8.0.33; Azure Linux 3.0)        12       2026-11-06T08:39:59Z
```

A new browser or scripting user agent (`curl`, `python-requests`, `Mozilla`) on an agent user is a strong signal. A new SDK version is not.

### 42. Agents that differ from their siblings

Agents created from the same blueprint should behave alike. This lists resources that exactly one agent in a blueprint group requested while its siblings did not. It needs at least two agent identities per blueprint, so it returned nothing here, where sibling agents used identical resources.

```kql
let lookback = 30d;
let agentResources = AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(lookback)
    | extend A = todynamic(Agent)
    | where A.agentType == "agenticAppInstance"
    | summarize Resources = make_set(ResourceDisplayName) by AgentId = ServicePrincipalId, AgentName = ServicePrincipalName,
        BlueprintAppId = tostring(A.parentAppId);
let peerGroups = agentResources
    | summarize PeerCount = dcount(AgentId) by BlueprintAppId
    | where PeerCount > 1;
let resourceUse = agentResources
    | mv-expand Resource = Resources to typeof(string)
    | summarize AgentsUsing = dcount(AgentId) by BlueprintAppId, Resource;
agentResources
| join kind=inner peerGroups on BlueprintAppId
| mv-expand Resource = Resources to typeof(string)
| join kind=inner resourceUse on BlueprintAppId, Resource
| where AgentsUsing == 1
| project AgentName, AgentId, BlueprintAppId, PeerCount, OnlyThisAgentUses = Resource
| order by BlueprintAppId, AgentName
```

### 43. One anomaly score per agent

Combines three of the signals above (new resource, new IP address, failure rate increase) into a ranked list, so one query shows which agents to look at first. Weights are 3 for a new resource, 2 for a new IP and 2 for a failure rate increase of at least 10 points. Only established agents are scored.

```kql
let window = 7d;
let baseline = 23d;
// Identity and agent user sign-ins, normalised to one agent ID
let signIns = union
    (AADServicePrincipalSignInLogs
        | where TimeGenerated > ago(window + baseline)
        | extend A = todynamic(Agent)
        | where A.agentType == "agenticAppInstance"
        | project TimeGenerated, AgentId = ServicePrincipalId, AgentName = ServicePrincipalName, Principal = "identity",
            Resource = ResourceDisplayName, IPAddress, Failed = ResultType != "0"),
    (AADNonInteractiveUserSignInLogs
        | where TimeGenerated > ago(window + baseline)
        | extend A = todynamic(Agent)
        | where A.agentSubjectType == "agentIDuser"
        | project TimeGenerated, AgentId = tostring(A.agentSubjectParentId), AgentName = "", Principal = "user",
            Resource = ResourceDisplayName, IPAddress, Failed = ResultType != "0");
// Only score agents that already had history before the window
let established = signIns | where TimeGenerated < ago(window) | summarize by AgentId;
let recent = signIns | where TimeGenerated >= ago(window) | join kind=inner established on AgentId;
let oldResources = signIns | where TimeGenerated < ago(window) | distinct AgentId, Principal, Resource;
let oldIps = signIns | where TimeGenerated < ago(window) | distinct AgentId, Principal, IPAddress;
let newResource = recent | join kind=leftanti oldResources on AgentId, Principal, Resource
    | summarize Hits = dcount(Resource) by AgentId | extend Signal = "new resource", Weight = 3;
let newIp = recent | join kind=leftanti oldIps on AgentId, Principal, IPAddress
    | summarize Hits = dcount(IPAddress) by AgentId | extend Signal = "new IP", Weight = 2;
let failureUp = signIns
    | summarize BaseRate = 100.0 * countif(Failed and TimeGenerated < ago(window)) / max_of(countif(TimeGenerated < ago(window)), 1),
        NewRate = 100.0 * countif(Failed and TimeGenerated >= ago(window)) / max_of(countif(TimeGenerated >= ago(window)), 1),
        NewCount = countif(TimeGenerated >= ago(window)) by AgentId
    | where NewCount >= 20 and NewRate - BaseRate >= 10
    | project AgentId, Hits = tolong(NewRate - BaseRate), Signal = "failure rate up", Weight = 2;
let names = AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(window + baseline)
    | summarize AgentName = take_any(ServicePrincipalName) by AgentId = ServicePrincipalId;
union newResource, newIp, failureUp
| summarize Score = sum(Weight), Signals = make_set(strcat(Signal, " (", tostring(Hits), ")")) by AgentId
| join kind=leftouter names on AgentId
| project AgentName = coalesce(AgentName, "(name not found)"), AgentId, Score, Signals
| order by Score desc
```

Sample output:

```text
AgentName             AgentId       Score  Signals
Contoso Triage Agent  11111111-...  3      ["new resource (5)"]
```

All `Hits` columns must be the same type (`long`), otherwise `union` splits the column in two and the final `summarize` fails. To add a signal, add another `let` that returns `AgentId, Hits, Signal, Weight` and add it to the `union`. Good candidates are queries 36, 38 and 41.

### Keeping a longer baseline

The 30-day hunting limit caps how much history a baseline can use. For a longer one, run a daily scheduled query that writes the aggregates (agent ID, resource, IP, hour, Graph family, tool) into a Sentinel custom table or summary rule, then compare against that table. The queries in this section would read from it unchanged except for the source of `known`.

---

## I. Agent runtime: Foundry, models, tools and content safety

The queries above start from Entra sign-ins. Agents built in Microsoft Foundry and most Copilot Studio agents do not show up there: their Entra agent ID appears only in the runtime telemetry, and their calls to other resources go out under a project managed identity. These queries use the Agent 365 runtime events in `CloudAppEvents` (`InvokeAgent`, `ExecuteToolBySDK`, `ExecuteToolByGateway`, `InferenceCall`, `AISpanOutput`) and `AADManagedIdentitySignInLogs` to close that gap.

### 44. Agents by runtime platform, and whether their own identity signs in

Every agent that shows up in the runtime telemetry (`InvokeAgent`, `ExecuteToolBySDK`, `ExecuteToolByGateway`, `InferenceCall`, `AISpanOutput`), grouped by the platform that hosts it, and checked against agent identity and agent user sign-ins. `InvokeAgent` events name the agent in `TargetAgentId`; the other events use `AgentId`.

```kql
let signedIn = union
    (AADServicePrincipalSignInLogs
        | where TimeGenerated > ago(30d)
        | extend A = todynamic(Agent)
        | where A.agentType == "agenticAppInstance"
        | distinct Id = ServicePrincipalId),
    (AADNonInteractiveUserSignInLogs
        | where TimeGenerated > ago(30d)
        | extend A = todynamic(Agent)
        | where A.agentSubjectType == "agentIDuser"
        | distinct Id = tostring(A.agentSubjectParentId));
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("InvokeAgent", "ExecuteToolBySDK", "ExecuteToolByGateway", "InferenceCall", "AISpanOutput")
| extend R = parse_json(RawEventData)
| extend AgentId = coalesce(tostring(R.TargetAgentId), tostring(R.AgentId)),
    AgentName = coalesce(tostring(R.TargetAgentName), tostring(R.AgentName)),
    Platform = coalesce(tostring(R.PlatformTargetAgentType), tostring(R.AgentPlatform), tostring(R.PlatformAgentType))
| where isnotempty(AgentId) and AgentId != "00000000-0000-0000-0000-000000000000"
| summarize Events = count(), Actions = make_set(ActionType), Names = make_set(AgentName, 3), First = min(Timestamp), Last = max(Timestamp)
    by AgentId, Platform
| join kind=leftouter (signedIn | distinct Id | extend SignsIn = true) on $left.AgentId == $right.Id
| extend IdentityUse = iff(SignsIn == true, "agent identity signs in", "no agent sign-in seen")
| project Platform, Names, AgentId, IdentityUse, Events, Actions, First, Last
| order by Platform asc, Events desc
```

Look for: agents marked `no agent sign-in seen`. Every Foundry agent ran tools and model calls under an Entra agent ID that never requested a token of its own. Its outbound calls went through the Foundry project managed identity instead (query 45). Copilot Studio agents behaved the same way, except one. For those agents, sign-in based queries (1 to 7, 23, 33 to 37) see nothing, and the access to review sits on a shared identity.

Sample output:

```text
Platform          Names                   IdentityUse              Events  First       Last
AzureAIFoundry    ["contoso-phish-triage"] no agent sign-in seen    555     2026-11-17  2026-11-20
AzureAIFoundry    ["contoso-agent-dev"]    no agent sign-in seen    78      2026-11-19  2026-11-19
CopilotStudio     ["Contoso HR Helper"]    agent identity signs in  299     2026-10-25  2026-11-20
CopilotStudio     ["Contoso HR Autonom"]   no agent sign-in seen    387     2026-10-26  2026-11-03
SecurityCopilot   ["...DetectionAuthoringAgent"] agent identity signs in  848  2026-11-19  2026-11-19
```

### 45. Foundry project managed identities

Foundry gives each project a system-assigned managed identity named `<account>/projects/<project>`. Agents that do not use their own agent identity (`project-managed-identity` authentication, legacy agents, or targets that need a managed identity) reach other resources through it. This lists those identities, what they requested and when.

```kql
AADManagedIdentitySignInLogs
| where TimeGenerated > ago(30d)
| where ServicePrincipalName has "/projects/"
| extend Account = tostring(split(ServicePrincipalName, "/")[0]), Project = tostring(split(ServicePrincipalName, "/")[2])
| summarize SignIns = count(), Resources = make_set(ResourceDisplayName, 10), Failures = countif(ResultType != "0"),
    IPs = dcount(IPAddress), First = min(TimeGenerated), Last = max(TimeGenerated)
    by Account, Project, ServicePrincipalId
| order by Last desc
```

Look for: project identities that reach resources outside the AI stack (Key Vault, Storage, Cosmos DB, Graph, Azure Resource Manager), new projects, and projects whose sign-ins line up in time with agent runs in query 44. Every agent in the project shares this identity, so its access cannot be attributed to one agent. Review it with the agent identities. The account-level managed identity (`<account>` without `/projects/`) and any AI gateway identity are worth adding to the filter if you use them.

Sample output:

```text
Account               Project            SignIns  Resources                                                             Failures  First       Last
contoso-aif-phish     defender-agents    5        ["Microsoft Cognitive Services","Azure AI Gateway","Azure Resource Manager",...]  0  2026-11-17  2026-11-19
contoso-aif-soc       soc-agents         7        ["Azure Resource Manager","Azure Storage","Azure Cosmos DB",...]   0         2026-11-16  2026-11-16
contoso-aif-prod      proj-socagents     1        ["Azure Resource Manager"]                                         0         2026-11-20  2026-11-20
```

### 46. Who invokes which agent, and what the content filter said

Who called which agent, from where, and how often the platform's content filter flagged the prompt. For Foundry agents, `InvokeAgent` carries the Azure AI content filter result as a JSON array in `ErrorMessage`, including `jailbreak.detected` and `blocked`. One invocation can carry several filter entries, so the query first collapses them per event.

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "InvokeAgent"
| extend R = parse_json(RawEventData)
| extend EventId = tostring(R.Id), CF = parse_json(tostring(R.ErrorMessage))
| mv-expand CF
| extend Jailbreak = tobool(CF.content_filter_results.jailbreak.detected), Blocked = tobool(CF.blocked)
| summarize Jailbreak = max(toint(Jailbreak)), Blocked = max(toint(Blocked)), Error = max(toint(tostring(R.ErrorType) == "Error")),
    Timestamp = any(Timestamp), IPAddress = any(IPAddress), ISP = any(ISP)
    by EventId, Caller = tostring(R.UserId), Target = tostring(R.TargetAgentName),
       Platform = tostring(R.PlatformTargetAgentType), Source = tostring(R.InvokeSource)
| summarize Invokes = count(), JailbreakDetected = sum(Jailbreak), BlockedPrompts = sum(Blocked), Errors = sum(Error),
    ISPs = make_set(ISP, 3), First = min(Timestamp), Last = max(Timestamp)
    by Caller, Target, Platform, Source
| order by JailbreakDetected desc, Invokes desc
```

Look for: callers you do not expect, `N/A` callers (agent-to-agent or service calls), a high `JailbreakDetected` share for one caller, and invocations from consumer ISPs. All jailbreak hits came from one user testing prompt injection against two Foundry agents.

Sample output:

```text
Caller                 Target                Platform         Invokes  JailbreakDetected  BlockedPrompts  Errors  ISPs
analyst@contoso.com    contoso-phish-triage  AzureAIFoundry   129      16                 16              23      ["<consumer ISP>","Microsoft Azure"]
analyst@contoso.com    contoso-agent-dev     AzureAIFoundry   44       10                 10              16      ["<consumer ISP>"]
user2@contoso.com      Contoso HR Helper     CopilotStudio    14       0                  0               0       ["Microsoft Azure"]
N/A                    contoso-phish-triage  AzureAIFoundry   4        0                  0               1       ["Microsoft Azure"]
```

### 47. Prompts the content filter flagged

One row per flagged prompt, with every content filter category that fired (`jailbreak`, `hate`, `violence`, `defender_for_ai` and so on), whether the prompt was blocked, and the conversation ID to pull the rest of the session.

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "InvokeAgent"
| extend R = parse_json(RawEventData)
| extend CF = parse_json(tostring(R.ErrorMessage))
| mv-expand CF
| extend Res = CF.content_filter_results
| mv-apply Category = bag_keys(Res) to typeof(string) on (
    where tobool(Res[Category].filtered) or tobool(Res[Category].detected)
    | summarize Categories = make_set(Category))
| where array_length(Categories) > 0
| project Timestamp, Caller = tostring(R.UserId), Target = tostring(R.TargetAgentName),
    Blocked = tobool(CF.blocked), SourceType = tostring(CF.source_type), Categories,
    ConversationId = tostring(R.ConversationId), IPAddress, ISP
| order by Timestamp desc
```

Look for: bursts of `jailbreak` from one caller within minutes, `defender_for_ai` detections, and categories hit with `Blocked = false`. Correlate with the Security for AI alerts in query 16: The "AI agent reconnaissance activity" alert on a Foundry agent fired within a minute of a series of blocked jailbreak prompts against the same agent.

Sample output:

```text
Timestamp             Caller               Target                Blocked  SourceType  Categories     ISP
2026-11-19T19:34:59Z  analyst@contoso.com  contoso-agent-dev     true     prompt      ["jailbreak"]  <consumer ISP>
2026-11-19T16:57:47Z  analyst@contoso.com  contoso-phish-triage  true     prompt      ["jailbreak"]  <consumer ISP>
2026-11-18T13:48:57Z  analyst@contoso.com  contoso-phish-triage  true     prompt      ["jailbreak"]  Microsoft Azure
```

### 48. Models each agent calls, and new models on established agents

`InferenceCall` events record the model behind each agent turn in `CopilotEventData.ModelTransparencyDetails`. This lists the models per agent and flags a model that appears for the first time on an agent that has been running for more than seven days.

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "InferenceCall"
| extend R = parse_json(RawEventData)
| mv-expand M = R.CopilotEventData.ModelTransparencyDetails
| extend M = parse_json(tostring(M))
| summarize Calls = count(), First = min(Timestamp), Last = max(Timestamp), ISPs = make_set(ISP, 3)
    by Agent = tostring(R.AgentName), AgentId = tostring(R.AgentId), Platform = tostring(R.AgentPlatform),
       Model = tostring(M.ModelName), Provider = tostring(M.ModelProviderName)
| join kind=inner (
    CloudAppEvents
    | where Timestamp > ago(30d)
    | where ActionType == "InferenceCall"
    | summarize AgentFirst = min(Timestamp) by AgentId = tostring(parse_json(RawEventData).AgentId)
  ) on AgentId
| extend NewModelForEstablishedAgent = AgentFirst < ago(7d) and First > ago(7d)
| project Agent, Platform, Model, Provider, Calls, First, Last, NewModelForEstablishedAgent, ISPs
| order by Agent asc, First asc
```

Look for: `NewModelForEstablishedAgent = true`, models routed through an unexpected deployment or gateway (the model name then carries the gateway and account, for example `<gateway>/<account>/<model>`), and agents that switch between several models. A changed model changes behavior and safety settings without any change to the agent's identity or permissions.

Sample output:

```text
Agent                   Platform         Model                                  Provider           Calls  First       NewModelForEstablishedAgent
contoso-phish-triage    AzureAIFoundry   gpt-5.6-luna-2026-07-09                microsoft.foundry  58     2026-11-17  false
contoso-phish-triage    AzureAIFoundry   contoso-apim/contoso-aif-phish/gpt-5-6-luna  microsoft.foundry  52  2026-11-18  false
contoso-phish-triage    AzureAIFoundry   gpt-5.6-terra-2026-07-09               microsoft.foundry  2      2026-11-20  false
...InvestigationAgent   SecurityCopilot  gpt-5.5                                AzureOpenAI        119    2026-11-19  false
```

### 49. Agent runtime calls from outside Microsoft's cloud

Agent runtime events whose client IP does not belong to Microsoft. Hosted agents run from Azure addresses, so a consumer or hosting ISP here usually means the agent was invoked or driven through the SDK from a workstation, or that a key or token is used outside the platform.

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("InvokeAgent", "ExecuteToolBySDK", "ExecuteToolByGateway", "InferenceCall")
| where isnotempty(IPAddress) and ISP !has "Microsoft"
| extend R = parse_json(RawEventData)
| extend Agent = coalesce(tostring(R.TargetAgentName), tostring(R.AgentName)),
    Platform = coalesce(tostring(R.PlatformTargetAgentType), tostring(R.AgentPlatform))
| summarize Events = count(), Actions = make_set(ActionType), Callers = make_set(tostring(R.UserId), 5),
    First = min(Timestamp), Last = max(Timestamp)
    by Agent, Platform, IPAddress, ISP, CountryCode
| order by Events desc
```

Look for: production agents with events from consumer ISPs, IPs that are not on your corporate egress list, and `InferenceCall` or `ExecuteToolBySDK` (not just `InvokeAgent`) from such an IP, which means the agent loop itself ran there.

Sample output:

```text
Agent                 Platform        IPAddress     ISP             Country  Events  Actions                                        Callers
contoso-phish-triage  AzureAIFoundry  203.0.113.24  <consumer ISP>  DE       126     ["InvokeAgent","InferenceCall","ExecuteToolBySDK"]  ["analyst@contoso.com","N/A"]
contoso-agent-dev     AzureAIFoundry  203.0.113.24  <consumer ISP>  DE       78      ["InvokeAgent","InferenceCall"]                 ["analyst@contoso.com","N/A"]
Contoso HR Helper     CopilotStudio   198.51.100.10 <consumer ISP>  DE       75      ["ExecuteToolBySDK","InvokeAgent"]              ["user2@contoso.com","N/A"]
```

### 50. Agents that run code or change files

Agents that ran shell, code or file-editing tools. The newer Defender agents in Security Copilot (`Global.Microsoft.Defender.*`) run in a sandbox with `bash`, `apply_patch`, `view`, `rg` and `glob` tools; custom agents can have a code interpreter.

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType startswith "ExecuteTool"
| extend R = parse_json(RawEventData)
| extend Tool = tostring(R.ToolName)
| where Tool matches regex @"(?i)(^|[._-])(bash|sh|shell|pwsh|powershell|python|code_interpreter|apply_patch|run_command|exec|write_file|create_file|edit_file)($|[._-])"
| summarize Runs = count(), Tools = make_set(Tool, 10), Failed = countif(isnotempty(tostring(R.ErrorCode))),
    First = min(Timestamp), Last = max(Timestamp)
    by Agent = tostring(R.AgentName), AgentId = tostring(R.AgentId), Platform = tostring(R.AgentPlatform)
| order by Runs desc
```

Look for: code execution on agents that are not supposed to have it, a sudden jump in `Runs`, and code tools on an agent that also has write access to Graph or Azure (queries 10, 13). Only Microsoft's own Defender agents used these tools.

Sample output:

```text
Agent                                               Platform         Runs  Tools                   First       Last
Global.Microsoft.Defender.PosturePrioritizationAgent SecurityCopilot  98    ["bash","apply_patch"]  2026-11-19  2026-11-19
Global.Microsoft.Defender.DetectionAuthoringAgent    SecurityCopilot  96    ["bash","apply_patch"]  2026-11-19  2026-11-19
Global.Microsoft.Defender.ReconAgent                 SecurityCopilot  32    ["bash"]                2026-11-19  2026-11-20
```

### 51. Agents that send data out: mail, messages, uploads, webhooks

Tool runs that send data out of the tenant boundary or to other people: sending or forwarding mail, posting messages, uploads, file sharing links, webhooks and raw HTTP requests. `ExecuteToolByGateway` events for the same agent show the call at the connector gateway.

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType startswith "ExecuteTool"
| extend R = parse_json(RawEventData)
| extend Tool = tostring(R.ToolName)
| where Tool matches regex @"(?i)(send|reply|forward|webhook|upload|share_?(file|link)|post_?message|http_?request)"
| summarize Runs = count(), Tools = make_set(Tool, 10), Channels = make_set(tostring(R.ChannelName), 3),
    First = min(Timestamp), Last = max(Timestamp)
    by ActionType, Agent = tostring(R.AgentName), AgentId = tostring(R.AgentId), Platform = tostring(R.AgentPlatform)
| order by Last desc
```

Look for: send tools on agents that only should read, sends from an agent with open prompt injection alerts (query 16) or Entra risk (queries 26 and 27), and sends from the Copilot Studio test pane in production. Extend the regex with the names of your own connector actions.

Sample output:

```text
ActionType            Agent              Platform                   Runs  Tools                                        Channels                        Last
ExecuteToolBySDK      Contoso HR Demo    CopilotStudio              4     ["mcp_MailTools.SendEmailWithAttachments"]   ["Copilot Studio Test Pane"]    2026-11-07
ExecuteToolByGateway                     CustomBuiltAgentsUsingSDK  4     ["SendEmailWithAttachments"]                 [""]                            2026-11-07
ExecuteToolBySDK      Contoso HR Helper  CopilotStudio              1     ["mcp_MailTools.SendEmailWithAttachments"]   ["Copilot Studio Test Pane"]    2026-10-25
```

### 52. Activity after an admin confirmed an agent compromised

An admin marked the agent as compromised in Entra ID Protection. This shows whether the agent kept signing in, being invoked or running tools afterwards. `AADRiskyAgents.Id` is the agent identity object ID.

```kql
let compromised = AADRiskyAgents
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by Id
    | where RiskState == "confirmedCompromised"
    | project AgentId = Id, AgentDisplayName, ConfirmedAt = RiskLastModifiedDateTime, IsEnabled;
let runtime = CloudAppEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("InvokeAgent", "ExecuteToolBySDK", "ExecuteToolByGateway", "InferenceCall", "AISpanOutput")
    | extend R = parse_json(RawEventData)
    | project Timestamp, AgentId = coalesce(tostring(R.TargetAgentId), tostring(R.AgentId)), Activity = ActionType,
        Detail = coalesce(tostring(R.ToolName), tostring(R.UserId));
let signins = AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(30d)
    | project Timestamp = TimeGenerated, AgentId = ServicePrincipalId, Activity = "SignIn", Detail = ResourceDisplayName;
compromised
| join kind=inner (union runtime, signins) on AgentId
| where Timestamp > ConfirmedAt
| summarize Events = count(), Activities = make_set(Activity), Details = make_set(Detail, 10), Last = max(Timestamp)
    by AgentDisplayName, AgentId, ConfirmedAt, IsEnabled
```

Look for: any row. Confirming compromise raises the risk to high but does not disable the agent. Unless a risk-based Conditional Access policy for agents or a manual disable follows, the agent keeps working. The agent was still enabled and invoked by two users, running SharePoint search and mail tools, the day after it was confirmed compromised.

Sample output:

```text
AgentDisplayName                      ConfirmedAt           IsEnabled  Events  Activities                                        Last
Contoso HR Helper (Microsoft Copilot Studio)  2026-11-19T09:33:26Z  true  82   ["InvokeAgent","AISpanOutput","ExecuteToolBySDK"]  2026-11-20T08:18:36Z
```

### 53. New tool source for an established agent

A tool source is the MCP server or toolset prefix of a tool name (`mcp_defender_phishing.run_hunting_query` gives `mcp_defender_phishing`, `perception_context-RunAdvancedHuntingQuery` gives `perception_context`). Plain tool names fall back to the tool type. This flags a source an agent used for the first time in the last seven days, when the agent itself has been running longer.

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType startswith "ExecuteTool"
| extend R = parse_json(RawEventData)
| extend Tool = tostring(R.ToolName), ToolType = tostring(R.ToolType), AgentId = tostring(R.AgentId)
| extend Source = case(Tool has ".", tostring(split(Tool, ".")[0]),
                       Tool matches regex @"^[A-Za-z0-9_]+-[A-Za-z]", tostring(split(Tool, "-")[0]),
                       strcat("(", ToolType, ")"))
| summarize SourceFirst = min(Timestamp), Runs = count(), Tools = make_set(Tool, 5)
    by Agent = tostring(R.AgentName), AgentId, Platform = tostring(R.AgentPlatform), Source, ToolType
| join kind=inner (
    CloudAppEvents
    | where Timestamp > ago(30d)
    | where ActionType startswith "ExecuteTool"
    | summarize AgentFirst = min(Timestamp) by AgentId = tostring(parse_json(RawEventData).AgentId)
  ) on AgentId
| where AgentFirst < ago(7d) and SourceFirst > ago(7d)
| project Agent, Platform, Source, ToolType, SourceFirst, AgentFirst, Runs, Tools
| order by SourceFirst desc
```

Look for: a new MCP server or connector on an established agent. Query 40 tracks individual tools for Security Copilot; this one works across platforms and at the server level, so a new server with many tools shows up once. It returned no rows for me, as most agents were less than two weeks old.

---

## J. Agent traffic through an AI gateway

An AI gateway (the Azure API Management AI gateway, also used by Foundry) sits between agents and their models and tools, and enforces token limits, content safety and key management. From a hunting point of view the question is simple: which agents actually go through it, and what happens on that path. Gateway configuration and key handling are control-plane topics and not covered here.

The Defender XDR tables show the path from three sides: the model route in `InferenceCall`, the gateway's identities in `EntraIdSpnSignInEvents`, and Defender for AI alerts on the model behind the gateway.

### 54. Agents whose model calls go through an AI gateway

When an agent calls a model through the gateway, `InferenceCall` records the model as `<gateway>/<backend account>/<deployment>` instead of the plain deployment name. This splits each agent's calls into gateway-routed and direct ones. The three-part name is what I saw for an API Management AI gateway in front of a Foundry account; check the format in your tenant.

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "InferenceCall"
| extend R = parse_json(RawEventData)
| mv-expand M = R.CopilotEventData.ModelTransparencyDetails
| extend Route = split(tostring(parse_json(tostring(M)).ModelName), "/")
| extend ViaGateway = array_length(Route) >= 3
| summarize Calls = count(), GatewayCalls = countif(ViaGateway),
    Gateways = make_set_if(tostring(Route[0]), ViaGateway, 5), Backends = make_set_if(tostring(Route[1]), ViaGateway, 5),
    Models = make_set(tostring(Route[-1]), 5), ISPs = make_set(ISP, 3),
    Errors = countif(isnotempty(tostring(R.CopilotEventData.ErrorMessage))), First = min(Timestamp), Last = max(Timestamp)
    by Agent = tostring(R.AgentName), AgentId = tostring(R.AgentId), Platform = tostring(R.AgentPlatform)
| extend GatewayShare = round(100.0 * GatewayCalls / Calls, 1)
| order by GatewayCalls desc, Calls desc
```

Look for: `GatewayShare` between 0 and 100. That agent reaches the same models both through the gateway and around it, so the gateway's token limits and content safety apply only to part of its traffic. The main Foundry agent sent 46 percent of its model calls through the gateway and the rest directly. Agents at 0 that should be behind a gateway are the next thing to check.

Sample output:

```text
Agent                 Platform        Calls  GatewayCalls  GatewayShare  Gateways         Backends               Models
contoso-phish-triage  AzureAIFoundry  112    52            46.4          ["contoso-aigw"]  ["contoso-aif-phish"]  ["gpt-5-6-luna","gpt-5.6-luna-2026-07-09",...]
contoso-agent-dev     AzureAIFoundry  34     19            55.9          ["contoso-aigw"]  ["contoso-aif-phish"]  ["gpt-5-6-luna","gpt-5.6-luna-2026-07-09"]
contoso-agent-gw      AzureAIFoundry  2      2             100.0         ["contoso-aigw"]  ["contoso-aif-phish"]  ["gpt-5-6-luna"]
...InvestigationAgent SecurityCopilot 119    0             0.0           []               []                     ["gpt-5.5"]
```

### 55. Identities on the gateway path

Two kinds of service principal sign-in mark the path in `EntraIdSpnSignInEvents`: callers requesting tokens for the `Azure AI Gateway` resource (here, a Foundry project managed identity), and the gateway's own managed identity requesting tokens for the backend (`Microsoft Cognitive Services`). The query takes the gateway names from query 54's routes, which assumes the gateway's managed identity carries the gateway's name, as a system-assigned identity does.

```kql
let gateways = CloudAppEvents
    | where Timestamp > ago(30d)
    | where ActionType == "InferenceCall"
    | mv-expand M = parse_json(RawEventData).CopilotEventData.ModelTransparencyDetails
    | extend Route = split(tostring(parse_json(tostring(M)).ModelName), "/")
    | where array_length(Route) >= 3
    | distinct Gateway = tostring(Route[0]);
EntraIdSpnSignInEvents
| where Timestamp > ago(30d)
| where ResourceDisplayName == "Azure AI Gateway" or ServicePrincipalName in (gateways)
| extend Direction = iff(ResourceDisplayName == "Azure AI Gateway", "caller to gateway", "gateway to backend")
| summarize SignIns = count(), Failures = countif(ErrorCode != 0), Resources = make_set(ResourceDisplayName, 5),
    First = min(Timestamp), Last = max(Timestamp)
    by Direction, ServicePrincipalName, ServicePrincipalId, IsManagedIdentity
| order by Direction asc, SignIns desc
```

Look for: callers to the gateway that are not the agents' project identities, and a gateway identity that requests tokens for anything besides the model backend and monitoring. Every agent behind the gateway reaches the models through that one identity, the same shared-identity problem as query 45.

Sample output:

```text
Direction           ServicePrincipalName                IsManagedIdentity  SignIns  Resources
caller to gateway   contoso-aif-phish/projects/agents   true               2        ["Azure AI Gateway"]
gateway to backend  contoso-aigw                        true               95       ["Azure Monitor Control Service","Microsoft Cognitive Services"]
```

### 56. Defender for AI alerts on the models behind the gateway

Defender for AI Services alerts name the model account (`CloudResource` evidence), not the agent. Joining that account to query 54's backends shows which agents send traffic to the attacked model, and through which gateway.

```kql
let routes = CloudAppEvents
    | where Timestamp > ago(30d)
    | where ActionType == "InferenceCall"
    | extend R = parse_json(RawEventData)
    | mv-expand M = R.CopilotEventData.ModelTransparencyDetails
    | extend Route = split(tostring(parse_json(tostring(M)).ModelName), "/")
    | where array_length(Route) >= 3
    | summarize Agents = make_set(tostring(R.AgentName), 10), Gateways = make_set(tostring(Route[0]), 3) by Backend = tostring(Route[1]);
let aiAlerts = AlertInfo
    | where Timestamp > ago(30d)
    | where DetectionSource == "Microsoft Defender for AI Services"
    | summarize arg_min(Timestamp, Title, Severity) by AlertId;
AlertEvidence
| where Timestamp > ago(30d)
| where AlertId in ((aiAlerts | project AlertId))
| summarize Backend = take_anyif(tostring(parse_json(AdditionalFields).ResourceName), EntityType == "CloudResource"),
    Users = make_set_if(AccountUpn, EntityType == "User" and isnotempty(AccountUpn), 5),
    IPs = make_set_if(RemoteIP, EntityType == "Ip" and isnotempty(RemoteIP), 5)
    by AlertId
| join kind=inner aiAlerts on AlertId
| mv-expand User = iff(array_length(Users) == 0, dynamic([""]), Users) to typeof(string)
| mv-expand IP = iff(array_length(IPs) == 0, dynamic([""]), IPs) to typeof(string)
| summarize Alerts = dcount(AlertId), Users = make_set_if(User, isnotempty(User), 5), IPs = make_set_if(IP, isnotempty(IP), 5),
    First = min(Timestamp), Last = max(Timestamp)
    by Title, Severity, Backend
| join kind=leftouter routes on Backend
| project Title, Severity, Backend, Gateways, AgentsOnThisBackend = Agents, Alerts, Users, IPs, First, Last
| order by Alerts desc
```

Look for: High-severity techniques such as ASCII smuggling, alerts on a backend that agents reach both through and around the gateway (query 54), and users or IPs that also appear in query 47. The backend behind the gateway raised eight ASCII smuggling alerts and five Prompt Shields jailbreak alerts, all from one test user.

Sample output:

```text
Title                                                        Severity  Backend            Gateways          AgentsOnThisBackend                                       Alerts
Suspected prompt injection using ASCII smuggling detected    High      contoso-aif-phish  ["contoso-aigw"]  ["contoso-phish-triage","contoso-agent-dev","contoso-agent-gw"]  8
A Jailbreak attempt on your Azure AI model deployment was blocked by Prompt Shields  Medium  contoso-aif-phish  ["contoso-aigw"]  [...]  4
```

---

## K. Copilot interactions: who drives them and what agents read

`CopilotInteraction` events in `CloudAppEvents` record each Copilot turn: who sent it, which Copilot app or agent handled it (`AppIdentity`, and `TargetAgentName` when an agent was called), and for Microsoft 365 and Copilot Studio agents the files, sites, connectors and web pages it read (`CopilotEventData.AccessedResources`, with the sensitivity label). The Sentinel table `CopilotActivity` was empty, while `CloudAppEvents` held 85,954 of these events.

### 57. Copilot interactions by agents and by people

```kql
let agentUpns = AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(30d)
    | extend A = todynamic(Agent)
    | where A.agentSubjectType == "agentIDuser"
    | distinct UserPrincipalName;
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "CopilotInteraction"
| extend R = parse_json(RawEventData)
| extend Who = tostring(R.UserId), App = tostring(R.AppIdentity)
| extend Caller = iff(Who in~ (agentUpns) or Who contains "AgentUser", "agent user", "person or service")
| summarize Events = count(), Principals = dcount(Who), Threads = dcount(tostring(R.CopilotEventData.ThreadId)),
    Examples = make_set(Who, 3), First = min(Timestamp), Last = max(Timestamp)
    by App, Caller
| order by Events desc
```

Look for: the share of interactions driven by agent users. Agent users sent 73 percent of all Security Copilot interactions (62,449 of 85,752), so Security Copilot activity is mostly agent activity there. Also look for Copilot Studio agents used by people outside the team that owns them.

Sample output:

```text
App                                          Caller             Events  Principals  Threads  Examples
Copilot.Security.SecurityCopilot             agent user         62449   8           15238    ["agentuser-aaaa@contoso.com",...]
Copilot.Security.SecurityCopilot             person or service  23303   9           5789     ["analyst@contoso.com",...]
Copilot.M365Copilot.Bizchat                  person or service  58      2           9        ["user2@contoso.com",...]
Copilot.Studio.<env>-cr608_HRHelper          person or service  53      2           32       ["user2@contoso.com",...]
```

### 58. Files and sites that Copilot agents read

Every resource an agent read to answer, one row per agent and resource, labelled ones first. `Type` separates documents from connectors (an MCP mail connector shows up as `Connector`) and from web pages (`CITATION`).

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "CopilotInteraction"
| extend R = parse_json(RawEventData)
| extend C = R.CopilotEventData
| mv-expand Res = C.AccessedResources
| extend Res = parse_json(tostring(Res))
| where isnotempty(Res.Name) or isnotempty(Res.SiteUrl)
| extend Agent = coalesce(tostring(C.TargetAgentName), tostring(R.AppIdentity)),
    Site = tostring(split(tostring(Res.SiteUrl), "/_layouts")[0])
| summarize Reads = count(), Users = make_set(tostring(R.UserId), 5), First = min(Timestamp), Last = max(Timestamp)
    by Agent, Resource = tostring(Res.Name), Type = tostring(Res.Type), Action = tostring(Res.Action),
       SensitivityLabelId = tostring(Res.SensitivityLabelId), Site
| extend Labeled = isnotempty(SensitivityLabelId)
| order by Labeled desc, Reads desc
```

Look for: labelled files read by agents that should not need them, the same sensitive file read through several agents or by several users, web citations on agents that also have send or write tools (a path for cross-prompt injection), and reads by an agent after it was confirmed compromised (query 52). An HR agent read two labelled salary lists, and it still read them on the day after an admin had confirmed it compromised.

Sample output:

```text
Agent                          Resource                  Type       Action        Labeled  Site                                   Reads  Users
Copilot.Studio.<env>-HRAutonom  Salary-Archive.xlsx       Excel      Read          true     https://contoso.sharepoint.com/sites/HR  36     ["user2@contoso.com"]
Copilot.Studio.<env>-HRHelper   Salary-Archive.xlsx       Excel      Read          true     https://contoso.sharepoint.com/sites/HR  14     ["user2@contoso.com","user3@contoso.com"]
Copilot.Studio.<env>-HRHelper   <agent>.outlookmailmcp... Connector  mcp_MailTools false                                            59     ["user2@contoso.com","user3@contoso.com"]
Copilot.M365Copilot.Bizchat     (web page)                CITATION   Read          false    https://example.org/...                21     ["user4@contoso.com"]
```

### 59. Jailbreak verdicts in Copilot interactions

Messages in Microsoft 365 Copilot and Copilot Studio interactions can carry a `JailbreakDetected` verdict. This counts them per agent.

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "CopilotInteraction"
| extend R = parse_json(RawEventData)
| extend C = R.CopilotEventData
| mv-expand Msg = C.Messages
| extend Msg = parse_json(tostring(Msg))
| where isnotnull(Msg.JailbreakDetected)
| summarize Messages = count(), Jailbreaks = countif(tobool(Msg.JailbreakDetected)),
    Users = make_set_if(tostring(R.UserId), tobool(Msg.JailbreakDetected), 5),
    LastJailbreak = maxif(Timestamp, tobool(Msg.JailbreakDetected))
    by Agent = coalesce(tostring(C.TargetAgentName), tostring(R.AppIdentity))
| order by Jailbreaks desc, Messages desc
```

Look for: any `Jailbreaks` above zero, and users who repeat them. No message carried a positive verdict, although the same HR agent had cross-prompt injection alerts (query 16): those come from Security for AI, not from this message flag, so check both.

---

## Detection ideas

| Idea | Based on | Why |
| --- | --- | --- |
| Agent identity or agent user requests a resource not seen in the baseline | Query 5 | Early sign of changed behavior |
| Agent writes to directory objects (`servicePrincipals`, `applications`, `groups`, `roleManagement`, `users`) | Query 10 | Most agents should only read |
| New app role assignment or Azure role write for an agent by an unexpected actor | Queries 11 to 13 | Permission creep and privilege escalation |
| Agent sign-ins from a new IP or country | Queries 1 and 2 (`IPs`) | Stolen token or relocated workload |
| Conditional Access block or consent failure for an agent | Queries 6 and 7 | Broken agent or probing |
| Burst of `401`/`403` across many Graph paths from one agent | Query 9 | Enumeration of permissions |
| Alert on `EntityType == "AIAgent"` | Query 16 | Prompt injection against an agent |
| Agent with alerts on three or more separate days | Query 17a | Recurring attack or misuse, not a one-off test |
| Same user or IP in alerts against several agents | Query 17b | One actor probing many agents |
| ATLAS technique other than prompt injection on an agent, or reconnaissance on an agent with tool access | Query 17c | Attack moving past the prompt |
| Agent alerts staying `New` for more than a day | Queries 18 and 20 | Triage gap for agent-related detections |
| Agent-related incidents closed `Undetermined` | Queries 19 and 20 | Detections that nobody classified |
| Incidents closed by an agent user without a classification | Queries 21 and 22 | Automation closing work without a decision |
| Agent user or application changing case status, classification or determination | Queries 21b and 22b | Decisions taken by automation, with the before and after value |
| UEBA first-time country, ISP or action on an agent older than a week, or `InvestigationPriority` above 5 | Query 23 | Behavior change on an established agent |
| UEBA anomaly that names an agent | Query 24 | Anomalous authentication for an agent |
| Entra risk state `atRisk` or `confirmedCompromised` for an agent | Queries 26 and 27 | Behavioral risk flagged by ID Protection |
| Defender indicator with severity High on an agent, or a published agent with privileged data access | Queries 28 to 30 | Posture risk before any misuse |
| Agent with high Defender posture risk and `none` in Entra | Query 30 | Misconfiguration, not an active attack |
| Any interactive sign-in by an agent user | Query 32 | Agent users never sign in interactively |
| Agent identity authenticating with a secret or certificate instead of a federated credential | Query 33 | Changed credential, possibly a changed blueprint |
| New IP, new ASN or off-hours activity for an established agent | Queries 34 and 35 | Moved or abused workload |
| Daily sign-in spike or drop on an agent with 14 or more days of history | Query 36 | Runaway agent, or an agent that lost a credential or trigger |
| New write-capable Graph API family for an established agent | Query 38 | Agent doing something it did not do before |
| Granted permission with no matching call in 30 days | Query 39 | Least-privilege cleanup |
| New tool, or a browser or scripting user agent on an agent user | Queries 40 and 41 | New capability, or the account used from another client |
| Anomaly score of 4 or more for an established agent | Query 43 | Several small changes at once |
| Agent active in runtime telemetry with no agent identity sign-in | Query 44 | Access sits on a shared project identity, invisible to sign-in hunting |
| Foundry project identity reaching a resource outside the AI stack | Query 45 | Shared identity with access no single agent owns |
| Several jailbreak detections from one caller against an agent | Queries 46 and 47 | Prompt injection testing or attack |
| New model or new gateway route for an established agent | Query 48 | Behavior change without an identity change |
| Agent runtime events from a consumer or unknown ISP | Query 49 | Agent loop run outside the platform, or a leaked key |
| Code execution tools on an agent that should not have them | Query 50 | Sandbox escape and tampering surface |
| Mail send, upload or webhook tool runs by an agent | Query 51 | Data leaving through an agent |
| Any activity after an agent was confirmed compromised | Query 52 | Confirmation alone does not stop the agent |
| New MCP server or connector on an established agent | Query 53 | New capability added outside change control |
| Agent with a gateway share between 0 and 100 percent | Query 54 | Part of the agent's model traffic bypasses the gateway's limits and content safety |
| Unexpected caller to the AI gateway, or gateway identity reaching beyond its backend | Query 55 | Gateway used outside the agent path, or a widened shared identity |
| Defender for AI alert on a model that agents reach through a gateway | Query 56 | Attack on the agent path that the agent alerts alone do not name |
| Labelled file read by an agent outside its purpose, or by an agent confirmed compromised | Queries 58 and 52 | Sensitive data reaching an agent that should not have it |
| Web citations on an agent that also has send or write tools | Queries 58 and 51 | Cross-prompt injection path from web content to an action |
| Positive `JailbreakDetected` verdict in a Copilot interaction | Query 59 | Jailbreak attempt against a Microsoft 365 or Copilot Studio agent |

## Limits of this data

- No Graph events for `inheritedAppRoleAssignments` or other permission reads, so you cannot see who inspected an agent's permissions.
- The Defender XDR sign-in tables (`EntraIdSpnSignInEvents`, `EntraIdSignInEvents`) have no agent marker. Use the workspace tables when you can.
- `GraphAPIAuditEvents` and `MicrosoftGraphActivityLogs` only cover Graph. Azure Resource Manager and Defender API calls by agents are not in it.
- `AlertInfo` and `AlertEvidence` have no status, so queries 17 to 17c cannot tell open from closed alerts. Resolved and closed state comes from `SecurityAlert` and `SecurityIncident`, which need the Sentinel workspace. Matching agents there relies on the agent ID appearing in the alert payload, so alerts that name only a display name are missed.
- The agent ID set in queries 17 to 25 and 31 comes from sign-ins in the last 30 days. Agents that have not signed in are not included.
- `SecurityIncident` ClosedBy is the last modifier, not necessarily the decision maker. Check the closing comment, or use `SecurityCaseEvent` (queries 21b and 22b), which records every change and its author.
- `CloudAppEvents` agent events depend on the product that emits them (Security Copilot, Copilot Studio, Foundry, Security for AI). First-party agents sometimes report an empty agent ID.
- Foundry agents and most Copilot Studio agents never sign in with their own agent identity, so queries 1 to 7, 23 and 33 to 37 miss them. Their outbound access shows up only under the project managed identity (query 45), which cannot be tied to a single agent from the logs.
- The content filter result in `InvokeAgent` is stored as JSON text in `ErrorMessage`, also on successful calls. Its format is not documented and may change.
