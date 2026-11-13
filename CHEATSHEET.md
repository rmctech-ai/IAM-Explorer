# IAM Cheat Sheet

_Auto-generated from the IAM Explorer lessons. One master memory hook + the key commands per lesson._

## 01 · What is IAM?

> ★ AuthN = "who are you?" (ID check). AuthZ = "what may you do?" (guest list). IAM does both on every call.

| Command | What it does |
|---|---|
| `aws sts get-caller-identity` | who am I? |
| `Principal · Action · Resource · Context` | parts of a request |
| `arn:aws:svc:region:acct:res` | ARN format |
| `default deny` | no Allow → denied |
| `explicit Deny wins` | always |

**Memory hooks:**

- **Every call is checked**: P-A-R-C: Principal, Action, Resource, Context. The four parts of every request.
- **Authentication**: "Who am I?" → aws sts get-caller-identity.
- **Authorization**: Default deny. Allow opens. Deny slams shut.
- **ARNs**: "arn : aws : service : region : account : resource". Empty slots mean "not needed here".
- **IAM is global & free**: Global, free, logged.

## 02 · The Root User

> ★ Root = the master key. MFA it, lock it in a safe, use it almost never.

| Command | What it does |
|---|---|
| `MFA on root` | first thing |
| `AccountAccessKeysPresent = 0` | no root keys |
| `get-account-summary` | check MFA/keys |
| `Admins group + AdministratorAccess` | daily admin |
| `alert on Root ConsoleLogin` | detect misuse |

**Memory hooks:**

- **What root can do**: Root can't be limited by IAM. So limit who can reach it.
- **Enable MFA**: Password + device. Always for root.
- **No root access keys**: Root keys = 0. Always.
- **Daily admin identity**: Root for emergencies, admin identity for everything else.
- **Watch for root use**: Root used? Get paged.

## 03 · Users, Groups & Credentials

> ★ Users have permanent keys; roles have temporary ones. Permanent keys leak.

| Command | What it does |
|---|---|
| `aws iam create-user --user-name u` | create user |
| `aws iam add-user-to-group` | join group |
| `aws iam list-access-keys` | see keys |
| `update-access-key --status Inactive` | disable key |
| `get-credential-report` | audit all creds |
| `aws configure sso` | SSO profile |

**Memory hooks:**

- **IAM users**: One human, one identity. Shared logins kill accountability.
- **Groups**: Attach to groups, not to people.
- **Access keys**: AKIA = permanent, ASIA = temporary.
- **When keys leak**: Deactivate → investigate → rotate → delete.
- **The modern way**: "Humans → SSO, machines → roles, users → rare."

## 04 · Policy Anatomy

> ★ "E-A-R-C": Effect, Action, Resource, Condition. "Allow s3:GetObject on this bucket when MFA is on."

| Command | What it does |
|---|---|
| `"Version": "2012-10-17"` | always |
| `"Effect": "Allow" \| "Deny"` | grant / block |
| `"Action": "s3:GetObject"` | service:Operation |
| `"Resource": "arn:aws:s3:::b/*"` | objects |
| `"Resource": "arn:aws:s3:::b"` | bucket (ListBucket) |
| `aws iam simulate-principal-policy` | test permissions |

**Memory hooks:**

- **Document shape**: Version is always "2012-10-17". Memorize it like a phone number.
- **Effect**: Allow opens, Deny locks, and Deny always wins.
- **Action**: service:Verb. A star means "every verb" — use sparingly.
- **Resource**: ListBucket → bucket ARN. GetObject → bucket/* ARN.
- **Condition (preview)**: Condition = "…but only if".

## 05 · Policy Evaluation Logic

> ★ "Deny beats Allow beats Default-deny." One explicit Deny anywhere = denied, no matter how many Allows.

| Command | What it does |
|---|---|
| `implicit deny` | no Allow matched |
| `explicit deny` | a Deny matched: final |
| `Deny > Allow > default` | priority |
| `simulate-principal-policy` | test decisions |
| `"…with an explicit deny in X"` | look at X |
| `"…no identity-based policy allows"` | add Allow |

**Memory hooks:**

- **Default: implicit deny**: Silence = No.
- **Allow grants**: One matching Allow is enough (if no Deny).
- **Explicit deny wins**: "Deny trumps all."
- **Reading the error**: "no … allows" = add Allow. "explicit deny in X" = go look at X.
- **The full chain**: "Deny, Org, Resource, Boundary, Session, Identity" → "Don't Open Rooms Before Security Inspects".

## 06 · Conditions & Policy Variables

> ★ Condition = Operator → Key → Value. "Bool → aws:MultiFactorAuthPresent → true".

| Command | What it does |
|---|---|
| `"Bool": {"aws:MultiFactorAuthPresent": "true"}` | require MFA |
| `"IpAddress": {"aws:SourceIp": "x/24"}` | from network |
| `"StringEquals": {"aws:RequestedRegion": [...]}` | regions |
| `${aws:username}` | per-user resources |
| `aws:ResourceTag/k vs aws:PrincipalTag/k` | ABAC |
| `...IfExists` | only if key present |

**Memory hooks:**

- **Condition structure**: Values OR, keys AND.
- **Common operators**: Match the operator to the data type.
- **Require MFA**: Dangerous action? Require MFA.
- **Policy variables**: &#36;{aws:username} = "the person asking".
- **ABAC with tags**: Match my tag to its tag.

## 07 · Roles & STS

> ★ A role is a costume, not a person. Trust policy = who may wear it. Permission policy = what the costume lets you do.

| Command | What it does |
|---|---|
| `aws iam create-role --assume-role-policy-document` | create role + trust |
| `"Principal": {"Service": "lambda.amazonaws.com"}` | trust a service |
| `aws sts assume-role --role-arn ...` | get temp creds |
| `attach-role-policy` | give permissions |
| `instance profile` | role for EC2 |
| `assumed-role/... in ARN` | you are in a role |

**Memory hooks:**

- **What a role is**: Roles = temporary by design.
- **Trust policy**: Trust = WHO. Permissions = WHAT.
- **STS & temporary creds**: Key + Secret + Session Token = temp creds.
- **Permission policies**: Inside the role, you are the role.
- **Where roles appear**: Workload needs AWS access? Give it a role.

## 08 · Resource Policies & Cross-Account

> ★ Identity policy = my badge's rights. Resource policy = the door's own guest list.

| Command | What it does |
|---|---|
| `aws s3api put-bucket-policy` | attach bucket policy |
| `"Principal": {"AWS": "arn:aws:iam::ACCT:root"}` | trust an account |
| `cross-account = both sides allow` | rule |
| `role_arn + source_profile` | switch role in CLI |
| `sts:ExternalId` | vendor safety |
| `get-public-access-block` | check public block |

**Memory hooks:**

- **Resource-based policies**: Principal present? It's a resource policy.
- **Same account**: Same account: identity OR resource.
- **Cross-account**: Cross-account = two keys: their door AND your badge.
- **Role-based cross-account**: Cross-account? Usually "assume a role in their account".
- **Public access danger**: "Principal": "*" → stop and double-check.

## 09 · Managed Policies & Boundaries

> ★ Effective permissions = identity policy ∩ boundary. The boundary is the fence; the policy is how far you walk inside it.

| Command | What it does |
|---|---|
| `arn:aws:iam::aws:policy/...` | AWS managed |
| `create-policy-version --set-as-default` | version yours |
| `put-role-permissions-boundary` | set ceiling |
| `effective = policy ∩ boundary` | rule |
| `iam:PermissionsBoundary condition` | safe delegation |
| `iam:PassRole` | escalation risk |

**Memory hooks:**

- **AWS managed policies**: AWS managed = quick start, not least privilege.
- **Customer managed & inline**: Prefer customer managed; inline only for one-offs.
- **Permissions boundary**: Boundary limits, never grants.
- **Boundary in action**: Outside the fence = denied, whatever the policy says.
- **Safe delegation**: CreateRole only with the boundary attached.

## 10 · Organizations & SCPs

> ★ SCP = the law of the country; IAM policies = rules inside each house. No house rule can break the law.

| Command | What it does |
|---|---|
| `aws organizations list-accounts` | see accounts |
| `SCP = ceiling for member accounts` | rule |
| `Deny + aws:RequestedRegion` | region lock |
| `Deny cloudtrail:StopLogging` | protect logs |
| `management account unaffected by SCPs` | caveat |
| `Control Tower` | landing zone |

**Memory hooks:**

- **Why many accounts**: Account = blast-radius boundary.
- **SCPs are ceilings**: SCP + IAM must both allow. SCPs never grant.
- **Region lock**: Deny + NotAction(global services) + StringNotEquals region.
- **Protect security services**: First guardrail: protect the logs.
- **Control Tower & good habits**: Management account = no workloads. Test SCPs in a sandbox OU.

## 11 · Identity Center & Federation

> ★ "Log in once, assume many." Identity Center turns one login into short-lived roles in any account.

| Command | What it does |
|---|---|
| `aws configure sso` | set up profile |
| `aws sso login --profile p` | daily login |
| `permission set + group + account` | assignment |
| `SCIM` | auto-provision |
| `AssumeRoleWithWebIdentity` | OIDC (GitHub) |
| `token...:sub = repo:org/repo:ref:...` | pin the repo |

**Memory hooks:**

- **Why federate**: One identity, temporary access, central offboarding.
- **Permission sets**: Group + permission set + account = access.
- **CLI with SSO**: aws sso login, then work. No keys.
- **SCIM & groups**: SCIM = auto-sync people & groups.
- **OIDC for GitHub Actions**: CI to AWS = OIDC role, scoped to repo + branch.

## 12 · Least Privilege Toolkit

> ★ "Start narrow, grant by need, prune by data."

| Command | What it does |
|---|---|
| `generate-service-last-accessed-details` | what was used |
| `accessanalyzer validate-policy` | lint a policy |
| `start-policy-generation` | policy from CloudTrail |
| `simulate-custom-policy` | test a draft |
| `narrow actions · resources · time` | least privilege |

**Memory hooks:**

- **What least privilege means**: Narrow actions, narrow resources, short time.
- **Last accessed data**: Unused for 90 days? Remove it.
- **IAM Access Analyzer**: Analyzer finds doors open to outsiders.
- **Generate from CloudTrail**: Observe, generate, review, replace.
- **Test before you ship**: Simulate allows AND denies.

## 13 · Auditing with CloudTrail

> ★ CloudTrail = the black-box recorder of your AWS account.

| Command | What it does |
|---|---|
| `aws cloudtrail lookup-events` | search 90 days |
| `userIdentity · eventName · sourceIPAddress · errorCode` | key fields |
| `create-trail --is-organization-trail` | central logging |
| `--enable-log-file-validation` | tamper evidence |
| `Athena / CloudTrail Lake` | SQL hunting |
| `EventBridge on Root ConsoleLogin` | alert |

**Memory hooks:**

- **Event history**: 90 days free; trails for forever.
- **Read an event**: Who (userIdentity), What (eventName), Where (sourceIP), Result (errorCode).
- **Organization trail**: Central, immutable, validated.
- **Hunt with SQL**: AccessDenied spikes = probing or broken config. Investigate both.
- **Alert in real time**: Watch the IAM-changing events.

