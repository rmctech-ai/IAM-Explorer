window.COURSE = {
 "short": "IAM",
 "key": "iam-explorer-v1",
 "prompt": "$",
 "termTitle": "aws cli",
 "where": "CLI",
 "lab": "iam",
 "errRe": "AccessDenied|error occurred|Error:|EXPLICIT DENY|IMPLICIT DENY|denied",
 "cats": [
  [
   "all",
   "ALL"
  ],
  [
   "core",
   "FUNDAMENTALS"
  ],
  [
   "policy",
   "POLICIES"
  ],
  [
   "access",
   "ROLES & ACCESS"
  ],
  [
   "gov",
   "GOVERNANCE"
  ],
  [
   "ops",
   "AUDIT & OPS"
  ]
 ],
 "catTitle": {
  "core": "IAM FUNDAMENTALS",
  "policy": "POLICIES IN DEPTH",
  "access": "ROLES, FEDERATION & CROSS-ACCOUNT",
  "gov": "GOVERNANCE AT SCALE",
  "ops": "LEAST PRIVILEGE & AUDITING"
 },
 "kinds": {
  "iam": [
   "IDENTITY",
   "#1d5bd8"
  ],
  "pol": [
   "POLICY",
   "#f59e0b"
  ],
  "sts": [
   "STS / ROLE",
   "#7c3aed"
  ],
  "eval": [
   "EVALUATION",
   "#0d9488"
  ],
  "org": [
   "ORGANIZATIONS",
   "#db2777"
  ],
  "audit": [
   "AUDIT",
   "#0891b2"
  ],
  "err": [
   "DENIED",
   "#e11d48"
  ],
  "cli": [
   "CLI",
   "#64748b"
  ]
 },
 "layers": [
  "IDENTITIES",
  "POLICIES",
  "EVALUATION",
  "ROLES & STS",
  "GOVERNANCE",
  "AUDIT"
 ],
 "levels": [
  [
   0,
   "IAM ROOKIE"
  ],
  [
   150,
   "POLICY READER"
  ],
  [
   400,
   "POLICY WRITER"
  ],
  [
   800,
   "ROLE ASSUMER"
  ],
  [
   1300,
   "LEAST-PRIVILEGE PRO"
  ],
  [
   2000,
   "GUARDRAIL BUILDER"
  ],
  [
   2900,
   "IAM ARCHITECT"
  ]
 ],
 "handsOn": "Policy Simulator challenge"
};
COURSE.errRe = new RegExp(COURSE.errRe, "i");
