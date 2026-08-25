# Vulnerability class reference: IAC (Infrastructure-as-Code & CI/CD misconfiguration)

You are auditing **infrastructure-as-code and CI/CD definitions**, not application
logic. These files provision cloud resources, containers, clusters, and pipelines;
their bugs are *misconfigurations* that grant excess exposure, privilege, or a
supply-chain foothold. There is often no "attacker-controlled input → sink" data
flow — the file's declared state **is** the vulnerability. Judge each finding by
the concrete capability the misconfiguration grants an attacker.

Read every IaC/CI file you are given in full. For each issue, report the exact
`file:line`, the insecure setting, the concrete impact, and the fix.

## What to look for, by technology

**Terraform / HCL / CloudFormation**
- Network exposure: security-group / firewall ingress from `0.0.0.0/0` (or `::/0`)
  to sensitive ports (22, 3389, 5432, 6379, 27017, 9200, all-ports) — CWE-284.
- Public storage: S3 buckets/objects with public-read/write ACLs or policies,
  `block_public_access` disabled; public blob/GCS buckets — CWE-732.
- Missing encryption: unencrypted EBS/RDS/S3/SNS/SQS, disabled TLS, `storage_encrypted = false` — CWE-311.
- Over-broad IAM: `Action: "*"`, `Resource: "*"`, `Principal: "*"`, `AssumeRole`
  trust to `*`, wildcard `iam:PassRole` — CWE-284 / CWE-269.
- Hardcoded secrets: access keys, passwords, tokens in `.tf`/vars/state — CWE-798.
- Disabled safeguards: logging/audit off, deletion protection off, public snapshots.

**Dockerfile / container**
- Runs as **root** (no `USER` directive, or `USER root`) — CWE-250.
- Secrets baked into layers via `ENV`/`ARG`/`COPY` of key material — CWE-798.
- `latest` / unpinned base images; `curl … | sh` or `wget … | bash` install steps
  (supply-chain / no integrity check) — CWE-494.
- `--privileged` hints, added Linux capabilities, docker socket mounted.

**Kubernetes / Helm**
- `securityContext.privileged: true`, `allowPrivilegeEscalation: true`,
  `runAsUser: 0`, added `capabilities` (`SYS_ADMIN`, `NET_ADMIN`) — CWE-250 / CWE-269.
- `hostPath`, `hostNetwork`, `hostPID`, `hostIPC` mounts — CWE-668.
- No resource limits (DoS), no `readOnlyRootFilesystem`, default service account
  with broad RBAC (`ClusterRole` `*`/`*`) — CWE-284 / CWE-400.
- Secrets in plain env / ConfigMaps — CWE-312.

**GitHub Actions / CI-CD**
- `pull_request_target` (or `workflow_run`) that checks out and **runs untrusted PR
  code** with access to secrets — the classic CI RCE / secret-exfil — CWE-94 / CWE-829.
- **Script injection**: untrusted `${{ github.event.* }}` (issue title, PR body,
  branch name) interpolated directly into a `run:` shell block — CWE-94.
- Unpinned third-party actions (`@main`/`@v3` tag, not a full SHA) — supply chain — CWE-829.
- `permissions: write-all` / broad `GITHUB_TOKEN`; secrets echoed to logs.
- Self-hosted runners on public repos (untrusted-code execution).

**Ansible / config mgmt**
- `become: true` with hardcoded passwords; `no_log: false` on secret-bearing tasks;
  `validate_certs: false`; world-readable file modes on secrets — CWE-798 / CWE-732.

## Disposition & output

Use the shared gate discipline, adapted: Gate 1 (is this file actually applied /
not an example or disabled?), Gate 3 (what capability does the misconfiguration
grant — public data, RCE, privilege escalation, secret disclosure?). A setting in a
`*.example`/`sample`/test fixture, or a resource that is clearly commented-out, is
**not** a finding. Cite `file:line`, name the CWE, state the concrete impact and
the one-line fix. Report each distinct misconfiguration separately.
