# Cloud Cost & Security Auditor (GCP)

A daily serverless scan that finds money being wasted and doors left open in Google Cloud
projects, stores every finding in **BigQuery**, and posts a summary to **Slack**.

```
Cloud Scheduler (9 AM IST, OIDC)
        │
        ▼
Cloud Function gen2 (Python, read-only SA)
        │  Compute API ─ VMs, disks, firewall rules
        │  Monitoring API ─ 7-day avg CPU per VM
        ▼
   checks.py ─► findings ─┬─► BigQuery  audit.findings  (partitioned by day, 6-month retention)
                          └─► Slack webhook (from Secret Manager)
```

## What it checks

| Check | Category | Rule | Severity |
|---|---|---|---|
| `idle_vm` | cost | RUNNING VM with < 5% average CPU over 7 days | MEDIUM |
| `unattached_disk` | cost | Persistent disk with no attached VM, with a monthly cost estimate | LOW / MEDIUM (≥ $10) |
| `open_firewall` | security | Enabled ingress rule from `0.0.0.0/0` or `::/0` exposing SSH, RDP, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch or Docker API (port ranges included) | HIGH |
| `open_firewall` | security | Same, but all ports open | CRITICAL |

Sample Slack message:

```
🚨 GCP audit for my-project: 3 findings (1 CRITICAL · 1 HIGH · 1 MEDIUM)
Estimated waste: $102.00/month
• CRITICAL open_firewall `allow-all` (default): All ports open to the internet on ALL instances...
• HIGH open_firewall `allow-ssh` (default): SSH (22) open to the internet on ALL instances...
• MEDIUM unattached_disk `old-db-disk` (asia-south1-a): 500 GB pd-ssd not attached to any VM...
```

## Design

- **Read-only by construction.** The function's service account has only `compute.viewer` and
  `monitoring.viewer` on audited projects, plus `bigquery.dataEditor` on the one `audit` dataset.
  It cannot modify anything it scans.
- **No secrets in code or state.** The Slack webhook lives in Secret Manager and is mounted as an
  env var at runtime. Terraform creates the secret but never the value.
- **Private function.** Ingress is internal-only and the scheduler calls it with an OIDC token, so
  there is no public endpoint.
- **Testable core.** `checks.py` is pure functions over plain dataclasses. All Google API code is
  isolated in `gcp.py`, so the rules are unit-tested without credentials.
- **Cheap.** One run a day, BigQuery table partitioned by day and clustered by
  project/check/severity, partitions expire after 180 days.
- **Multi-project.** Set `audit_projects` and the same function scans all of them.

## Layout

```
src/auditor/
  models.py   Vm, Disk, FirewallRule, Finding
  checks.py   the rules
  gcp.py      Compute + Monitoring API readers
  report.py   BigQuery writer, Slack Block Kit message
  main.py     Cloud Function entry point + CLI
terraform/    function, scheduler, BigQuery, secret, IAM
terraform/queries.sql   trend queries over the findings table
scripts/package.sh      builds the function source folder
```

## Run locally

```bash
uv sync
uv run pytest -q
gcloud auth application-default login
uv run auditor my-project            # human-readable
uv run auditor my-project --json     # raw findings
```

## Deploy

```bash
./scripts/package.sh
cd terraform
terraform init
terraform apply -var project_id=$PROJECT
# optional: -var 'audit_projects=["proj-a","proj-b"]'

# add the Slack webhook (kept out of Terraform state)
echo -n "https://hooks.slack.com/services/..." | \
  gcloud secrets versions add auditor-slack-webhook --data-file=-

# run it now instead of waiting for 9 AM
gcloud scheduler jobs run cost-security-auditor-daily --location=asia-south1
```
