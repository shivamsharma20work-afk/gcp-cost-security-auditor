"""Entry points: Cloud Function (HTTP, called by Cloud Scheduler) and a local CLI."""

import argparse
import json
import logging
import os

import functions_framework

from auditor import checks, gcp, report
from auditor.models import Finding

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("auditor")


def audit(project: str) -> list[Finding]:
    vms = gcp.list_vms(project)
    findings = [
        *checks.idle_vms(project, vms, gcp.avg_cpu_by_instance(project)),
        *checks.unattached_disks(project, gcp.list_disks(project)),
        *checks.open_firewall_rules(project, gcp.list_firewall_rules(project)),
    ]
    log.info("project=%s vms=%d findings=%d", project, len(vms), len(findings))
    return findings


@functions_framework.http
def run_audit(request):
    """Scans every project in AUDIT_PROJECTS, stores findings, posts one Slack summary each."""
    projects = [p.strip() for p in os.environ["AUDIT_PROJECTS"].split(",") if p.strip()]
    table = os.environ["BQ_TABLE"]
    webhook = os.environ.get("SLACK_WEBHOOK_URL")  # mounted from Secret Manager

    total = 0
    for project in projects:
        findings = audit(project)
        total += len(findings)
        report.write_bigquery(findings, table)
        if webhook:
            report.send_slack(webhook, report.slack_message(project, findings))

    return {"projects": len(projects), "findings": total}, 200


def cli() -> None:
    parser = argparse.ArgumentParser(description="Audit a GCP project for waste and exposure")
    parser.add_argument("project")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    args = parser.parse_args()

    findings = audit(args.project)
    if args.json:
        print(json.dumps([f.to_row() for f in findings], indent=2))
    else:
        print(report.slack_message(args.project, findings)["text"])
        for f in findings:
            print(f"  [{f.severity.value}] {f.check} {f.resource} ({f.location}): {f.detail}")
