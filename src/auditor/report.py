"""Outputs: BigQuery (history for trends) and Slack (today's summary for humans)."""

from collections import Counter

import requests

from auditor.models import Finding, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


def write_bigquery(findings: list[Finding], table: str) -> None:
    """Append findings to `project.dataset.table`. Schema is managed by Terraform."""
    if not findings:
        return
    from google.cloud import bigquery

    errors = bigquery.Client().insert_rows_json(table, [f.to_row() for f in findings])
    if errors:
        raise RuntimeError(f"BigQuery insert failed: {errors[:3]}")


def slack_message(project: str, findings: list[Finding], max_items: int = 10) -> dict:
    """Build a Slack Block Kit payload. Most severe first, capped so the message stays readable."""
    if not findings:
        text = f":white_check_mark: *{project}*: no idle resources or open firewall rules today."
        return {"text": text, "blocks": [{"type": "section", "text": _md(text)}]}

    counts = Counter(f.severity for f in findings)
    waste = sum(f.est_monthly_cost_usd for f in findings)
    summary = " · ".join(f"{counts[s]} {s.value}" for s in SEVERITY_ORDER if counts[s])
    header = f":rotating_light: *GCP audit for {project}*: {len(findings)} findings ({summary})"
    if waste:
        header += f"\nEstimated waste: *${waste:,.2f}/month*"

    ranked = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))
    lines = [
        f"• `{f.severity.value}` *{f.check}* `{f.resource}` ({f.location}): {f.detail}"
        for f in ranked[:max_items]
    ]
    if len(ranked) > max_items:
        lines.append(f"…and {len(ranked) - max_items} more in BigQuery.")

    return {
        "text": header,
        "blocks": [
            {"type": "section", "text": _md(header)},
            {"type": "divider"},
            {"type": "section", "text": _md("\n".join(lines))},
        ],
    }


def send_slack(webhook_url: str, payload: dict) -> None:
    resp = requests.post(webhook_url, json=payload, timeout=10)
    resp.raise_for_status()


def _md(text: str) -> dict:
    return {"type": "mrkdwn", "text": text}
