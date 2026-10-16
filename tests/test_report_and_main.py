from unittest.mock import MagicMock

from auditor import main, report
from auditor.models import Category, Finding, Severity


def finding(sev, cost=0.0, name="r"):
    return Finding("p", Category.COST, "unattached_disk", sev, name, "zone", "detail", cost)


def test_slack_clean_message():
    msg = report.slack_message("p", [])
    assert "no idle resources" in msg["text"]


def test_slack_summary_sorted_and_capped():
    findings = [finding(Severity.LOW, 5, "low")] + [
        finding(Severity.CRITICAL, name=f"c{i}") for i in range(12)
    ]
    msg = report.slack_message("p", findings, max_items=10)
    body = msg["blocks"][2]["text"]["text"]
    assert "13 findings" in msg["text"] and "12 CRITICAL · 1 LOW" in msg["text"]
    assert "$5.00/month" in msg["text"]
    assert body.splitlines()[0].startswith("• `CRITICAL`")
    assert "3 more in BigQuery" in body


def test_finding_row_is_json_friendly():
    row = finding(Severity.HIGH).to_row()
    assert row["severity"] == "HIGH" and row["category"] == "cost"
    assert isinstance(row["scanned_at"], str)


def test_run_audit_writes_and_notifies_each_project(monkeypatch):
    monkeypatch.setenv("AUDIT_PROJECTS", "proj-a, proj-b")
    monkeypatch.setenv("BQ_TABLE", "x.audit.findings")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/x")
    monkeypatch.setattr(main, "audit", lambda p: [finding(Severity.HIGH, name=p)])
    bq, slack = MagicMock(), MagicMock()
    monkeypatch.setattr(report, "write_bigquery", bq)
    monkeypatch.setattr(report, "send_slack", slack)

    body, status = main.run_audit(None)

    assert status == 200 and body == {"projects": 2, "findings": 2}
    assert bq.call_count == 2 and slack.call_count == 2
