import pytest

from auditor import checks
from auditor.models import Disk, FirewallRule, Severity, Vm

P = "demo-project"


def vm(name, status="RUNNING", iid=None):
    return Vm(name, "asia-south1-a", "e2-medium", status, iid or name)


def fw(name, ranges=("0.0.0.0/0",), allowed=(("tcp", ["22"]),), **kw):
    return FirewallRule(
        name=name,
        network="default",
        direction=kw.get("direction", "INGRESS"),
        disabled=kw.get("disabled", False),
        source_ranges=list(ranges),
        allowed=list(allowed),
        target_tags=kw.get("tags", []),
    )


# --- idle VMs -----------------------------------------------------------------


def test_idle_vm_flagged_below_threshold():
    found = checks.idle_vms(P, [vm("idle"), vm("busy")], {"idle": 0.01, "busy": 0.6})
    assert [f.resource for f in found] == ["idle"]
    assert found[0].check == "idle_vm"


def test_stopped_vm_and_vm_without_metrics_ignored():
    found = checks.idle_vms(P, [vm("off", status="TERMINATED"), vm("new")], {"off": 0.0})
    assert found == []


# --- unattached disks ----------------------------------------------------------


def test_unattached_disk_cost_estimate():
    disks = [
        Disk("orphan", "asia-south1-a", 500, "pd-ssd"),
        Disk("in-use", "asia-south1-a", 50, "pd-ssd", users=["instances/web-1"]),
    ]
    [f] = checks.unattached_disks(P, disks)
    assert f.resource == "orphan"
    assert f.est_monthly_cost_usd == pytest.approx(102.0)
    assert f.severity == Severity.MEDIUM


def test_small_unattached_disk_is_low():
    [f] = checks.unattached_disks(P, [Disk("tiny", "asia-south1-a", 10, "pd-standard")])
    assert f.severity == Severity.LOW


# --- firewall -----------------------------------------------------------------


def test_ssh_open_to_world_is_high():
    [f] = checks.open_firewall_rules(P, [fw("allow-ssh")])
    assert f.severity == Severity.HIGH
    assert "SSH (22)" in f.detail


def test_all_ports_open_is_critical():
    [f] = checks.open_firewall_rules(P, [fw("allow-all", allowed=[("all", [])])])
    assert f.severity == Severity.CRITICAL


def test_port_range_covering_sensitive_port():
    [f] = checks.open_firewall_rules(P, [fw("range", allowed=[("tcp", ["3000-6000"])])])
    assert "PostgreSQL (5432)" in f.detail and "MySQL (3306)" in f.detail


def test_ipv6_any_counts_as_open():
    assert checks.open_firewall_rules(P, [fw("v6", ranges=["::/0"])])


@pytest.mark.parametrize(
    "rule",
    [
        fw("https", allowed=[("tcp", ["443"])]),  # public web port is fine
        fw("iap-ssh", ranges=["35.235.240.0/20"]),  # IAP range only
        fw("disabled", disabled=True),
        fw("egress", direction="EGRESS"),
        fw("udp", allowed=[("udp", ["22"])]),
    ],
)
def test_safe_rules_not_flagged(rule):
    assert checks.open_firewall_rules(P, [rule]) == []
