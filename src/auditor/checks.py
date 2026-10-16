"""The audit rules. Pure functions: resources in, findings out."""

from auditor.models import Category, Disk, Finding, FirewallRule, Severity, Vm

# asia-south1 list prices (USD / GB / month). Good enough for a "you're wasting ~$X" estimate.
DISK_PRICE_PER_GB = {
    "pd-standard": 0.048,
    "pd-balanced": 0.12,
    "pd-ssd": 0.204,
    "pd-extreme": 0.15,
    "hyperdisk-balanced": 0.096,
}
DEFAULT_DISK_PRICE = 0.12

# Ports that should never be open to the whole internet
SENSITIVE_PORTS = {
    "22": "SSH",
    "3389": "RDP",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "6379": "Redis",
    "27017": "MongoDB",
    "9200": "Elasticsearch",
    "2375": "Docker API",
}
OPEN_TO_WORLD = {"0.0.0.0/0", "::/0"}


def idle_vms(
    project: str, vms: list[Vm], avg_cpu: dict[str, float], threshold: float = 0.05
) -> list[Finding]:
    """RUNNING VMs whose average CPU over the lookback window is below `threshold` (0-1)."""
    findings = []
    for vm in vms:
        if vm.status != "RUNNING" or vm.instance_id not in avg_cpu:
            continue
        cpu = avg_cpu[vm.instance_id]
        if cpu < threshold:
            findings.append(
                Finding(
                    project=project,
                    category=Category.COST,
                    check="idle_vm",
                    severity=Severity.MEDIUM,
                    resource=vm.name,
                    location=vm.zone,
                    detail=(
                        f"{vm.machine_type} averaged {cpu:.1%} CPU over 7 days. "
                        "Stop it, downsize it, or schedule it off outside working hours."
                    ),
                )
            )
    return findings


def unattached_disks(project: str, disks: list[Disk]) -> list[Finding]:
    """Persistent disks not attached to any VM: you pay for them and nothing uses them."""
    findings = []
    for d in disks:
        if d.users:
            continue
        cost = round(d.size_gb * DISK_PRICE_PER_GB.get(d.disk_type, DEFAULT_DISK_PRICE), 2)
        findings.append(
            Finding(
                project=project,
                category=Category.COST,
                check="unattached_disk",
                severity=Severity.LOW if cost < 10 else Severity.MEDIUM,
                resource=d.name,
                location=d.zone,
                detail=f"{d.size_gb} GB {d.disk_type} not attached to any VM. "
                "Snapshot it if needed, then delete.",
                est_monthly_cost_usd=cost,
            )
        )
    return findings


def _exposed_ports(rule: FirewallRule) -> tuple[bool, list[str]]:
    """Returns (all_ports_open, [sensitive services exposed])."""
    exposed: list[str] = []
    for protocol, ports in rule.allowed:
        if protocol not in ("tcp", "all"):
            continue
        if not ports:
            return True, list(SENSITIVE_PORTS.values())
        for p in ports:
            lo, _, hi = p.partition("-")
            hi = hi or lo
            for port, name in SENSITIVE_PORTS.items():
                if int(lo) <= int(port) <= int(hi):
                    exposed.append(f"{name} ({port})")
    return False, exposed


def open_firewall_rules(project: str, rules: list[FirewallRule]) -> list[Finding]:
    """Enabled ingress rules that open sensitive ports (or everything) to 0.0.0.0/0."""
    findings = []
    for rule in rules:
        if rule.disabled or rule.direction != "INGRESS":
            continue
        if not OPEN_TO_WORLD & set(rule.source_ranges):
            continue
        all_open, exposed = _exposed_ports(rule)
        if not exposed:
            continue
        scope = f"tags {rule.target_tags}" if rule.target_tags else "ALL instances"
        findings.append(
            Finding(
                project=project,
                category=Category.SECURITY,
                check="open_firewall",
                severity=Severity.CRITICAL if all_open else Severity.HIGH,
                resource=rule.name,
                location=rule.network,
                detail=(
                    ("All ports" if all_open else ", ".join(exposed))
                    + f" open to the internet on {scope}. "
                    "Restrict source ranges or use IAP TCP forwarding (35.235.240.0/20)."
                ),
            )
        )
    return findings
