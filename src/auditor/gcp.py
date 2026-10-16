"""Read resources from GCP and convert them to plain models.

All Google API calls live here. Read-only: the function's service account only
has viewer roles, so the auditor can never change what it scans.
"""

from datetime import UTC, datetime, timedelta

from google.cloud import compute_v1, monitoring_v3

from auditor.models import Disk, FirewallRule, Vm


def _last(url: str) -> str:
    return url.rsplit("/", 1)[-1]


def list_vms(project: str) -> list[Vm]:
    client = compute_v1.InstancesClient()
    vms = []
    for zone, scoped in client.aggregated_list(project=project):
        for inst in scoped.instances:
            vms.append(
                Vm(
                    name=inst.name,
                    zone=_last(zone),
                    machine_type=_last(inst.machine_type),
                    status=inst.status,
                    instance_id=str(inst.id),
                )
            )
    return vms


def list_disks(project: str) -> list[Disk]:
    client = compute_v1.DisksClient()
    disks = []
    for zone, scoped in client.aggregated_list(project=project):
        for d in scoped.disks:
            disks.append(
                Disk(
                    name=d.name,
                    zone=_last(zone),
                    size_gb=d.size_gb,
                    disk_type=_last(d.type_),
                    users=list(d.users),
                )
            )
    return disks


def list_firewall_rules(project: str) -> list[FirewallRule]:
    client = compute_v1.FirewallsClient()
    return [
        FirewallRule(
            name=fw.name,
            network=_last(fw.network),
            direction=fw.direction,
            disabled=fw.disabled,
            source_ranges=list(fw.source_ranges),
            allowed=[(a.I_p_protocol, list(a.ports)) for a in fw.allowed],
            target_tags=list(fw.target_tags),
        )
        for fw in client.list(project=project)
    ]


def avg_cpu_by_instance(project: str, days: int = 7) -> dict[str, float]:
    """Mean CPU utilisation (0-1) per instance_id over the last `days`."""
    client = monitoring_v3.MetricServiceClient()
    now = datetime.now(UTC)
    interval = monitoring_v3.TimeInterval(start_time=now - timedelta(days=days), end_time=now)
    aggregation = monitoring_v3.Aggregation(
        alignment_period={"seconds": days * 86400},
        per_series_aligner=monitoring_v3.Aggregation.Aligner.ALIGN_MEAN,
    )
    series = client.list_time_series(
        name=f"projects/{project}",
        filter='metric.type="compute.googleapis.com/instance/cpu/utilization"',
        interval=interval,
        view=monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
        aggregation=aggregation,
    )
    result = {}
    for ts in series:
        if ts.points:
            result[ts.resource.labels["instance_id"]] = ts.points[0].value.double_value
    return result
