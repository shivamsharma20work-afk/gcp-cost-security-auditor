"""Plain data types.

The checks work on these instead of raw Google API objects, so they can be
unit-tested without GCP credentials and the API-specific code stays in gcp.py.
"""

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Category(StrEnum):
    COST = "cost"
    SECURITY = "security"


@dataclass
class Vm:
    name: str
    zone: str
    machine_type: str
    status: str
    instance_id: str


@dataclass
class Disk:
    name: str
    zone: str
    size_gb: int
    disk_type: str
    users: list[str] = field(default_factory=list)


@dataclass
class FirewallRule:
    name: str
    network: str
    direction: str
    disabled: bool
    source_ranges: list[str]
    # [(protocol, [ports])], ports empty = all ports for that protocol
    allowed: list[tuple[str, list[str]]]
    target_tags: list[str] = field(default_factory=list)


@dataclass
class Finding:
    project: str
    category: Category
    check: str
    severity: Severity
    resource: str
    location: str
    detail: str
    est_monthly_cost_usd: float = 0.0
    scanned_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_row(self) -> dict:
        row = asdict(self)
        row["category"] = str(self.category)
        row["severity"] = str(self.severity)
        row["scanned_at"] = self.scanned_at.isoformat()
        return row
