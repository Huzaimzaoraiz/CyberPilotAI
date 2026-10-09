from .connection import DatabaseConnection
from .assets import AssetDBMixin
from .vulnerabilities import VulnerabilityDBMixin
from .tasks import TaskDBMixin
from .attack_paths import AttackPathDBMixin
from .remediation import RemediationDBMixin
from .snapshot import SnapshotDBMixin

class DatabaseClient(
    DatabaseConnection,
    AssetDBMixin,
    VulnerabilityDBMixin,
    TaskDBMixin,
    AttackPathDBMixin,
    RemediationDBMixin,
    SnapshotDBMixin
):
    pass
