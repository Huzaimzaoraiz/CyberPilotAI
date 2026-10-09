from .base import BaseLLMClient
from .recon import ReconLLMMixin
from .validation import ValidationLLMMixin
from .attack_path import AttackPathLLMMixin
from .remediation import RemediationLLMMixin

class RealLLMClient(
    BaseLLMClient,
    ReconLLMMixin,
    ValidationLLMMixin,
    AttackPathLLMMixin,
    RemediationLLMMixin
):
    pass
