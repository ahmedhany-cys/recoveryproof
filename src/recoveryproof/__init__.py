"""RecoveryProof — prove recovery before disaster strikes.

A decision-support platform that analyses (synthetic) infrastructure and backup
evidence to determine whether critical systems can actually be recovered.
"""

__version__ = "1.0.0"

# Bumped whenever rules, scoring weights or calculations change so that reports
# can always be traced back to the exact analysis logic that produced them.
ANALYSIS_VERSION = "2026.10.1"

__all__ = ["ANALYSIS_VERSION", "__version__"]
