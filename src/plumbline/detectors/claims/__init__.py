"""Claim Ledger detector rules package."""

from plumbline.detectors.claims.rules import (
    CLM001_SPEC,
    CLM002_SPEC,
    CLM003_SPEC,
    CLM004_SPEC,
    detect_clm001,
    detect_clm002,
    detect_clm003,
    detect_clm004,
)

__all__ = [
    "CLM001_SPEC",
    "CLM002_SPEC",
    "CLM003_SPEC",
    "CLM004_SPEC",
    "detect_clm001",
    "detect_clm002",
    "detect_clm003",
    "detect_clm004",
]
