"""
DIY WhisperPair - Google Fast Pair Seeker Implementation
For security research and testing purposes only.

This package implements the Seeker side of Google Fast Pair protocol
to demonstrate the CVE-2025-36911 vulnerability.

Reference: https://whisperpair.eu
"""

__version__ = "0.1.0"
__author__ = "Security Researcher"

from .constants import (
    FAST_PAIR_SERVICE_UUID,
    KEY_BASED_PAIRING_CHAR_UUID,
    ACCOUNT_KEY_CHAR_UUID,
    PASSKEY_CHAR_UUID,
    MODEL_ID_CHAR_UUID,
)

__all__ = [
    "FAST_PAIR_SERVICE_UUID",
    "KEY_BASED_PAIRING_CHAR_UUID",
    "ACCOUNT_KEY_CHAR_UUID",
    "PASSKEY_CHAR_UUID",
    "MODEL_ID_CHAR_UUID",
]
