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
        return cls(
            provider_address=provider_address,
            seeker_address=seeker_address,
            flags=PairingRequestFlags.INITIATE_BONDING,
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
