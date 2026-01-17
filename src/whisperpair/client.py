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
)
from .scanner import FastPairDevice


@dataclass
class VerificationResult:
    success: bool
    provider_address: Optional[str] = None
    error: Optional[str] = None
    raw_response: Optional[bytes] = None


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

    async def verify_pairing_behavior(
        self,
        aes_key: bytes,
        seeker_address: Optional[bytes] = None,
    ) -> VerificationResult:
        if not self._client:
            return VerificationResult(success=False, error="Not connected")

        try:
            provider_addr_bytes = parse_bluetooth_address(self.address)
        except ValueError as e:
            return VerificationResult(success=False, error=str(e))

        request = KeyBasedPairingRequest.for_verification(
            provider_address=provider_addr_bytes,
            seeker_address=seeker_address,
        )

        try:
            response = await self.send_key_based_pairing_request(request, aes_key)

            if response:
                return VerificationResult(
                    success=True,
                    provider_address=response.provider_address_str,
                    raw_response=bytes(response.provider_address) + response.salt,
                )
            else:
                return VerificationResult(
                    success=False,
                    error="No response from device (not vulnerable or invalid key)",
                )

        except Exception as e:
            return VerificationResult(success=False, error=str(e))
