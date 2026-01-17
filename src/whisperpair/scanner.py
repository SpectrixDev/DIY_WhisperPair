"""
Fast Pair BLE Scanner - Discovers devices advertising the Fast Pair Service (0xFE2C)
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field
from typing import Callable

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from .constants import (
    FAST_PAIR_SERVICE_UUID,
    FAST_PAIR_SERVICE_UUID_16,
    KNOWN_MODEL_IDS,
    DEFAULT_SCAN_TIMEOUT,
)


@dataclass
class FastPairDevice:
    ble_device: BLEDevice
    model_id: int | None = None
    model_name: str = "Unknown"
    rssi: int = -100
    is_in_pairing_mode: bool = False
    has_account_key_filter: bool = False
    raw_service_data: bytes = field(default_factory=bytes)
    battery_info: dict | None = None

    @property
    def address(self) -> str:
        return self.ble_device.address

    @property
    def name(self) -> str:
        return self.ble_device.name or self.model_name

    def __str__(self) -> str:
        mode = "PAIRING" if self.is_in_pairing_mode else "paired/idle"
        model_hex = f"0x{self.model_id:06X}" if self.model_id else "N/A"
        return (
            f"FastPairDevice({self.name}, addr={self.address}, "
            f"model={model_hex}, rssi={self.rssi}dBm, mode={mode})"
        )


def parse_fast_pair_service_data(data: bytes) -> dict:
    """
    Parse Fast Pair service data from BLE advertisement.
    
    Format varies based on device state:
    - Pairing mode: [Model ID (3 bytes)]
    - Not in pairing mode: [Flags + Account Key Filter]
    
    Reference: https://developers.google.com/nearby/fast-pair/specifications/bledevice
    """
    result = {
        "model_id": None,
        "is_pairing_mode": False,
        "has_account_key_filter": False,
        "salt": None,
        "battery": None,
    }

    if not data or len(data) < 3:
        return result

    first_byte = data[0]

    if first_byte == 0x00 and len(data) >= 3:
        model_id_bytes = data[0:3]
        result["model_id"] = struct.unpack(">I", b"\x00" + model_id_bytes)[0]
        result["is_pairing_mode"] = True

    elif len(data) == 3 and (first_byte & 0x80) == 0:
        result["model_id"] = struct.unpack(">I", b"\x00" + data)[0]
        result["is_pairing_mode"] = True

    elif (first_byte & 0x60) != 0:
        result["has_account_key_filter"] = True
        result["is_pairing_mode"] = False

        filter_length = (first_byte >> 4) & 0x0F
        filter_type = first_byte & 0x0F

        if len(data) > 1 + filter_length:
            remaining = data[1 + filter_length:]
            i = 0
            while i < len(remaining) - 1:
                field_id = remaining[i]
                field_len = remaining[i + 1] if i + 1 < len(remaining) else 0

                if field_id == 0x11 and field_len >= 1:
                    result["salt"] = remaining[i + 2:i + 2 + field_len]
                elif field_id == 0x03 and field_len >= 1:
                    result["battery"] = remaining[i + 2:i + 2 + field_len]

                i += 2 + field_len
    else:
        if len(data) == 3:
            result["model_id"] = struct.unpack(">I", b"\x00" + data)[0]
            result["is_pairing_mode"] = True

    return result


class FastPairScanner:
    def __init__(
        self,
        timeout: float = DEFAULT_SCAN_TIMEOUT,
        on_device_found: Callable[[FastPairDevice], None] | None = None,
    ):
        self.timeout = timeout
        self.on_device_found = on_device_found
        self.discovered_devices: dict[str, FastPairDevice] = {}
        self._scanner: BleakScanner | None = None

    def _detection_callback(
        self, device: BLEDevice, advertisement_data: AdvertisementData
    ) -> None:
        service_data = advertisement_data.service_data or {}
        service_uuids = advertisement_data.service_uuids or []

        fp_data = None
        has_fast_pair_uuid = False
        
        for uuid, data in service_data.items():
            if "fe2c" in uuid.lower():
                fp_data = data
                has_fast_pair_uuid = True
                break

        for uuid in service_uuids:
            if "fe2c" in uuid.lower():
                has_fast_pair_uuid = True
                break

        if not has_fast_pair_uuid:
            return
        
        if fp_data is None:
            fp_data = bytes()

        parsed = parse_fast_pair_service_data(fp_data)

        fp_device = FastPairDevice(
            ble_device=device,
            model_id=parsed.get("model_id"),
            model_name=KNOWN_MODEL_IDS.get(parsed.get("model_id", 0), "Unknown"),
            rssi=advertisement_data.rssi or -100,
            is_in_pairing_mode=parsed.get("is_pairing_mode", False),
            has_account_key_filter=parsed.get("has_account_key_filter", False),
            raw_service_data=fp_data,
        )

        if parsed.get("battery"):
            fp_device.battery_info = {"raw": parsed["battery"]}

        self.discovered_devices[device.address] = fp_device

        if self.on_device_found:
            self.on_device_found(fp_device)

    async def scan(self) -> list[FastPairDevice]:
        """
        Scan for Fast Pair devices.
        
        Note: We scan ALL devices and filter in callback rather than using
        service_uuids filter, because BlueZ filtering can miss devices that
        advertise Fast Pair in service_data but not as primary services.
        """
        self.discovered_devices.clear()

        self._scanner = BleakScanner(
            detection_callback=self._detection_callback,
        )

        await self._scanner.start()
        await asyncio.sleep(self.timeout)
        await self._scanner.stop()

        return list(self.discovered_devices.values())

    async def scan_all_ble(self) -> list[FastPairDevice]:
        """
        Scan ALL BLE devices and check for Fast Pair service.
        Use this when devices don't actively advertise Fast Pair but support it.
        """
        self.discovered_devices.clear()

        self._scanner = BleakScanner(detection_callback=self._detection_callback)

        await self._scanner.start()
        await asyncio.sleep(self.timeout)
        await self._scanner.stop()

        return list(self.discovered_devices.values())

    async def stop(self) -> None:
        if self._scanner:
            await self._scanner.stop()


async def find_fast_pair_devices(
    timeout: float = DEFAULT_SCAN_TIMEOUT,
    verbose: bool = False,
) -> list[FastPairDevice]:
    def on_found(device: FastPairDevice) -> None:
        if verbose:
            print(f"[+] Found: {device}")

    scanner = FastPairScanner(timeout=timeout, on_device_found=on_found)
    return await scanner.scan()


async def find_vulnerable_devices(
    timeout: float = DEFAULT_SCAN_TIMEOUT,
    verbose: bool = False,
) -> list[FastPairDevice]:
    all_devices = await find_fast_pair_devices(timeout=timeout, verbose=verbose)

    vulnerable_candidates = []
    for device in all_devices:
        if not device.is_in_pairing_mode:
            vulnerable_candidates.append(device)
            if verbose:
                print(f"[!] Potential target (not in pairing mode): {device}")

    return vulnerable_candidates
