#!/usr/bin/env python3
import asyncio
import sys

sys.path.insert(0, "src")

from whisperpair.scanner import FastPairScanner, find_vulnerable_devices
from whisperpair.constants import KNOWN_MODEL_IDS


async def main():
    print("=" * 60)
    print("DIY WhisperPair - Fast Pair Device Scanner")
    print("=" * 60)
    print()

    print("[*] Scanning for Fast Pair devices (10 seconds)...")
    print()

    def on_device_found(device):
        status = "PAIRING MODE" if device.is_in_pairing_mode else "NOT IN PAIRING MODE"
        vuln = " [VERIFY]" if not device.is_in_pairing_mode else ""        model = f"0x{device.model_id:06X}" if device.model_id else "Unknown"
        print(f"  [+] Found: {device.address}")
        print(f"      Name: {device.name}")
        print(f"      Model ID: {model}")
        print(f"      RSSI: {device.rssi} dBm")
        print(f"      Status: {status}{vuln}")
        print()

    scanner = FastPairScanner(timeout=10.0, on_device_found=on_device_found)

    try:
        devices = await scanner.scan()
    except Exception as e:
        print(f"[!] Scan error: {e}")
        print("[!] Make sure Bluetooth is enabled and you have permissions.")
        return

    print("=" * 60)
    print(f"[*] Scan complete. Found {len(devices)} Fast Pair device(s).")

    vulnerable = [d for d in devices if not d.is_in_pairing_mode]
    if vulnerable:
        print(f"[!] {len(vulnerable)} device(s) potentially vulnerable to WhisperPair")
        print()
        print("Vulnerable devices advertise Fast Pair while NOT in pairing mode.")
        print("This indicates they may respond to pairing requests when idle.")
        print()
        print("To verify behavior (requires proper AES key):")
        for device in vulnerable:
            print(f"  whisperpair verify {device.address} --key <aes-key-hex>")
    else:
        print("[*] No potentially vulnerable devices found.")
        print("    (Devices in pairing mode are behaving correctly)")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Scan cancelled.")
