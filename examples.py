#!/usr/bin/env python3
"""
WhisperPair Examples - Copy-paste ready code for security researchers

Usage:
    python examples.py scan              # Scan for Fast Pair devices
    python examples.py vulnerable        # Find devices not in pairing mode
    python examples.py verify TARGET     # Verify specific device
    python examples.py custom            # Custom scanner with callbacks

LEGAL: Only use on devices you own or have written authorization to test.
"""

import asyncio
import sys


async def example_scan():
    from whisperpair import scan_devices

    print("[*] Scanning for Fast Pair devices (10s)...")
    devices = await scan_devices(timeout=10)

    if not devices:
        print("[-] No devices found")
        return

    print(f"\n[+] Found {len(devices)} device(s):\n")
    for d in devices:
        risk = "HIGH" if not d.is_in_pairing_mode else "Low"
        model = f"0x{d.model_id:06X}" if d.model_id else "Unknown"
        print(f"  {d.address} | {d.name} | {model} | Risk: {risk}")


async def example_vulnerable():
    from whisperpair import scan_devices

    print("[*] Scanning for potentially vulnerable devices...")
    devices = await scan_devices(timeout=10, vulnerable_only=True)

    if not devices:
        print("[+] No vulnerable devices found")
        return

    print(f"\n[!] Found {len(devices)} potentially vulnerable:\n")
    for d in devices:
        print(f"  {d.address} - {d.name}")


async def example_verify(target: str):
    from whisperpair import verify_device

    print(f"[*] Verifying: {target}")
    print("[!] Only proceed if you own this device\n")

    result = await verify_device(target)

    if result.success:
        print(f"[!] VULNERABLE - Provider: {result.provider_address}")
    else:
        print(f"[+] Not vulnerable: {result.error}")


async def example_custom():
    from whisperpair import FastPairScanner, FastPairDevice

    def on_found(device: FastPairDevice):
        status = "VULN?" if not device.is_in_pairing_mode else "OK"
        print(f"  [+] {device.address} | {device.name} | {status}")

    print("[*] Custom scanner with live callbacks (15s):\n")
    scanner = FastPairScanner(timeout=15, on_device_found=on_found)
    devices = await scanner.scan()
    print(f"\n[*] Total: {len(devices)} devices")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "scan":
        asyncio.run(example_scan())
    elif cmd == "vulnerable":
        asyncio.run(example_vulnerable())
    elif cmd == "verify":
        if len(sys.argv) < 3:
            print("Usage: python examples.py verify AA:BB:CC:DD:EE:FF")
            sys.exit(1)
        asyncio.run(example_verify(sys.argv[2]))
    elif cmd == "custom":
        asyncio.run(example_custom())
    else:
        print(f"Unknown: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
