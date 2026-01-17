"""
Google Fast Pair Service UUIDs and Constants

Reference: https://developers.google.com/nearby/fast-pair/specifications/characteristics
"""

# =============================================================================
# GATT Service UUID
# =============================================================================

# Google Fast Pair Service UUID (16-bit: 0xFE2C)
FAST_PAIR_SERVICE_UUID_16 = 0xFE2C
FAST_PAIR_SERVICE_UUID = "0000fe2c-0000-1000-8000-00805f9b34fb"

# =============================================================================
# GATT Characteristic UUIDs
# =============================================================================

# Model ID Characteristic - Read only, returns 3-byte Model ID
MODEL_ID_CHAR_UUID = "fe2c1233-8366-4814-8eb0-01de32100bea"

# Key-based Pairing Characteristic - Write, Notify
# This is the PRIMARY target for the WhisperPair vulnerability
KEY_BASED_PAIRING_CHAR_UUID = "fe2c1234-8366-4814-8eb0-01de32100bea"

# Passkey Characteristic - Write, Notify  
# Used during the pairing confirmation phase
PASSKEY_CHAR_UUID = "fe2c1235-8366-4814-8eb0-01de32100bea"

# Account Key Characteristic - Write only
ACCOUNT_KEY_CHAR_UUID = "fe2c1236-8366-4814-8eb0-01de32100bea"

# Firmware Revision Characteristic (optional)
FIRMWARE_REVISION_CHAR_UUID = "fe2c1237-8366-4814-8eb0-01de32100bea"

# Additional Data Characteristic (optional) - Write, Notify
ADDITIONAL_DATA_CHAR_UUID = "fe2c1238-8366-4814-8eb0-01de32100bea"

# =============================================================================
# Message Types for Key-based Pairing Characteristic
# =============================================================================

class MessageType:
    """Message types for Key-based Pairing Request/Response"""
    KEY_BASED_PAIRING_REQUEST = 0x00
    KEY_BASED_PAIRING_RESPONSE = 0x01
    KEY_BASED_PAIRING_EXTENDED_RESPONSE = 0x02
    SEEKER_PASSKEY = 0x02  # Seeker's passkey notification
    PROVIDER_PASSKEY = 0x03  # Provider's passkey notification
    ACTION_REQUEST = 0x10

# =============================================================================
# Flags for Key-based Pairing Request
# =============================================================================

class PairingFlags:
    """Bit flags for Key-based Pairing Request"""
    # Bit 0: Request device to initiate bonding
    INITIATE_BONDING = 0x01
    
    # Bit 1: Seeker's BR/EDR address is present (octets 8-13)
    SEEKER_ADDRESS_PRESENT = 0x02
    
    # Bit 2: Reserved
    RESERVED_BIT_2 = 0x04
    
    # Bit 3: Alternative Seeker address present indicator
    ALT_SEEKER_ADDRESS_PRESENT = 0x08
    
    # Bit 4: Request extended response (message type 0x02)
    REQUEST_EXTENDED_RESPONSE = 0x10
    
    # Bit 5: Subsequent pairing (not initial pair)
    SUBSEQUENT_PAIRING = 0x20
    
    # Bit 6: Request retroactive writing of account key
    RETROACTIVE_ACCOUNT_KEY = 0x40
    
    # Bit 7: Reserved
    RESERVED_BIT_7 = 0x80

# =============================================================================
# Provider Advertising Data Types
# =============================================================================

class AdvertisingType:
    """Fast Pair advertising types from service data"""
    # First byte of advertising service data indicates type
    MODEL_ID_INDICATOR = 0x00  # Followed by 3-byte Model ID
    ACCOUNT_KEY_FILTER = 0x00  # When bit 6 is set, contains bloom filter
    
    # Advertising field IDs
    FIELD_MODEL_ID = 0x01
    FIELD_BATTERY = 0x03
    FIELD_SALT = 0x11

# =============================================================================
# Anti-Spoofing Key Types
# =============================================================================

class KeyType:
    """Types of keys used in Fast Pair protocol"""
    # Anti-Spoofing Public Key (from Google's database, per Model ID)
    ANTI_SPOOFING_PUBLIC_KEY = "anti_spoofing"
    
    # Account Key (16 bytes, written by Seeker to establish ownership)
    ACCOUNT_KEY = "account_key"
    
    # Shared Secret (derived via ECDH during key-based pairing)
    SHARED_SECRET = "shared_secret"

# =============================================================================
# Timeouts and Limits
# =============================================================================

# BLE scan timeout in seconds
DEFAULT_SCAN_TIMEOUT = 10.0

# GATT connection timeout in seconds
DEFAULT_CONNECTION_TIMEOUT = 10.0

# Notification timeout in seconds
DEFAULT_NOTIFICATION_TIMEOUT = 5.0

# Maximum number of account keys a device can store
MAX_ACCOUNT_KEYS = 10

# Account key size in bytes
ACCOUNT_KEY_SIZE = 16

# =============================================================================
# Known Model IDs for Testing
# =============================================================================

# Dictionary mapping known Model IDs to device names
# These are public Model IDs from various manufacturers
KNOWN_MODEL_IDS = {
    # Google Pixel Buds
    0x0600FC: "Google Pixel Buds",
    0x0600FD: "Google Pixel Buds",
    0xD800AA: "Google Pixel Buds Pro",
    0x30018E: "Google Pixel Buds Pro 2",
    
    # Sony
    0xCD8256: "Sony WF-1000XM4",
    0x0E30C3: "Sony WH-1000XM5",
    0x821F66: "Sony LinkBuds S",
    
    # JBL
    0xF52494: "JBL Tune Buds",
    0x718FA4: "JBL Live Pro 2",
    
    # Anker Soundcore
    0x9D3F8A: "Anker Soundcore Liberty 4",
    
    # Samsung (Galaxy Buds use a different protocol but some support Fast Pair)
    0x1312F3: "Samsung Galaxy Buds2 Pro",
}

def get_device_name(model_id: int) -> str:
    """Get friendly device name from Model ID"""
    return KNOWN_MODEL_IDS.get(model_id, f"Unknown Device (0x{model_id:06X})")
