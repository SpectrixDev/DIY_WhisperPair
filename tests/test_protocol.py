import pytest
from whisperpair.protocol import (
    KeyBasedPairingRequest,
    KeyBasedPairingResponse,
    PasskeyBlock,
    PairingRequestFlags,
    parse_bluetooth_address,
    format_bluetooth_address,
)
from whisperpair.crypto import (
    aes_128_encrypt,
    aes_128_decrypt,
    generate_secp256r1_keypair,
    generate_account_key,
    sha256,
)
from whisperpair.constants import MessageType


class TestBluetoothAddress:
    def test_parse_valid_address(self):
        addr = parse_bluetooth_address("AA:BB:CC:DD:EE:FF")
        assert addr == bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])

    def test_parse_address_with_dashes(self):
        addr = parse_bluetooth_address("AA-BB-CC-DD-EE-FF")
        assert addr == bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])

    def test_format_address(self):
        addr_bytes = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        formatted = format_bluetooth_address(addr_bytes)
        assert formatted == "11:22:33:44:55:66"

    def test_parse_invalid_address(self):
        with pytest.raises(ValueError):
            parse_bluetooth_address("invalid")

    def test_parse_invalid_length(self):
        with pytest.raises(ValueError):
            parse_bluetooth_address("AA:BB:CC")


class TestKeyBasedPairingRequest:
    def test_build_basic_request(self):
        provider_addr = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        request = KeyBasedPairingRequest(
            provider_address=provider_addr,
            flags=PairingRequestFlags.INITIATE_BONDING,
        )
        packet = request.build()

        assert len(packet) == 16
        assert packet[0] == MessageType.KEY_BASED_PAIRING_REQUEST
        assert packet[1] == PairingRequestFlags.INITIATE_BONDING
        assert packet[2:8] == provider_addr

    def test_build_request_with_seeker_address(self):
        provider_addr = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        seeker_addr = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])

        request = KeyBasedPairingRequest(
            provider_address=provider_addr,
            seeker_address=seeker_addr,
            flags=PairingRequestFlags.INITIATE_BONDING,
        )
        packet = request.build()

        assert len(packet) == 16
        assert packet[1] & PairingRequestFlags.SEEKER_ADDRESS_PRESENT
        assert packet[8:14] == seeker_addr

    def test_for_verification_factory(self):
        provider_addr = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        request = KeyBasedPairingRequest.for_verification(provider_addr)

        assert request.flags == PairingRequestFlags.INITIATE_BONDING
        assert request.provider_address == provider_addr

    def test_invalid_provider_address_length(self):
        with pytest.raises(ValueError):
            KeyBasedPairingRequest(provider_address=bytes([0x11, 0x22]))


class TestKeyBasedPairingResponse:
    def test_parse_response(self):
        response_data = bytes([
            0x01,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])

        response = KeyBasedPairingResponse.parse(response_data)

        assert response.message_type == 0x01
        assert response.provider_address == bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        assert response.provider_address_str == "11:22:33:44:55:66"

    def test_parse_invalid_length(self):
        with pytest.raises(ValueError):
            KeyBasedPairingResponse.parse(bytes(10))


class TestPasskeyBlock:
    def test_build_passkey(self):
        passkey_block = PasskeyBlock(
            message_type=0x02,
            passkey=123456,
            salt=bytes(12),
        )
        packet = passkey_block.build()

        assert len(packet) == 16
        assert packet[0] == 0x02
        passkey_value = int.from_bytes(packet[1:4], byteorder="big")
        assert passkey_value == 123456

    def test_parse_passkey(self):
        data = bytes([0x03]) + (654321).to_bytes(3, "big") + bytes(12)
        parsed = PasskeyBlock.parse(data)

        assert parsed.message_type == 0x03
        assert parsed.passkey == 654321

    def test_create_seeker_passkey(self):
        block = PasskeyBlock.create_seeker_passkey(999999)
        assert block.message_type == 0x02
        assert block.passkey == 999999
        assert len(block.salt) == 12


class TestAESCrypto:
    def test_encrypt_decrypt_roundtrip(self):
        key = bytes(16)
        plaintext = bytes(range(16))

        ciphertext = aes_128_encrypt(key, plaintext)
        decrypted = aes_128_decrypt(key, ciphertext)

        assert decrypted == plaintext

    def test_encrypt_invalid_key_length(self):
        with pytest.raises(ValueError):
            aes_128_encrypt(bytes(8), bytes(16))

    def test_encrypt_invalid_plaintext_length(self):
        with pytest.raises(ValueError):
            aes_128_encrypt(bytes(16), bytes(10))

    def test_known_test_vector(self):
        key = bytes.fromhex("00000000000000000000000000000000")
        plaintext = bytes.fromhex("00000000000000000000000000000000")
        expected = bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e")

        ciphertext = aes_128_encrypt(key, plaintext)
        assert ciphertext == expected


class TestECDH:
    def test_generate_keypair(self):
        keypair = generate_secp256r1_keypair()

        assert keypair.private_key is not None
        assert keypair.public_key is not None
        assert len(keypair.public_key_bytes) == 64

    def test_keypairs_are_unique(self):
        kp1 = generate_secp256r1_keypair()
        kp2 = generate_secp256r1_keypair()

        assert kp1.public_key_bytes != kp2.public_key_bytes


class TestAccountKey:
    def test_generate_account_key(self):
        key = generate_account_key()
        assert len(key) == 16

    def test_account_keys_are_random(self):
        key1 = generate_account_key()
        key2 = generate_account_key()
        assert key1 != key2


class TestSHA256:
    def test_sha256_known_vector(self):
        result = sha256(b"hello")
        expected = bytes.fromhex(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )
        assert result == expected
