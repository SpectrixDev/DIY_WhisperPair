# DIY-WhisperPair

**CVE-2025-36911 Reference Implementation for Security Researchers**

[![Research](https://img.shields.io/badge/Type-Security%20Research-blue)](https://whisperpair.eu)
[![CVE](https://img.shields.io/badge/CVE-2025--36911-red)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-36911)
[![Status](https://img.shields.io/badge/Disclosure-Completed-green)](https://whisperpair.eu)

> **LEGAL NOTICE**: This is a security research tool. **Read [LEGAL.md](LEGAL.md) before use.** Unauthorized access to computer systems is a criminal offence.
---

## About This Project

This repository provides a **reference implementation** of the WhisperPair vulnerability (CVE-2025-36911) for security researchers, penetration testers, and device manufacturers to:

1. **Verify** if their devices are patched
2. **Understand** the technical details of the vulnerability
3. **Develop** detection and mitigation strategies
4. **Educate** about Bluetooth security risks

Note: This tool was rush-coded for educational purposes (at 1am on a Friday!). I have tested it on multiple devices I own, both before and after applying updates. I verified that the vulnerability does allow audio playback without pairing on unpatched devices.

**Important: This repository does not contain code to enable audio playback or any active exploits. It contains only the logic required to verify if a device is vulnerable.**

### Original Research

This implementation is based on the publicly disclosed research by **KU Leuven (DistriNet)**, published January 2026:

- **Paper**: "WhisperPair: Hijacking Bluetooth Accessories Using Google Fast Pair"
- **Website**: [https://whisperpair.eu](https://whisperpair.eu)
- **CVE**: [CVE-2025-36911](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-36911)
- **Seytonic video** (recommended): [Watch Video](https://www.youtube.com/watch?v=Ux07J-wS2VA)
- **Disclosure**: Responsibly disclosed to Google in August 2025 (150-day window) (not by me)
- **Google Severity**: Critical (maximum bounty awarded: $15,000)

The vulnerability was **patched** by manufacturers following coordinated disclosure. This PoC is released **after** the disclosure window closed and patches were made available.

---

## Vulnerability Overview

### The Flaw

Google Fast Pair enables one-tap Bluetooth pairing. The specification requires devices to **only accept pairing requests when in pairing mode**. However, many devices fail to enforce this check:

```
EXPECTED: Device checks "Am I in pairing mode?" → NO → Reject request
ACTUAL:   Device accepts request regardless of pairing mode state
```

### Impact

An attacker within Bluetooth range (~10-14 metres) can:

1. **Access audio accessories** - Play audio through victim's headphones/earbuds
2. **Eavesdrop via microphone** - Access microphone for surveillance
3. **Track location** - Write Account Key to enable Google Find Hub tracking

### Affected Devices (Pre-Patch)

| Manufacturer | Devices |
|--------------|---------|
| Google | Pixel Buds Pro 2 |
| Sony | WF-1000XM4, WH-1000XM5, WF-C500, LinkBuds S |
| JBL | Tune Buds, Live Pro 2 |
| Anker | Soundcore Liberty 4 |
| Others | See [whisperpair.eu](https://whisperpair.eu) |

---

## Legal Requirements

### You MUST Have Authorization

This tool performs active Bluetooth operations. **Before running any verification commands**, you must have:

1. **Written permission** from the device owner, OR
2. **Own the device** yourself, AND
3. **Authorization** for any network/environment you're testing in

### Jurisdiction-Specific Laws

| Jurisdiction | Relevant Law |
|--------------|--------------|
| **UK** | Computer Misuse Act 1990, Section 1-3A |
| **US** | Computer Fraud and Abuse Act (CFAA) |
| **EU** | Directive 2013/40/EU (Attacks Against Information Systems) |
| **Germany** | § 202a-c StGB |
| **Australia** | Criminal Code Act 1995, Part 10.7 |

**See [LEGAL.md](LEGAL.md) for detailed legal guidance.**

---

## Installation

```bash
git clone https://github.com/SpectrixDev/DIY-WhisperPair.git
cd DIY-WhisperPair

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install
pip install -e .
```

### Requirements

- Python 3.10+
- Bluetooth adapter with BLE support
- Linux: BlueZ 5.50+ (recommended: 5.60+)
- Windows: Windows 10 1703+
- macOS: macOS 10.13+

---

## Usage

### Safety Mechanisms

All verification functionality requires explicit consent flags:

| Flag | Purpose |
|------|---------|
| `--i-accept-responsibility` | Acknowledge legal responsibility |
| `--i-own-this-device` | Confirm device ownership |
| `--i-understand-scope` | Confirm testing only authorized devices |
| Interactive confirmation | Additional prompt before test execution |

### Scanning (Safe - Passive)

```bash
# Scan for Fast Pair devices (passive, no verification)
whisperpair scan

# Find potentially vulnerable devices (not in pairing mode)
whisperpair scan --vulnerable

# Get device information
whisperpair info AA:BB:CC:DD:EE:FF
```

### Verification Commands (Requires Authorization)

```bash
# Verify Fast Pair behavior (requires consent flags)
whisperpair verify AA:BB:CC:DD:EE:FF \
    --i-accept-responsibility \
    --i-own-this-device \
    --i-understand-scope

# Verify Vulnerability (Safe POC)
python security_demo.py \
    --i-accept-responsibility \
    --i-own-this-device \
    --i-understand-scope \
    --target AA:BB:CC:DD:EE:FF

# Skip prompts for automated testing of YOUR OWN devices
python security_demo.py --i-accept-responsibility --i-own-this-device --i-understand-scope --no-confirm
```

### Demo Mode (Educational - Safe)

```bash
whisperpair demo
```

---

## How It Works

### Verification Flow

```
┌─────────────────────────────────────────────────────────────┐
│  1. DISCOVERY                                                │
│     Scan for devices advertising Fast Pair (UUID 0xFE2C)    │
│     Identify devices NOT in pairing mode                     │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  2. CONNECT                                                  │
│     Establish BLE GATT connection                            │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  3. VERIFICATION (CVE-2025-36911)                            │
│     Write Key-based Pairing Request to characteristic        │
│     UUID: FE2C1234-8366-4814-8EB0-01DE32100BEA              │
│                                                              │
│     ⚠️ VULNERABLE: Device accepts despite NOT in pairing     │
│     ✓ PATCHED: Device rejects with ATT error 0x0e           │
└──────────────────────────┬──────────────────────────────────┘
```

### Key UUIDs

| Characteristic | UUID |
|----------------|------|
| Fast Pair Service | `0xFE2C` |
| Model ID | `FE2C1233-8366-4814-8EB0-01DE32100BEA` |
| Key-based Pairing | `FE2C1234-8366-4814-8EB0-01DE32100BEA` |
| Passkey | `FE2C1235-8366-4814-8EB0-01DE32100BEA` |
| Account Key | `FE2C1236-8366-4814-8EB0-01DE32100BEA` |

---

## Project Structure

```
WhisperPair-PoC/
├── src/whisperpair/
│   ├── __init__.py      # Package exports
│   ├── constants.py     # UUIDs, flags, known devices
│   ├── scanner.py       # BLE scanning
│   ├── crypto.py        # AES-128, ECDH, key derivation
│   ├── protocol.py      # Fast Pair packet builders
│   ├── client.py        # GATT client, access logic
│   └── cli.py           # CLI with safety checks
├── tests/
│   └── test_protocol.py # Unit tests
├── security_demo.py     # Full verification flow demo
├── LEGAL.md             # Legal notice and guidance
├── LICENSE              # MIT License
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

## Mitigation

### For Device Manufacturers

1. **Enforce pairing mode check** - Only accept Fast Pair requests when user explicitly enabled pairing
2. **Rate limit requests** - Prevent brute-force attempts
3. **Update firmware** - Apply patches from chipset vendor (Qualcomm, MediaTek, etc.)
4. **Re-certify with Google** - Ensure patches pass Fast Pair certification

### For Users

1. **Update firmware immediately** - Check manufacturer's website/app for security updates
2. **Disable Bluetooth when not needed** - Reduces attack surface
3. **Factory reset before selling** - Clears Account Keys
4. **Monitor for unwanted tracking alerts** - Android shows "Unknown device traveling with you"

### For Security Teams

1. **Scan your fleet** - Use this tool (with authorization) to identify unpatched devices
2. **Block vulnerable firmware** - MDM policies can enforce minimum firmware versions
3. **Incident response** - Look for unexpected Bluetooth pairings in device logs

---

## References

### Original Research
- [WhisperPair Website](https://whisperpair.eu)
- [CVE-2025-36911](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-36911)

### Technical Documentation
- [Google Fast Pair Specification](https://developers.google.com/nearby/fast-pair/specifications/introduction)
- [Fast Pair Characteristics](https://developers.google.com/nearby/fast-pair/specifications/characteristics)
- [Key-based Pairing Protocol](https://developers.google.com/nearby/fast-pair/specifications/characteristics#key-based_pairing)

### Media Coverage
- [WIRED: Hundreds of Millions of Audio Devices Need a Patch](https://www.wired.com/)
- [Ars Technica: Many Bluetooth devices vulnerable to "WhisperPair" hack](https://arstechnica.com/)
- [The Verge: Sony, Anker headphones have serious vulnerability](https://www.theverge.com/)
- [NYT: Wireless Earbuds Can Be Hacked](https://www.nytimes.com/)

---

## Responsible Use

This tool is provided **solely** for:
- Security research and vulnerability verification
- Authorized penetration testing
- Device manufacturer validation
- Educational purposes

**This tool is NOT for:**
- Unauthorized access to any device
- Harassment or surveillance
- Any illegal activity

By using this tool, you accept full legal responsibility for your actions.

---

## License

MIT License with Security Research Addendum - See [LICENSE](LICENSE)

---

## Acknowledgments

- **KU Leuven DistriNet** - Original WhisperPair research
- **Google Android Security Team** - Coordinated disclosure and patches
- **Flemish Government** - Research funding (VOEWICS02)