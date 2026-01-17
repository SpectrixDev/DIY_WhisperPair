# Legal Notice and Guidance

**Last Updated**: January 2026

This document provides legal context for the WhisperPair PoC tool. This is **not legal advice**. If you have specific legal questions, consult a qualified solicitor/attorney in your jurisdiction.

---

## Summary

| Action | Legal Status |
|--------|--------------|
| Scanning for devices (passive) | Generally lawful |
| Testing your OWN devices | Lawful |
| Testing devices WITH authorization | Lawful |
| Testing devices WITHOUT authorization | **ILLEGAL** |
| Distributing for research | Protected (post-disclosure) |

---

## UK Law: Computer Misuse Act 1990

The primary legislation in the United Kingdom is the **Computer Misuse Act 1990** (CMA).

### Section 1 - Unauthorized Access

> A person is guilty of an offence if:
> (a) he causes a computer to perform any function with intent to secure access to any program or data held in any computer;
> (b) the access he intends to secure is unauthorised; and
> (c) he knows at the time when he causes the computer to perform the function that that is the case.

**Penalty**: Up to 2 years imprisonment

### Section 3 - Unauthorized Acts with Intent to Impair

> A person is guilty of an offence if:
> (a) he does any unauthorised act in relation to a computer;
> (b) at the time when he does the act he knows that it is unauthorised; and
> (c) either [intent to impair or recklessness as to impairing]

**Penalty**: Up to 10 years imprisonment

### Section 3A - Making, Supplying or Obtaining Articles for Use in Offences

> A person is guilty of an offence if he makes, adapts, supplies or offers to supply any article:
> (a) knowing that it is designed or adapted for use in the course of or in connection with an offence under section 1, 3 or 3ZA; or
> (b) intending it to be used to commit, or to assist in the commission of, an offence under section 1, 3 or 3ZA

**Penalty**: Up to 2 years imprisonment

---

## Why This Tool Is Lawful to Distribute

### 1. Dual-Use Nature

The Crown Prosecution Service (CPS) guidance on Section 3A recognizes that security tools have legitimate uses. The CPS states:

> "Prosecutors should be aware that there are legitimate reasons for the creation and supply of such tools, e.g. for use by security researchers, penetration testers, and network administrators."

### 2. Intent and Purpose

The key factor is **intent**. This tool is:
- Released **after** responsible disclosure
- Released **after** patches are available
- Intended for security research and authorized testing
- Documented with clear legal warnings
- Equipped with safety mechanisms requiring explicit consent

### 3. Post-Disclosure Release

This tool implements a vulnerability that:
- Was reported to Google in August 2025
- Followed a 150-day coordinated disclosure window
- Is now publicly documented (CVE-2025-36911)
- Has been covered by major media outlets
- Has patches available from manufacturers

Releasing security research after responsible disclosure is recognized as legitimate security practice.

### 4. Legitimate Use Cases

This tool enables:
- **Security researchers** to study the vulnerability
- **Device manufacturers** to verify their patches work
- **Penetration testers** to assess authorized environments
- **IT security teams** to identify unpatched devices in their fleet
- **Educators** to teach about Bluetooth security

---

## Your Responsibilities

### Before Using This Tool

1. **Verify ownership or authorization**
   - You own the device, OR
   - You have written permission from the device owner, AND
   - You have authorization for the testing environment

2. **Understand the law**
   - Familiarize yourself with laws in your jurisdiction
   - When in doubt, seek legal advice

3. **Document your authorization**
   - Keep records of permission/authorization
   - Use written agreements for professional engagements

### When Using This Tool

1. **Use the safety flags**
   - `--authorized`: Confirm you own the device and accept responsibility

2. **Limit scope**
   - Only target devices covered by your authorization
   - Do not "accidentally" test other devices in range

3. **Record your testing**
   - Keep logs of what you tested and when
   - Document the purpose (verification, pentest, research)

---

## Comparison: Lawful vs. Unlawful Use

### Lawful Examples

| Scenario | Why It's Lawful |
|----------|-----------------|
| Testing your own Sony earbuds to see if firmware update worked | You own the device |
| Pentest engagement with signed contract covering Bluetooth devices | Written authorization |
| University research lab testing purchased devices | Owned by institution |
| Manufacturer verifying patch before release | Authorized product testing |
| Security team scanning corporate fleet with IT approval | Organizational authorization |

### Unlawful Examples

| Scenario | Why It's Unlawful |
|----------|-------------------|
| Testing a stranger's earbuds on the train | No authorization |
| Demonstrating verification on friend's device without asking | No explicit consent |
| Using tool to eavesdrop on anyone | Surveillance without consent |
| Scanning public spaces to find vulnerable devices to access | Unauthorized access |

---

## Professional Penetration Testing

If you're using this tool professionally:

### Required Documentation

1. **Statement of Work (SoW)** or **Rules of Engagement (RoE)**
2. **Explicit scope** including Bluetooth/wireless testing
3. **Get-out-of-jail letter** from authorized signatory
4. **Insurance** (professional indemnity)

### Best Practices

1. Test in controlled environments when possible
2. Notify building security/IT when testing wireless
3. Have emergency contact for scope questions
4. Document everything

---

## Other Jurisdictions

### United States

**Computer Fraud and Abuse Act (CFAA)**, 18 U.S.C. § 1030

Similar provisions to UK CMA. Unauthorized access is federal offense.

### European Union

**Directive 2013/40/EU** on attacks against information systems

Member states implement similar unauthorized access offenses.

### Germany

**§ 202a StGB** (Ausspähen von Daten)
**§ 202b StGB** (Abfangen von Daten)
**§ 202c StGB** (Vorbereiten des Ausspähens und Abfangens von Daten)

Note: Germany has strict laws on "hacker tools" but recognizes security research exceptions.

### Australia

**Criminal Code Act 1995**, Part 10.7

Covers unauthorized access to computer systems including IoT devices.

---

## Contact

If you have questions about the legal status of this tool or security research in general:

### UK Resources
- **National Cyber Security Centre (NCSC)**: [ncsc.gov.uk](https://www.ncsc.gov.uk)
- **CPS Guidance on CMA**: Search "CPS Computer Misuse Act guidance"

### General Security Research
- **EFF Coders' Rights Project**: [eff.org/issues/coders](https://www.eff.org/issues/coders)
- **Disclose.io**: [disclose.io](https://disclose.io) - Safe harbor templates

---

## Disclaimer

THIS DOCUMENT IS PROVIDED FOR INFORMATIONAL PURPOSES ONLY AND DOES NOT CONSTITUTE LEGAL ADVICE. THE AUTHORS ARE NOT SOLICITORS OR ATTORNEYS. LAWS VARY BY JURISDICTION AND CHANGE OVER TIME. IF YOU HAVE SPECIFIC LEGAL QUESTIONS, CONSULT A QUALIFIED LEGAL PROFESSIONAL IN YOUR JURISDICTION.

BY USING THIS SOFTWARE, YOU ACKNOWLEDGE THAT YOU HAVE READ AND UNDERSTOOD THIS LEGAL NOTICE AND ACCEPT FULL RESPONSIBILITY FOR YOUR USE OF THE SOFTWARE.
