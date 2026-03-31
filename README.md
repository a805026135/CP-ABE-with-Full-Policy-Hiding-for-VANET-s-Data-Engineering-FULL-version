```markdown
# CP-ABE for VANET - Full Policy Hiding, Revocation & Outsourced Decryption

This repository contains the Java implementation (using JPBC) of the CP-ABE scheme proposed in the paper:

> **"Ciphertext-Policy Attribute-based Encryption with Full Policy-Hiding for VANET's Data Engineering"**  
> *Yanwei Zhou, Kui Ma, Guoji Song, Guangjin Zhang, Zirui Qiao, Xianxiang Liu, Yong Yu*

It also includes several related CP-ABE variants for comparison and evaluation.

## File Structure (under `HideCPABE/`)

| File | Description |
|------|-------------|
| `FullPolicyHidingCPABE.java` | Main implementation of the proposed full policy‑hiding CP‑ABE scheme (key generation, encryption, outsourced decryption). |
| `CPABEWithRevocationAndHiding.java` | Extension of the scheme with dynamic attribute revocation (Algorithm 1) and policy structure hiding via hash chain table. |
| `RevocationExample.java` | Example demonstrating the attribute revocation process and the resulting ciphertext update. |
| `PartialPolicyHiddenABBE.java` | Implementation of a partial policy‑hidden CP‑ABE scheme (for comparison with our full hiding approach). |
| `PHAS_HEKR_CP_ABE.java` | Reimplementation of Zhang et al.'s PHAS‑HEKR‑CP‑ABE scheme (partial policy hiding + efficient revocation). |
| `PMCPABE.java` | Another CP‑ABE variant with partial policy hiding (used as baseline in performance evaluation). |
| `VerifiableCPABE.java` | CP‑ABE with verifiable outsourced decryption (ensuring correctness of cloud computation). |

## Requirements

- Java 8 or higher
- [JPBC 2.0.0](http://gas.dia.unisa.it/projects/jpbc/) (Java Pairing‑Based Cryptography)
- Type A curve parameter file `a.properties` in classpath

## Quick Start

Compile and run any main class (e.g., `FullPolicyHidingCPABE.java`). Example:

```bash
javac -cp jpbc-2.0.0.jar FullPolicyHidingCPABE.java
java -cp .:jpbc-2.0.0.jar FullPolicyHidingCPABE
```

## Key Features Implemented

- ✅ Full policy hiding (both attribute values and LSSS matrix structure)
- ✅ Dynamic attribute revocation (row removal from access matrix)
- ✅ Outsourced decryption with privacy preservation
- ✅ Comparison with partial‑hiding and revocable schemes

## Reference

If you use this code, please cite the original paper (see above).

