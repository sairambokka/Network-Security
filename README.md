# Network Security 🔐

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: Analysis](https://img.shields.io/badge/Security-Analysis-blue.svg)]()
[![Protocols: Cryptography](https://img.shields.io/badge/Protocols-Cryptography-green.svg)]()

This repository contains a collection of projects related to network security protocols, cryptographic algorithms, and their analysis. Each project demonstrates different aspects of security principles, vulnerabilities, and protocol design.

## 📋 Table of Contents
- [Projects Overview](#projects)
  - [SDES Cryptanalysis](#1-sdes-simplified-des-cryptanalysis)
  - [Needham-Schroeder Protocol Analysis](#2-needham-schroeder-protocol-analysis)
  - [Kerberos Protocol Analysis](#3-kerberos-protocol-analysis)
  - [Authentication Protocol Design](#4-authentication-protocol-design)
  - [Fixed Authentication Protocol](#5-fixed-authentication-protocol)
  - [Authentication Protocol Analysis](#6-authentication-protocol-analysis)
  - [TLS Protocol Analysis](#7-tls-protocol-analysis)
- [Tools and Technologies](#tools-and-technologies)
- [Usage](#usage)
- [References](#references)

---

## Projects

### 1. SDES (Simplified DES) Cryptanalysis
<details>
<summary>🔍 Click to expand details</summary>

Implementation of the Simplified Data Encryption Standard along with various cryptanalysis techniques:
- Simple SDES implementation
- Double SDES implementation
- Brute force attacks
- Meet-in-the-middle attacks
- Weak key analysis
- Performance testing

```python
# Example of SDES encryption (simplified)
def encrypt(plaintext, key):
    # Key generation
    subkeys = generate_subkeys(key)
    # Initial permutation
    ip_result = initial_permutation(plaintext)
    # Complex function application with subkeys
    result = complex_function_f(ip_result, subkeys)
    # Final permutation
    return final_permutation(result)
```

**Directory:** [SDES_Cryptanalysis](./SDES_Cryptanalysis)
</details>

### 2. Needham-Schroeder Protocol Analysis
<details>
<summary>🔒 Click to expand details</summary>

Analysis of the Needham-Schroeder Symmetric Key Protocol using formal methods:
- Protocol modeling in CPSA (Cryptographic Protocol Shapes Analyzer)
- Verification of security properties
- Includes the original 1978 Needham-Schroeder paper
- Vulnerability analysis and attack demonstration

| Protocol Step | Description | Security Properties |
|---------------|-------------|---------------------|
| 1. A → S: A,B,Na | Initiation request with nonce | Freshness |
| 2. S → A: {Na,B,Kab,{Kab,A}Kbs}Kas | Key distribution | Confidentiality, Authentication |
| 3. A → B: {Kab,A}Kbs | Key forwarding | Authentication |
| 4. B → A: {Nb}Kab | Challenge | Authentication |
| 5. A → B: {Nb-1}Kab | Response | Authentication |

**Directory:** [Needham_Schroeder_Protocol_Analysis](./Needham_Schroeder_Protocol_Analysis)
</details>

### 3. Kerberos Protocol Analysis
<details>
<summary>🔑 Click to expand details</summary>

Examination of the Kerberos authentication protocol:
- Analysis of Kerberos V4
- Analysis of Kerberos V5
- Security properties and potential vulnerabilities

**Directory:** [Kerberos_Protocol_Analysis](./Kerberos_Protocol_Analysis)
</details>

### 4. Authentication Protocol Design
<details>
<summary>🛠️ Click to expand details</summary>

Custom authentication protocol design and analysis:
- Protocol specification
- Formal modeling using CPSA
- Security properties verification
- Documentation of design decisions

**Directory:** [Authentication_Protocol_Design](./Authentication_Protocol_Design)
</details>

### 5. Fixed Authentication Protocol
<details>
<summary>🔧 Click to expand details</summary>

Implementation of improved authentication protocol with:
- Vulnerabilities fixed from previous versions
- Security verification
- Implementation details

**Directory:** [Fixed_Authentication_Protocol](./Fixed_Authentication_Protocol)
</details>

### 6. Authentication Protocol Analysis
<details>
<summary>🔎 Click to expand details</summary>

Further analysis of authentication protocols focusing on:
- Security properties
- Formal verification
- Attack scenarios

**Directory:** [Authentication_Protocol_Analysis_4](./Authentication_Protocol_Analysis_4)
</details>

### 7. TLS Protocol Analysis
<details>
<summary>🌐 Click to expand details</summary>

Analysis of Transport Layer Security (TLS) protocols:
- TLS 1.2 RSA and DHE analysis
- TLS 1.3 analysis
- Protocol modeling using CPSA
- Security verification

**Directory:** [TLS_Protocol_Analysis](./TLS_Protocol_Analysis)
</details>

---

## Tools and Technologies

| Tool/Technology | Purpose | Used In |
|-----------------|---------|---------|
| CPSA | Cryptographic Protocol Shapes Analyzer | Protocol Analysis Projects |
| Python | Cryptographic Implementations | SDES Cryptanalysis |
| Formal Methods | Security Verification | All Protocol Analysis Projects |

## Usage

Each project directory contains specific documentation and implementation details. To get started:

1. Clone the repository:
   ```bash
   git clone https://github.com/username/Network-Security.git
   cd Network-Security
   ```

2. Navigate to the specific project directory:
   ```bash
   cd SDES_Cryptanalysis
   ```

3. Follow the instructions in the project's documentation.

## References

- 📄 Needham, R. M., & Schroeder, M. D. (1978). Using encryption for authentication in large networks of computers. Communications of the ACM, 21(12), 993-999.
- 📄 Kerberos: The Network Authentication Protocol - MIT
- 📄 TLS Protocol Version 1.2 - RFC 5246
- 📄 TLS Protocol Version 1.3 - RFC 8446
