# Evice Cloak Core

**e-cloak-core** is the native C++ Qt Plugin Engine for **Logos Basecamp**, bridging the **e-identity-stack** (`e_identity_sdk` and `e_moderation_sdk`) to the **e-cloak** QML frontend via C-ABI FFI and Basecamp IPC.

## Architectural Overview

`e-cloak-core` implements the core backend service and exposes cryptographic and storage APIs to Basecamp:

1. **Identity Management**:
   - Random and deterministic Nullifier Secret Key (NSK) derivation.
   - Commitment computation: `SHA256(NSK)`.
   - Off-chain username registry with Schnorr signature authentication.

2. **Decentralized Room Management**:
   - Deterministic room creation (`SHA256(admin_commitment || creation_index || n_mod || m_mod)`).
   - Cryptographically signed join-consent requests.
   - Room maturity validation (age indexes and active member tracking).

3. **Two-Tier Shamir Secret Sharing (SSS) Chat Messaging**:
   - `MemberClient` integration: creates post payloads with Tier-2 point assignment.
   - Tier-1 N-of-M splitting per post.
   - Diffie-Hellman (ECDH) encryption of secret shares targeted at individual moderator public keys.

4. **Moderator Strike Protocol**:
   - `ModeratorClient` share decryption using secp256k1 private keys.
   - BIP-340 Schnorr strike certification.
   - Multi-signature certificate validation.

5. **Lagrange Slashing & Identity De-Anonymization**:
   - Tier-1 strike reconstruction from N moderator shares over GF(2⁸).
   - Tier-2 full NSK reconstruction from K accumulated strikes.
   - Identity commitment blacklisting.

6. **Encrypted Blob & Chat Storage**:
   - High-performance Zstandard compression (`ZSTD_compress`).
   - Authenticated encryption via OpenSSL AES-256-GCM.
   - Key derivation using SHA-256 from user's Nullifier Secret Key (NSK).
   - Storage path under `module_data/e-cloak-core` with automatic backward-compatibility migration from `module_data/ecloakcore`.

## Directory Structure

```
e-cloak-core/
├── LICENSE                 # Business Source License 1.1 (BSL 1.1)
├── CMakeLists.txt          # CMake plugin build script (logos_module)
├── metadata.json           # Basecamp core module manifest (e_cloak_core / e-cloak-core)
├── flake.nix               # Nix packaging definition
├── README.md               # Architecture and integration documentation
├── lib/                    # Vendor FFI binaries & headers from e-identity-stack
│   ├── e_identity_sdk.h    # Cryptographic identity & vault headers
│   ├── e_moderation_sdk.h  # GF(2^8) & Shamir Secret Sharing headers
│   ├── libe_identity_sdk.so
│   └── libe_moderation_sdk.so
└── src/
    ├── e_cloak_core_impl.h    # Core module implementation header
    └── e_cloak_core_impl.cpp  # Implementation bridging Qt/QML to Rust FFI & encrypted storage
```

## Build Instructions

Using Nix with Logos Module Builder:

```bash
nix build .#
```

## License

This project is licensed under the **Business Source License 1.1 (BSL 1.1)**.

- **Free for non-commercial use**, evaluation, personal privacy, academic research, and public security audits.
- **Commercial deployment or SaaS hosting** requires a commercial license agreement from **Evice Labs**.
- Effective **September 12, 2029**, this work converts automatically to the **Apache License, Version 2.0**.

See the full [LICENSE](LICENSE) file for terms and conditions.

---

<p align="center">
  Copyright &copy; 2026 <strong>Evice Labs</strong>. All rights reserved.
</p>
