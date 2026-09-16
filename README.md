# eCloakCore

**eCloak Core C++ Qt Plugin Engine** for **Logos Basecamp**, bridging the **E-Identity Stack** (`e_identity_sdk` and `e_moderation_sdk`) to the Basecamp QML frontend via C-ABI FFI.

## Architectural Overview

`el-anon-chat-core` () implements the `PluginInterface` and exposes `AnonChatInterface` to Basecamp, providing native cryptographic capabilities:

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

## Directory Structure

```
eCloakCore/
├── LICENSE                 # Business Source License 1.1 (BSL 1.1)
├── CMakeLists.txt          # CMake plugin build script (logos_module)
├── metadata.json           # Basecamp core module manifest
├── flake.nix               # Nix packaging definition
├── README.md               # Architecture and integration documentation
├── lib/                    # Vendor FFI binaries & headers
│   ├── e_identity_sdk.h
│   ├── e_moderation_sdk.h
│   ├── libe_identity_sdk.so
│   └── libe_moderation_sdk.so
└── src/
    ├── anon_chat_interface.h  # Qt Plugin Interface definition
    ├── anon_chat_plugin.h     # QObject Plugin declaration
    └── anon_chat_plugin.cpp   # Implementation bridging Qt/QML to Rust FFI
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
