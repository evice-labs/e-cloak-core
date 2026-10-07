# Evice Cloak Core

**e-cloak-core** is the native C++ Qt Plugin Engine for **Logos Basecamp**, bridging the **e-identity-stack** (`e_identity_sdk`, `e_moderation_sdk`, and `e_chat_bridge`) and decentralized transport (**logos-delivery**) to the **e-cloak** QML frontend via C-ABI FFI and Basecamp IPC.

## Architectural Overview

`e-cloak-core` implements the core backend service and exposes cryptographic, messaging, and storage APIs to Basecamp:

1. **Identity Management**:
   - Random and deterministic Nullifier Secret Key (NSK) derivation.
   - Commitment computation: `SHA256(NSK)`.
   - Off-chain and on-chain username registry with Schnorr signature authentication.
   - Strict username validation: 3..32 characters, ASCII alphanumeric + underscore (`_`), with case-insensitive collision rejection.
   - Zero-cost on-chain registration (fees covered by eCloak sponsor account `Public/9p7BZn9g6UrVMBiatyeNtq4yv9DitxYM1ZXsjYi6vf47`). Sybil and spam deterrence are enforced cryptographically via Two-Tier SSS de-anonymization and on-chain commitment revocation without requiring user collateral.

2. **Decentralized Room Management**:
   - Deterministic room creation (`SHA256(admin_commitment || creation_index || n_mod || m_mod)`).
   - Cryptographically signed join-consent requests.
   - Room maturity validation (age indexes and active member tracking).

3. **Decentralized MLS (RFC 9420) Group & 1-on-1 Chat**:
   - Native integration with `e_chat_bridge` (Messaging Layer Security engine).
   - Joiner client workflow: RFC 9420 `KeyPackage` generation and sharing.
   - Epoch commit & `Welcome` message generation and ratchet tree state synchronization.
   - Forward secrecy and post-compromise security (PCS) across member joins and message epochs.
   - End-to-end encrypted 1-on-1 private Direct Messages (DMs).

4. **Two-Tier Shamir Secret Sharing (SSS) Chat Messaging**:
   - `MemberClient` integration: creates post payloads with Tier-2 point assignment.
   - Tier-1 N-of-M splitting per post.
   - Diffie-Hellman (ECDH) encryption of secret shares targeted at individual moderator public keys.
   - Seamless MLS payload binding: combines MLS group ratchet encryption with verifiable Two-Tier SSS shares.

5. **Moderator Strike Protocol**:
   - `ModeratorClient` share decryption using secp256k1 private keys.
   - BIP-340 Schnorr strike certification.
   - Multi-signature certificate validation.

6. **Lagrange Slashing & Identity De-Anonymization**:
   - Tier-1 strike reconstruction from N moderator shares over GF(2⁸).
   - Tier-2 full NSK reconstruction from K accumulated strikes.
   - Identity commitment blacklisting and automatic revocation.

7. **Decentralized Transport (Logos Delivery / Waku)**:
   - Dynamic linking and runtime loading (`dlopen`) of `liblogosdelivery.so`.
   - Waku v2 content topic pub/sub routing:
     - Group messages: `/e-identity/1/room-{roomIdHex}/proto`
     - Handshake messages: `/e-identity/1/room-{roomIdHex}-handshake/proto`
     - 1-on-1 DMs: `/e-identity/1/dm-{channelIdHex}/proto`
   - Resilient transport fallback with in-memory buffering for offline and standalone operations.

8. **Encrypted Blob & Persistent Chat Storage**:
   - High-performance Zstandard compression (`ZSTD_compress`).
   - Authenticated encryption via OpenSSL AES-256-GCM.
   - Key derivation using SHA-256 from user's Nullifier Secret Key (NSK).
   - Storage path under `module_data/e-cloak-core` with automatic backward-compatibility migration from `module_data/ecloakcore`.

9. **Global User Discovery & Headless Dispatcher Integration**:
   - **Hybrid Registry Persistence**: Active identities and discovered contacts stored in `module_data/e-cloak-core/registered_users.json`.
   - **Decentralized P2P Peer Announcements**: Newly registered users are automatically published over Logos Delivery (Waku) topic `/e-identity/1/global-registry/proto`, enabling instant, zero-config user discovery across distinct app instances.
   - **Headless On-Chain Dispatcher**: Background execution of `e_cloak_dispatcher register-username` directly submitting transactions to LEZ Testnet with real-time inclusion polling.

## Directory Structure

```
e-cloak-core/
├── LICENSE                 # Business Source License 1.1 (BSL 1.1)
├── CMakeLists.txt          # CMake plugin build script (logos_module)
├── metadata.json           # Basecamp core module manifest (e_cloak_core)
├── flake.nix               # Nix packaging definition
├── README.md               # Architecture and integration documentation
├── lib/                    # Vendor FFI binaries & headers from e-identity-stack
│   ├── e_identity_sdk.h    # Cryptographic identity & vault headers
│   ├── libe_identity_sdk.so
│   ├── e_moderation_sdk.h  # GF(2^8) & Shamir Secret Sharing headers
│   ├── libe_moderation_sdk.so
│   ├── e_chat_bridge.h     # RFC 9420 Messaging Layer Security (MLS) headers
│   └── libe_chat_bridge.so
├── src/
│   ├── e_cloak_core_impl.h    # Core module implementation header
│   └── e_cloak_core_impl.cpp  # Implementation bridging Qt/QML to Rust FFI & transport
└── tests/
    ├── test_de_mls_integration.cpp # End-to-end de-MLS & Logos Delivery integration test suite
    └── test_user_discovery.cpp     # User discovery, validation & registry integration test suite
```

## Build & Test Instructions

### Building with Nix (Recommended)

Using Nix with Logos Module Builder:

```bash
nix build .# --no-link --print-out-paths
```

### Running Integration Tests

#### 1. User Discovery, Validation & Global Registry Suite
Compile and execute the user discovery integration test:

```bash
/usr/bin/g++ -std=c++20 \
  tests/test_user_discovery.cpp \
  src/e_cloak_core_impl.cpp \
  -Isrc -Ilib \
  -Llib -le_identity_sdk -le_moderation_sdk -le_chat_bridge -lcrypto -lzstd -ldl \
  -Wl,-rpath,lib \
  -o tests/test_user_discovery_runner && ./tests/test_user_discovery_runner
```

#### 2. Decentralized MLS & Logos Delivery Suite
Compile and execute the end-to-end de-MLS test runner:

```bash
/usr/bin/g++ -std=c++20 \
  tests/test_de_mls_integration.cpp \
  src/e_cloak_core_impl.cpp \
  -Isrc -Ilib \
  -Llib -le_identity_sdk -le_moderation_sdk -le_chat_bridge -lcrypto -lzstd -ldl \
  -Wl,-rpath,lib \
  -o tests/test_de_mls_runner && ./tests/test_de_mls_runner
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
