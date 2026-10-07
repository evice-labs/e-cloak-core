#include "e_cloak_core_impl.h"
#include "../lib/e_identity_sdk.h"
#include "../lib/e_moderation_sdk.h"
#include "../lib/e_chat_bridge.h"
#include <dlfcn.h>

#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>
#include <vector>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <zstd.h>
#include <thread>
#include <chrono>
#include <strings.h>

using json = nlohmann::json;

// Internal Helper Functions

static std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::string s = hex;
    if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) {
        s = s.substr(2);
    }
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < s.length(); i += 2) {
        if (i + 1 < s.length()) {
            try {
                uint8_t byte = static_cast<uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16));
                bytes.push_back(byte);
            } catch (...) {
                return {};
            }
        }
    }
    return bytes;
}

static std::string bytesToHex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

static std::string makeErrorJson(const std::string& msg) {
    json j;
    j["error"] = msg;
    return j.dump();
}

// Implementation

static std::string getModuleDataDir() {
    std::string root;
    const char* customDir = std::getenv("LOGOS_USER_DIR");
    if (customDir && std::strlen(customDir) > 0) {
        root = std::string(customDir) + "/module_data";
    } else {
#if defined(_WIN32)
        const char* appData = std::getenv("APPDATA");
        if (appData && std::strlen(appData) > 0) {
            root = std::string(appData) + "/Logos/LogosBasecamp/module_data";
        } else {
            root = "C:/LogosBasecamp/module_data";
        }
#elif defined(__APPLE__)
        const char* home = std::getenv("HOME");
        if (home && std::strlen(home) > 0) {
            root = std::string(home) + "/Library/Application Support/Logos/LogosBasecamp/module_data";
        } else {
            root = "/tmp";
        }
#else
        const char* xdgData = std::getenv("XDG_DATA_HOME");
        if (xdgData && std::strlen(xdgData) > 0) {
            root = std::string(xdgData) + "/Logos/LogosBasecamp/module_data";
        } else {
            const char* home = std::getenv("HOME");
            if (home && std::strlen(home) > 0) {
                root = std::string(home) + "/.local/share/Logos/LogosBasecamp/module_data";
            } else {
                root = "/tmp";
            }
        }
#endif
    }

    std::string moduleDataDir = root + "/e-cloak-core";
    std::error_code ec;
    std::filesystem::create_directories(moduleDataDir, ec);
    return moduleDataDir;
}

static std::string getIdentityFilePath() {
    return getModuleDataDir() + "/identity.json";
}

static std::string getChatStoreFilePath() {
    return getModuleDataDir() + "/chat_store.json";
}

static std::string getChatStoreEncFilePath() {
    return getModuleDataDir() + "/chat_store.enc";
}

static std::string getWalletStoreFilePath() {
    return getModuleDataDir() + "/wallet_store.json";
}

static std::string getRegisteredUsersFilePath() {
    return getModuleDataDir() + "/registered_users.json";
}

static std::string getProfilesFilePath() {
    return getModuleDataDir() + "/profiles.json";
}

static std::string getBlobsDir() {
    std::string dir = getModuleDataDir() + "/blobs";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return dir;
}

static std::vector<uint8_t> base64Decode(const std::string& input) {
    std::string clean = input;
    auto commaPos = clean.find(',');
    if (commaPos != std::string::npos && clean.find("base64") != std::string::npos) {
        clean = clean.substr(commaPos + 1);
    }
    clean.erase(std::remove_if(clean.begin(), clean.end(), [](unsigned char c) {
        return std::isspace(c);
    }), clean.end());

    static const std::string b64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[b64Chars[i]] = i;

    std::vector<uint8_t> out;
    int val = 0, valb = -8;
    for (unsigned char c : clean) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

static std::string base64Encode(const uint8_t* data, size_t len) {
    static const char b64Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (size_t i = 0; i < len; ++i) {
        val = (val << 8) + data[i];
        valb += 8;
        while (valb >= 0) {
            out.push_back(b64Chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(b64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

static std::string computeSha256Hex(const uint8_t* data, size_t len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

static std::vector<uint8_t> compressZstd(const std::string& input) {
    size_t const maxDstSize = ZSTD_compressBound(input.size());
    std::vector<uint8_t> dst(maxDstSize);
    size_t const cSize = ZSTD_compress(dst.data(), maxDstSize, input.data(), input.size(), 3);
    if (ZSTD_isError(cSize)) {
        throw std::runtime_error(std::string("ZSTD compression failed: ") + ZSTD_getErrorName(cSize));
    }
    dst.resize(cSize);
    return dst;
}

static std::string decompressZstd(const uint8_t* src, size_t srcSize) {
    unsigned long long rSize = ZSTD_getFrameContentSize(src, srcSize);
    if (rSize == ZSTD_CONTENTSIZE_ERROR) {
        throw std::runtime_error("ZSTD frame content size error");
    }
    if (rSize == ZSTD_CONTENTSIZE_UNKNOWN) {
        rSize = srcSize * 4 + 1024;
    }
    std::string out;
    out.resize(rSize);
    size_t const dSize = ZSTD_decompress(&out[0], out.size(), src, srcSize);
    if (ZSTD_isError(dSize)) {
        throw std::runtime_error(std::string("ZSTD decompression failed: ") + ZSTD_getErrorName(dSize));
    }
    out.resize(dSize);
    return out;
}

static std::vector<uint8_t> deriveStorageKey(const uint8_t* secret, size_t secretLen) {
    std::vector<uint8_t> key(32);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        std::string s(reinterpret_cast<const char*>(secret), secretLen);
        s += "eCloak-ChatStore-v1";
        SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), hash);
        std::memcpy(key.data(), hash, 32);
        return key;
    }
    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretLen) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char*)"eCloak-ChatStore-v1", 19) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        unsigned char hash[SHA256_DIGEST_LENGTH];
        std::string s(reinterpret_cast<const char*>(secret), secretLen);
        s += "eCloak-ChatStore-v1";
        SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), hash);
        std::memcpy(key.data(), hash, 32);
        return key;
    }
    size_t outlen = 32;
    EVP_PKEY_derive(pctx, key.data(), &outlen);
    EVP_PKEY_CTX_free(pctx);
    return key;
}

static std::vector<uint8_t> encryptAes256Gcm(const std::vector<uint8_t>& key,
                                             const std::vector<uint8_t>& plaintext) {
    std::vector<uint8_t> iv(12);
    if (RAND_bytes(iv.data(), 12) != 1) {
        throw std::runtime_error("RAND_bytes failed for AES-GCM IV");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to init AES-256-GCM encrypt");
    }

    std::vector<uint8_t> ciphertext(plaintext.size());
    int outLen = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    ciphertext.resize(outLen + finalLen);

    std::vector<uint8_t> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get GCM tag");
    }
    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> result;
    result.reserve(4 + 1 + 12 + 16 + ciphertext.size());
    result.push_back('E');
    result.push_back('C');
    result.push_back('L');
    result.push_back('K');
    result.push_back(0x01);
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), tag.begin(), tag.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    return result;
}

static std::vector<uint8_t> decryptAes256Gcm(const std::vector<uint8_t>& key,
                                             const std::vector<uint8_t>& encData) {
    if (encData.size() < (4 + 1 + 12 + 16)) {
        throw std::runtime_error("Encrypted data too small");
    }
    if (encData[0] != 'E' || encData[1] != 'C' || encData[2] != 'L' || encData[3] != 'K' || encData[4] != 0x01) {
        throw std::runtime_error("Invalid file magic or version");
    }
    const uint8_t* iv = encData.data() + 5;
    const uint8_t* tag = encData.data() + 5 + 12;
    const uint8_t* ciphertext = encData.data() + 5 + 12 + 16;
    size_t cipherLen = encData.size() - (5 + 12 + 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to init AES-256-GCM decrypt");
    }

    std::vector<uint8_t> plaintext(cipherLen);
    int outLen = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outLen, ciphertext, cipherLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set GCM tag");
    }

    int finalLen = 0;
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen, &finalLen);
    EVP_CIPHER_CTX_free(ctx);
    if (ret <= 0) {
        throw std::runtime_error("AES-256-GCM authentication failed: data corrupted or wrong key");
    }
    plaintext.resize(outLen + finalLen);
    return plaintext;
}

ECloakCoreImpl::ECloakCoreImpl()
{
    m_usernameRegistry = ffi_username_registry_new();
    m_roomRegistry = ffi_room_registry_new();
    m_moderatorRegistry = ffi_moderator_registry_new();
    m_blacklist = ffi_blacklist_new();
    loadPersistedIdentity();
    if (m_registration && !m_cachedUsername.empty() && m_usernameRegistry) {
        uint8_t comm[32];
        ffi_registration_commitment(m_registration, comm);
        char* regRes = ffi_username_registry_register(m_usernameRegistry, comm, m_cachedUsername.c_str());
        if (regRes) ffi_identity_free_string(regRes);
    }

    // Auto-sync state from on-chain LEZ smart contract in background
    std::thread([this]() {
        syncFromOnChainState();
    }).detach();
}

ECloakCoreImpl::~ECloakCoreImpl()
{
    if (m_registration) ffi_registration_free(m_registration);
    if (m_usernameRegistry) ffi_username_registry_free(m_usernameRegistry);
    if (m_roomRegistry) ffi_room_registry_free(m_roomRegistry);
    if (m_moderatorRegistry) ffi_moderator_registry_free(m_moderatorRegistry);
    if (m_blacklist) ffi_blacklist_free(m_blacklist);
    if (m_member) ffi_member_free(m_member);
    if (m_moderator) ffi_moderator_free(m_moderator);
    if (m_aggregator) ffi_aggregator_free(m_aggregator);

    for (auto& [id, sess] : m_chatSessions) {
        if (sess) {
            ffi_chat_session_free(sess);
        }
    }
    m_chatSessions.clear();
    if (m_chatJoiner) {
        ffi_chat_joiner_free(m_chatJoiner);
        m_chatJoiner = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Identity Operations
// ---------------------------------------------------------------------------

void ECloakCoreImpl::loadPersistedIdentity()
{
    try {
        std::string path = getIdentityFilePath();
        if (!std::filesystem::exists(path)) return;
        std::ifstream file(path);
        if (!file.is_open()) return;
        json j;
        file >> j;
        if (j.contains("nsk") && j["nsk"].is_string()) {
            std::string nskHex = j["nsk"].get<std::string>();
            std::vector<uint8_t> bytes = hexToBytes(nskHex);
            if (bytes.size() == 32) {
                if (m_registration) ffi_registration_free(m_registration);
                m_registration = ffi_registration_from_nsk(bytes.data());
                if (j.contains("staked") && j["staked"].is_boolean()) {
                    m_staked = j["staked"].get<bool>();
                    if (j.contains("stake_amount") && j["stake_amount"].is_number_unsigned()) {
                        m_stakeAmount = j["stake_amount"].get<uint64_t>();
                    }
                }
                if (j.contains("onchain_synced") && j["onchain_synced"].is_boolean()) {
                    m_onchainSynced = j["onchain_synced"].get<bool>();
                }
                if (j.contains("tx_hash") && j["tx_hash"].is_string()) {
                    m_onchainTxHash = j["tx_hash"].get<std::string>();
                }
                if (j.contains("username") && j["username"].is_string() && m_usernameRegistry) {
                    std::string u = j["username"].get<std::string>();
                    m_cachedUsername = u;
                    if (!u.empty()) {
                        uint8_t comm[32];
                        ffi_registration_commitment(m_registration, comm);
                        char* res = ffi_username_registry_register(m_usernameRegistry, comm, u.c_str());
                        if (res) ffi_identity_free_string(res);
                    }
                }
            }
        }
    } catch (...) {}
}

void ECloakCoreImpl::savePersistedIdentity()
{
    if (!m_registration) return;
    try {
        uint8_t comm[32];
        ffi_registration_commitment(m_registration, comm);
        uint8_t nsk[32];
        ffi_registration_nsk(m_registration, nsk);

        json j;
        j["commitment"] = bytesToHex(comm, 32);
        j["nsk"] = bytesToHex(nsk, 32);
        j["username"] = m_cachedUsername;
        j["staked"] = m_staked;
        j["stake_amount"] = m_stakeAmount;
        j["onchain_synced"] = m_onchainSynced;
        if (!m_onchainTxHash.empty()) {
            j["tx_hash"] = m_onchainTxHash;
        }

        std::string path = getIdentityFilePath();
        std::ofstream file(path);
        if (file.is_open()) {
            file << j.dump(2);
        }
    } catch (...) {}
}

std::string ECloakCoreImpl::getIdentityInfo()
{
    json res;
    if (!m_registration) {
        res["has_identity"] = false;
        res["commitment"] = "";
        res["nsk"] = "";
        res["username"] = "";
        return res.dump();
    }
    uint8_t comm[32];
    ffi_registration_commitment(m_registration, comm);
    uint8_t nsk[32];
    ffi_registration_nsk(m_registration, nsk);
    res["has_identity"] = true;
    res["commitment"] = bytesToHex(comm, 32);
    res["nsk"] = bytesToHex(nsk, 32);
    res["username"] = m_cachedUsername;
    res["staked"] = m_staked;
    res["stake_amount"] = m_stakeAmount;
    res["onchain_synced"] = m_onchainSynced;
    if (!m_onchainTxHash.empty()) {
        res["tx_hash"] = m_onchainTxHash;
    }
    res["schnorr_pubkey"] = getSchnorrPublicKey();
    return res.dump();
}

std::string ECloakCoreImpl::getNetworkStatus()
{
    json res;
    res["connected"] = true;
    res["network_name"] = "Logos Execution Zone (LEZ) Testnet";
    res["sequencer_url"] = "https://testnet.lez.logos.co/";
    res["min_stake_amount"] = 0;
    res["required_collateral_lez"] = 0;
    res["collateral_active"] = true;
    res["stake_amount"] = m_stakeAmount;
    res["has_active_identity"] = (m_registration != nullptr);
    res["onchain_synced"] = m_onchainSynced;
    if (m_registration) {
        uint8_t comm[32];
        ffi_registration_commitment(m_registration, comm);
        res["commitment"] = bytesToHex(comm, 32);
    } else {
        res["commitment"] = "";
    }
    return res.dump();
}

std::string ECloakCoreImpl::recordStake(uint64_t amount)
{
    if (!m_registration) return makeErrorJson("No active identity to stake for");
    m_staked = true;
    m_stakeAmount = amount;
    savePersistedIdentity();
    json j;
    j["ok"] = true;
    j["staked"] = true;
    j["stake_amount"] = amount;
    return j.dump();
}

std::string ECloakCoreImpl::createIdentity(const std::string& nskHex)
{
    // Maximum 2 accounts per computer validation
    syncProfilesStorage();
    try {
        std::string pPath = getProfilesFilePath();
        if (std::filesystem::exists(pPath)) {
            std::ifstream f(pPath);
            if (f.is_open()) {
                json pj; f >> pj;
                if (pj.contains("profiles") && pj["profiles"].is_array() && pj["profiles"].size() >= 2) {
                    return makeErrorJson("Maximum 2 accounts per computer reached. Cannot add more identities.");
                }
            }
        }
    } catch (...) {}

    // Anti-Bypass Guard: Prevent regeneration if an active unrevoked identity already exists
    if (m_registration != nullptr) {
        uint8_t existingComm[32];
        ffi_registration_commitment(m_registration, existingComm);
        bool revoked = (m_blacklist && ffi_blacklist_is_revoked(m_blacklist, existingComm) == 1);
        if (!revoked) {
            return makeErrorJson("Active identity already exists. Regeneration is prohibited unless revoked by slashing.");
        }
    }

    if (m_registration) {
        ffi_registration_free(m_registration);
        m_registration = nullptr;
    }
    if (m_member) {
        ffi_member_free(m_member);
        m_member = nullptr;
    }

    if (nskHex.empty()) {
        m_registration = ffi_registration_new();
    } else {
        std::vector<uint8_t> bytes = hexToBytes(nskHex);
        if (bytes.size() != 32) {
            return makeErrorJson("NSK must be exactly 32 bytes (64 hex characters)");
        }
        m_registration = ffi_registration_from_nsk(bytes.data());
    }

    if (!m_registration) {
        return makeErrorJson("Failed to initialize RegistrationClient");
    }

    uint8_t comm[32];
    ffi_registration_commitment(m_registration, comm);
    uint8_t nsk[32];
    ffi_registration_nsk(m_registration, nsk);

    m_staked = true;
    m_stakeAmount = 0;
    m_onchainSynced = true;

    std::string commHex = bytesToHex(comm, 32);
    savePersistedIdentity();

    if (!m_cachedUsername.empty()) {
        if (m_usernameRegistry && !m_cachedUsername.empty()) {
            char* regRes = ffi_username_registry_register(m_usernameRegistry, comm, m_cachedUsername.c_str());
            if (regRes) ffi_identity_free_string(regRes);
        }
    }
    dispatchOnChainRegistration(commHex, m_cachedUsername);

    json res;
    res["commitment"] = commHex;
    res["nsk"] = bytesToHex(nsk, 32);
    res["staked"] = true;
    res["stake_amount"] = 0;
    res["onchain_synced"] = true;
    return res.dump();
}

std::string ECloakCoreImpl::getCommitment()
{
    if (!m_registration) return "";
    uint8_t comm[32];
    ffi_registration_commitment(m_registration, comm);
    return bytesToHex(comm, 32);
}

bool ECloakCoreImpl::hasActiveIdentity()
{
    return m_registration != nullptr;
}

std::string ECloakCoreImpl::getSchnorrPublicKey()
{
    if (!m_registration) return "";
    uint8_t nsk[32];
    ffi_registration_nsk(m_registration, nsk);
    FfiModeratorClient* tempClient = ffi_moderator_new(nsk);
    if (!tempClient) return "";
    uint8_t pub[32];
    ffi_moderator_public_key(tempClient, pub);
    ffi_moderator_free(tempClient);
    return bytesToHex(pub, 32);
}

std::string ECloakCoreImpl::prepareRegistration(const std::string& username,
                                                    uint64_t kSssThreshold,
                                                    const std::string& nodePubkeysJson)
{
    if (!m_registration) return makeErrorJson("identity not initialized — generate or restore identity first");
    if (username.empty()) return makeErrorJson("username cannot be empty");

    uint8_t comm[32];
    ffi_registration_commitment(m_registration, comm);
    if (m_blacklist && ffi_blacklist_is_revoked(m_blacklist, comm) == 1) {
        return makeErrorJson("identity has been revoked — cannot prepare registration");
    }

    try {
        json j = json::parse(nodePubkeysJson);
        if (!j.is_array()) return makeErrorJson("node pubkeys must be a JSON array");
        if (j.empty()) return makeErrorJson("at least one node pubkey is required");
        if (kSssThreshold == 0 || kSssThreshold > j.size()) {
            return makeErrorJson("invalid threshold: must be between 1 and total nodes");
        }

        std::vector<uint8_t> flatPubkeys;
        for (const auto& item : j) {
            std::string keyHex = item.get<std::string>();
            std::vector<uint8_t> keyBytes = hexToBytes(keyHex);
            if (keyBytes.size() != 32) return makeErrorJson("each node pubkey must be 32 bytes");
            flatPubkeys.insert(flatPubkeys.end(), keyBytes.begin(), keyBytes.end());
        }

        uint32_t nodeCount = static_cast<uint32_t>(j.size());
        char* rawJson = ffi_registration_prepare(
            m_registration,
            username.c_str(),
            flatPubkeys.data(),
            nodeCount,
            static_cast<uint32_t>(kSssThreshold)
        );

        if (!rawJson) return makeErrorJson("failed to prepare registration");
        std::string out(rawJson);
        ffi_identity_free_string(rawJson);
        return out;
    } catch (const std::exception& e) {
        return makeErrorJson(e.what());
    }
}

void ECloakCoreImpl::syncRegisteredUsersFromFile()
{
    try {
        std::string path = getRegisteredUsersFilePath();
        if (!std::filesystem::exists(path)) return;
        std::ifstream file(path);
        if (!file.is_open()) return;
        json j;
        file >> j;
        if (!j.is_array()) return;
        for (const auto& item : j) {
            if (item.contains("commitment") && item.contains("username")) {
                std::string cHex = item["commitment"].get<std::string>();
                std::string uName = item["username"].get<std::string>();
                if (cHex.length() == 64 && !uName.empty() && m_usernameRegistry) {
                    std::vector<uint8_t> comm = hexToBytes(cHex);
                    if (comm.size() == 32) {
                        char* r = ffi_username_registry_register(m_usernameRegistry, comm.data(), uName.c_str());
                        if (r) ffi_identity_free_string(r);
                    }
                }
            }
        }
    } catch (...) {}
}

void ECloakCoreImpl::persistRegisteredUser(const std::string& commitmentHex, const std::string& username)
{
    if (commitmentHex.empty() || username.empty()) return;
    try {
        std::string path = getRegisteredUsersFilePath();
        json arr = json::array();
        if (std::filesystem::exists(path)) {
            std::ifstream file(path);
            if (file.is_open()) {
                try { file >> arr; } catch (...) { arr = json::array(); }
            }
        }
        if (!arr.is_array()) arr = json::array();

        bool found = false;
        for (auto& item : arr) {
            if (item.contains("commitment") && item["commitment"].get<std::string>() == commitmentHex) {
                item["username"] = username;
                found = true;
                break;
            }
        }
        if (!found) {
            json item;
            item["commitment"] = commitmentHex;
            item["username"] = username;
            arr.push_back(item);
        }

        std::ofstream out(path);
        if (out.is_open()) {
            out << arr.dump(2);
        }
    } catch (...) {}
}

void ECloakCoreImpl::dispatchOnChainRegistration(const std::string& commitmentHex, const std::string& username)
{
    if (commitmentHex.empty()) return;
    m_onchainSynced = true;

    // Persist immediately to registered users registry
    persistRegisteredUser(commitmentHex, username);

    // Launch background thread to execute headless transaction submission via e_cloak_dispatcher
    std::thread([this, commitmentHex, username]() {
        try {
            std::string logFile = getModuleDataDir() + "/onchain_tx.log";
            std::string dispatcherBin = "/home/namauser/logos-ecosystem/project/e-identity-stack/tools/dispatcher/target/release/e_cloak_dispatcher";

            std::string cmd = "export LEE_WALLET_HOME_DIR=/home/namauser/.lee/wallet; " +
                dispatcherBin + " register-username " +
                "--username \"" + username + "\" " +
                "--commitment \"" + commitmentHex + "\" >> " + logFile + " 2>&1";
            system(cmd.c_str());
        } catch (...) {}
    }).detach();
}

std::string ECloakCoreImpl::registerUsername(const std::string& username)
{
    if (!m_registration) return makeErrorJson("identity not initialized — generate or restore identity first");
    if (!m_usernameRegistry) return makeErrorJson("username registry not initialized");
    if (username.empty()) return makeErrorJson("username cannot be empty");
    if (username.length() < 3 || username.length() > 32) {
        return makeErrorJson("Username must be between 3 and 32 characters");
    }
    for (char c : username) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' ) {
            return makeErrorJson("Username can only contain alphanumeric characters and underscores");
        }
    }

    uint8_t comm[32];
    ffi_registration_commitment(m_registration, comm);
    std::string myCommHex = bytesToHex(comm, 32);

    if (m_blacklist && ffi_blacklist_is_revoked(m_blacklist, comm) == 1) {
        return makeErrorJson("identity has been revoked — cannot register username");
    }

    syncRegisteredUsersFromFile();

    // Check case-insensitive uniqueness across existing registered users
    try {
        std::string path = getRegisteredUsersFilePath();
        if (std::filesystem::exists(path)) {
            std::ifstream file(path);
            if (file.is_open()) {
                json fileArr;
                file >> fileArr;
                if (fileArr.is_array()) {
                    for (const auto& item : fileArr) {
                        if (item.contains("username") && item.contains("commitment")) {
                            std::string existingUser = item["username"].get<std::string>();
                            std::string existingComm = item["commitment"].get<std::string>();
                            std::string u1 = username;
                            std::string u2 = existingUser;
                            std::transform(u1.begin(), u1.end(), u1.begin(), ::tolower);
                            std::transform(u2.begin(), u2.end(), u2.begin(), ::tolower);
                            if (u1 == u2 && existingComm != myCommHex) {
                                return makeErrorJson("Username already taken");
                            }
                        }
                    }
                }
            }
        }
    } catch (...) {}

    char* regRes = ffi_username_registry_register(m_usernameRegistry, comm, username.c_str());
    if (regRes) {
        std::string resStr(regRes);
        ffi_identity_free_string(regRes);
        if (resStr.find("error") != std::string::npos && resStr.find("already taken") != std::string::npos) {
            char* existing = ffi_username_registry_lookup_by_username(m_usernameRegistry, username.c_str());
            if (existing) {
                std::string existRaw(existing);
                ffi_identity_free_string(existing);
                std::string existHex = existRaw;
                try {
                    auto j = json::parse(existRaw);
                    if (j.contains("commitment") && j["commitment"].is_string()) {
                        existHex = j["commitment"].get<std::string>();
                    }
                } catch (...) {}
                if (existHex != myCommHex) {
                    return makeErrorJson("Username already taken");
                }
            }
        }
    }

    persistRegisteredUser(myCommHex, username);
    m_cachedUsername = username;
    savePersistedIdentity();

    // Broadcast user registration over logos-delivery
    try {
        json announcement;
        announcement["type"] = "USER_REGISTRATION";
        announcement["username"] = username;
        announcement["commitment"] = myCommHex;
        announcement["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        std::string payload = announcement.dump();
        std::string b64 = base64Encode(reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
        publishDeliveryMessage("/e-identity/1/global-registry/proto", b64);
    } catch (...) {}

    // Headless Auto-Dispatch to On-Chain Sequencer in background
    dispatchOnChainRegistration(myCommHex, username);

    json res;
    res["ok"] = true;
    res["username"] = username;
    res["commitment"] = myCommHex;
    res["onchain_synced"] = true;
    return res.dump();
}

std::string ECloakCoreImpl::lookupUsername(const std::string& commitmentHex)
{
    if (commitmentHex.length() < 32) return "";
    syncRegisteredUsersFromFile();
    if (m_usernameRegistry) {
        std::vector<uint8_t> comm = hexToBytes(commitmentHex);
        if (comm.size() == 32) {
            char* name = ffi_username_registry_lookup_by_commitment(m_usernameRegistry, comm.data());
            if (name) {
                std::string out(name);
                ffi_identity_free_string(name);
                try {
                    auto j = json::parse(out);
                    if (j.contains("username") && !j["username"].is_null()) {
                        return j["username"].get<std::string>();
                    }
                } catch (...) {}
            }
        }
    }

    // Check registered_users.json
    try {
        std::string path = getRegisteredUsersFilePath();
        if (std::filesystem::exists(path)) {
            std::ifstream file(path);
            if (file.is_open()) {
                json fileArr;
                file >> fileArr;
                if (fileArr.is_array()) {
                    for (const auto& item : fileArr) {
                        if (item.contains("commitment") && item["commitment"].get<std::string>() == commitmentHex) {
                            return item["username"].get<std::string>();
                        }
                    }
                }
            }
        }
    } catch (...) {}

    return "";
}

std::string ECloakCoreImpl::lookupCommitment(const std::string& username)
{
    if (username.empty()) {
        return makeErrorJson("User not found in registry");
    }
    syncRegisteredUsersFromFile();
    if (m_usernameRegistry) {
        char* commHex = ffi_username_registry_lookup_by_username(m_usernameRegistry, username.c_str());
        if (commHex) {
            std::string rawJson(commHex);
            ffi_identity_free_string(commHex);
            std::string actualCommHex = rawJson;
            try {
                auto j = json::parse(rawJson);
                if (j.contains("commitment") && j["commitment"].is_string()) {
                    actualCommHex = j["commitment"].get<std::string>();
                }
            } catch (...) {}
            if (!actualCommHex.empty()) {
                json res;
                res["ok"] = true;
                res["username"] = username;
                res["commitment"] = actualCommHex;
                return res.dump();
            }
        }
    }

    // Check registered_users.json
    try {
        std::string path = getRegisteredUsersFilePath();
        if (std::filesystem::exists(path)) {
            std::ifstream file(path);
            if (file.is_open()) {
                json fileArr;
                file >> fileArr;
                if (fileArr.is_array()) {
                    for (const auto& item : fileArr) {
                        if (item.contains("username") && item["username"].get<std::string>() == username) {
                            std::string cHex = item["commitment"].get<std::string>();
                            json res;
                            res["ok"] = true;
                            res["username"] = username;
                            res["commitment"] = cHex;
                            return res.dump();
                        }
                    }
                }
            }
        }
    } catch (...) {}

    return makeErrorJson("User not found in registry");
}

std::string ECloakCoreImpl::getRegisteredUsersList()
{
    syncRegisteredUsersFromFile();
    json arr = json::array();
    std::unordered_map<std::string, std::string> seen;

    // 1. Current user
    if (m_registration && !m_cachedUsername.empty()) {
        uint8_t comm[32];
        ffi_registration_commitment(m_registration, comm);
        std::string myCommHex = bytesToHex(comm, 32);
        json item;
        item["commitment"] = myCommHex;
        item["username"] = m_cachedUsername;
        arr.push_back(item);
        seen[myCommHex] = m_cachedUsername;
    }

    // 2. Load all from persisted registry
    try {
        std::string path = getRegisteredUsersFilePath();
        if (std::filesystem::exists(path)) {
            std::ifstream file(path);
            if (file.is_open()) {
                json fileArr;
                file >> fileArr;
                if (fileArr.is_array()) {
                    for (const auto& item : fileArr) {
                        if (item.contains("commitment") && item.contains("username")) {
                            std::string cHex = item["commitment"].get<std::string>();
                            std::string uName = item["username"].get<std::string>();
                            if (seen.find(cHex) == seen.end()) {
                                seen[cHex] = uName;
                                json entry;
                                entry["commitment"] = cHex;
                                entry["username"] = uName;
                                arr.push_back(entry);
                            }
                        }
                    }
                }
            }
        }
    } catch (...) {}

    return arr.dump();
}

// ---------------------------------------------------------------------------
// Room Operations
// ---------------------------------------------------------------------------

std::string ECloakCoreImpl::createRoom(const std::string& adminCommitmentHex,
                                           uint64_t nThreshold,
                                           uint64_t mTotal,
                                           const std::string& moderatorPubkeysJson,
                                           uint64_t creationIndex,
                                           uint64_t minMembersForMaturity)
{
    if (!m_registration) {
        return makeErrorJson("identity not initialized — generate or restore identity first");
    }

    uint8_t localComm[32];
    ffi_registration_commitment(m_registration, localComm);
    std::string localCommHex = bytesToHex(localComm, 32);

    std::string effectiveAdminHex = adminCommitmentHex.empty() ? localCommHex : adminCommitmentHex;
    if (effectiveAdminHex != localCommHex) {
        return makeErrorJson("admin commitment does not match active identity");
    }

    std::vector<uint8_t> adminComm = hexToBytes(effectiveAdminHex);
    if (adminComm.size() != 32) {
        return makeErrorJson("admin commitment must be 32 bytes");
    }

    if (m_blacklist && ffi_blacklist_is_revoked(m_blacklist, adminComm.data()) == 1) {
        return makeErrorJson("identity has been revoked — cannot create room");
    }

    if (!m_roomRegistry) return makeErrorJson("room registry not initialized");

    if (nThreshold == 0 || mTotal == 0) {
        return makeErrorJson("threshold and total moderators must be greater than zero");
    }
    if (nThreshold > mTotal) {
        return makeErrorJson("threshold (N) cannot exceed total moderators (M)");
    }

    try {
        json j = json::parse(moderatorPubkeysJson);
        if (!j.is_array()) return makeErrorJson("moderator pubkeys must be a JSON array");
        if (j.size() != mTotal) return makeErrorJson("moderator pubkeys count must match mTotal");

        std::vector<uint8_t> flatPubkeys;
        for (const auto& item : j) {
            if (!item.is_string()) return makeErrorJson("moderator pubkey must be a hex string");
            std::vector<uint8_t> keyBytes = hexToBytes(item.get<std::string>());
            if (keyBytes.size() != 32) return makeErrorJson("each moderator pubkey must be 32 bytes");
            flatPubkeys.insert(flatPubkeys.end(), keyBytes.begin(), keyBytes.end());
        }

        char* res = ffi_room_registry_create_room(
            m_roomRegistry,
            adminComm.data(),
            static_cast<uint32_t>(nThreshold),
            static_cast<uint32_t>(mTotal),
            flatPubkeys.data(),
            creationIndex,
            static_cast<uint32_t>(minMembersForMaturity)
        );

        if (!res) return makeErrorJson("failed to create room");
        std::string out(res);
        ffi_identity_free_string(res);
        return out;
    } catch (const std::exception& e) {
        return makeErrorJson(e.what());
    }
}

std::string ECloakCoreImpl::signRoomConsent(const std::string& roomIdHex)
{
    if (!m_registration) return makeErrorJson("identity not initialized — generate or restore identity first");

    std::vector<uint8_t> roomId = hexToBytes(roomIdHex);
    if (roomId.size() != 32) return makeErrorJson("room ID must be 32 bytes");

    uint8_t comm[32];
    ffi_registration_commitment(m_registration, comm);
    uint8_t nsk[32];
    ffi_registration_nsk(m_registration, nsk);

    char* res = ffi_room_sign_join_consent(roomId.data(), comm, nsk);
    if (!res) return makeErrorJson("failed to sign join consent");
    std::string out(res);
    ffi_identity_free_string(res);
    return out;
}

std::string ECloakCoreImpl::joinRoom(const std::string& roomIdHex,
                                         const std::string& memberCommitmentHex,
                                         const std::string& memberPubkeyHex,
                                         const std::string& consentSignatureHex,
                                         uint64_t joinIndex)
{
    if (!m_registration) return makeErrorJson("identity not initialized — generate or restore identity first");

    uint8_t localComm[32];
    ffi_registration_commitment(m_registration, localComm);
    std::string localCommHex = bytesToHex(localComm, 32);

    std::string effectiveCommHex = memberCommitmentHex.empty() ? localCommHex : memberCommitmentHex;
    if (effectiveCommHex != localCommHex) {
        return makeErrorJson("member commitment does not match active identity");
    }

    std::vector<uint8_t> comm = hexToBytes(effectiveCommHex);
    if (comm.size() != 32) return makeErrorJson("member commitment must be 32 bytes");

    if (m_blacklist && ffi_blacklist_is_revoked(m_blacklist, comm.data()) == 1) {
        return makeErrorJson("identity has been revoked — cannot join room");
    }

    if (!m_roomRegistry) return makeErrorJson("room registry not initialized");

    std::vector<uint8_t> roomId = hexToBytes(roomIdHex);
    if (roomId.size() != 32) return makeErrorJson("room ID must be 32 bytes");

    uint8_t nsk[32];
    ffi_registration_nsk(m_registration, nsk);

    std::vector<uint8_t> pubkey;
    if (memberPubkeyHex.empty() || memberPubkeyHex == memberCommitmentHex) {
        FfiModeratorClient* tempClient = ffi_moderator_new(nsk);
        if (tempClient) {
            uint8_t derivedPub[32];
            ffi_moderator_public_key(tempClient, derivedPub);
            ffi_moderator_free(tempClient);
            pubkey.assign(derivedPub, derivedPub + 32);
        } else {
            pubkey = hexToBytes(memberPubkeyHex);
        }
    } else {
        pubkey = hexToBytes(memberPubkeyHex);
    }

    if (pubkey.size() != 32) return makeErrorJson("member pubkey must be 32 bytes");

    std::vector<uint8_t> sigBytes = hexToBytes(consentSignatureHex);
    bool isPlaceholderSig = (sigBytes.size() != 64);
    if (!isPlaceholderSig) {
        bool allZero = true;
        for (uint8_t b : sigBytes) {
            if (b != 0) { allZero = false; break; }
        }
        if (allZero) isPlaceholderSig = true;
    }

    if (isPlaceholderSig) {
        char* signRes = ffi_room_sign_join_consent(roomId.data(), comm.data(), nsk);
        if (signRes) {
            try {
                json sj = json::parse(signRes);
                if (sj.contains("ok") && sj["ok"].contains("signature")) {
                    std::string autoSigHex = sj["ok"]["signature"].get<std::string>();
                    sigBytes = hexToBytes(autoSigHex);
                }
            } catch (...) {}
            ffi_identity_free_string(signRes);
        }
    }

    if (sigBytes.size() != 64) {
        return makeErrorJson("consent signature must be 64 bytes");
    }

    char* res = ffi_room_registry_join_room(
        m_roomRegistry,
        roomId.data(),
        comm.data(),
        pubkey.data(),
        sigBytes.data(),
        joinIndex
    );

    if (!res) return makeErrorJson("failed to join room");
    std::string out(res);
    ffi_identity_free_string(res);
    return out;
}

std::string ECloakCoreImpl::leaveRoom(const std::string& roomIdHex, const std::string& memberCommitmentHex)
{
    if (!m_registration) return makeErrorJson("identity not initialized — generate or restore identity first");

    uint8_t localComm[32];
    ffi_registration_commitment(m_registration, localComm);
    std::string localCommHex = bytesToHex(localComm, 32);

    std::string effectiveCommHex = memberCommitmentHex.empty() ? localCommHex : memberCommitmentHex;
    if (effectiveCommHex != localCommHex) {
        return makeErrorJson("member commitment does not match active identity");
    }

    if (!m_roomRegistry) return makeErrorJson("room registry not initialized");
    std::vector<uint8_t> roomId = hexToBytes(roomIdHex);
    if (roomId.size() != 32) return makeErrorJson("room ID must be 32 bytes");
    std::vector<uint8_t> comm = hexToBytes(effectiveCommHex);
    if (comm.size() != 32) return makeErrorJson("member commitment must be 32 bytes");

    char* res = ffi_room_registry_leave_room(
        m_roomRegistry,
        roomId.data(),
        comm.data()
    );

    if (!res) return makeErrorJson("failed to leave room");
    std::string out(res);
    ffi_identity_free_string(res);
    return out;
}

int64_t ECloakCoreImpl::getRoomMemberCount(const std::string& roomIdHex)
{
    if (!m_roomRegistry) return 0;
    std::vector<uint8_t> roomId = hexToBytes(roomIdHex);
    if (roomId.size() != 32) return 0;
    return static_cast<int64_t>(ffi_room_registry_active_member_count(m_roomRegistry, roomId.data()));
}

bool ECloakCoreImpl::isRoomMember(const std::string& roomIdHex, const std::string& memberCommitmentHex)
{
    if (!m_roomRegistry) return false;
    std::vector<uint8_t> roomId = hexToBytes(roomIdHex);
    std::vector<uint8_t> comm = hexToBytes(memberCommitmentHex);
    if (roomId.size() != 32 || comm.size() != 32) return false;
    return ffi_room_registry_has_active_membership(m_roomRegistry, roomId.data(), comm.data()) == 1;
}

// ---------------------------------------------------------------------------
// Chat & Messaging Operations (Two-Tier SSS)
// ---------------------------------------------------------------------------

std::string ECloakCoreImpl::preparePost(const std::string& message,
                                            const std::string& postSaltHex,
                                            const std::string& moderatorPubkeysJson,
                                            int64_t nThreshold)
{
    if (!m_registration) return makeErrorJson("identity not initialized — generate or restore identity first");

    uint8_t comm[32];
    ffi_registration_commitment(m_registration, comm);

    if (m_blacklist && ffi_blacklist_is_revoked(m_blacklist, comm) == 1) {
        return makeErrorJson("identity has been revoked — cannot post messages");
    }

    if (message.empty()) {
        return makeErrorJson("message cannot be empty");
    }

    uint8_t nsk[32];
    ffi_registration_nsk(m_registration, nsk);

    if (!m_member) {
        m_member = ffi_member_new(nsk, 3); // default k_strikes = 3
    }
    if (!m_member) {
        return makeErrorJson("failed to initialize member client");
    }

    std::vector<uint8_t> salt = hexToBytes(postSaltHex);
    if (salt.size() != 32) return makeErrorJson("post salt must be 32 bytes");

    try {
        json j = json::parse(moderatorPubkeysJson);
        if (!j.is_array()) return makeErrorJson("moderator pubkeys must be a JSON array");
        if (j.empty()) return makeErrorJson("at least one moderator pubkey is required");
        if (nThreshold <= 0 || static_cast<size_t>(nThreshold) > j.size()) {
            return makeErrorJson("invalid threshold: must be between 1 and total moderators");
        }

        std::vector<uint8_t> flatKeys;
        for (const auto& val : j) {
            std::vector<uint8_t> key = hexToBytes(val.get<std::string>());
            if (key.size() != 32) return makeErrorJson("each pubkey must be 32 bytes");
            flatKeys.insert(flatKeys.end(), key.begin(), key.end());
        }

        char* res = ffi_member_prepare_post(
            m_member,
            reinterpret_cast<const uint8_t*>(message.data()),
            static_cast<uint32_t>(message.size()),
            salt.data(),
            flatKeys.data(),
            static_cast<uint32_t>(j.size()),
            static_cast<uint32_t>(nThreshold)
        );

        if (!res) return makeErrorJson("failed to prepare post");
        std::string out(res);
        ffi_free_string(res);

        try {
            json postJ = json::parse(out);
            if (postJ.contains("tracing_tag") && postJ["tracing_tag"].is_array()) {
                std::vector<uint8_t> tagBytes = postJ["tracing_tag"].get<std::vector<uint8_t>>();
                postJ["tracing_tag"] = bytesToHex(tagBytes.data(), tagBytes.size());
                return postJ.dump();
            }
        } catch (...) {}

        return out;
    } catch (const std::exception& e) {
        return makeErrorJson(e.what());
    }
}

// ---------------------------------------------------------------------------
// Moderation Operations
// ---------------------------------------------------------------------------

std::string ECloakCoreImpl::createModerator(const std::string& privkeyHex)
{
    if (m_moderator) { ffi_moderator_free(m_moderator); m_moderator = nullptr; }
    std::vector<uint8_t> priv = hexToBytes(privkeyHex);
    if (priv.size() != 32) return makeErrorJson("privkey must be 32 bytes");

    m_moderator = ffi_moderator_new(priv.data());
    if (!m_moderator) return makeErrorJson("failed to create moderator");

    json j;
    j["ok"] = true;
    return j.dump();
}

std::string ECloakCoreImpl::getModeratorPubkey()
{
    if (!m_moderator) return "";
    uint8_t pub[32];
    ffi_moderator_public_key(m_moderator, pub);
    return bytesToHex(pub, 32);
}

std::string ECloakCoreImpl::issueStrike(const std::string& /*roomIdHex*/,
                                            const std::string& /*targetCommitmentHex*/,
                                            const std::string& /*evidenceHashHex*/,
                                            const std::string& tracingTagHex,
                                            const std::string& encryptedShareJson,
                                            int64_t moderatorIndex)
{
    if (!m_moderator) return makeErrorJson("moderator not initialized");
    std::vector<uint8_t> tag = hexToBytes(tracingTagHex);
    if (tag.size() != 32) return makeErrorJson("tracing tag must be 32 bytes");

    char* res = ffi_moderator_issue_strike(
        m_moderator,
        tag.data(),
        encryptedShareJson.c_str(),
        static_cast<uint32_t>(moderatorIndex)
    );

    if (!res) return makeErrorJson("failed to issue strike");
    std::string out(res);
    ffi_free_string(res);
    return out;
}

std::string ECloakCoreImpl::validateStrike(const std::string& certificateJson, int64_t nThreshold)
{
    if (!m_moderatorRegistry) return makeErrorJson("moderator registry not initialized");
    char* res = ffi_strike_validate(certificateJson.c_str(), static_cast<uint32_t>(nThreshold), m_moderatorRegistry);
    if (!res) return makeErrorJson("failed to validate strike");
    std::string out(res);
    ffi_identity_free_string(res);
    return out;
}

// ---------------------------------------------------------------------------
// Slashing & Reconstruction
// ---------------------------------------------------------------------------

std::string ECloakCoreImpl::createAggregator(int64_t nThreshold, int64_t kStrikes, const std::string& moderatorPubkeysJson)
{
    if (m_aggregator) { ffi_aggregator_free(m_aggregator); m_aggregator = nullptr; }

    try {
        json j = json::parse(moderatorPubkeysJson);
        std::vector<uint8_t> flatKeys;
        for (const auto& val : j) {
            std::vector<uint8_t> key = hexToBytes(val.get<std::string>());
            flatKeys.insert(flatKeys.end(), key.begin(), key.end());
        }

        m_aggregator = ffi_aggregator_new(
            static_cast<uint32_t>(nThreshold),
            static_cast<uint32_t>(kStrikes),
            flatKeys.data(),
            static_cast<uint32_t>(j.size())
        );

        if (!m_aggregator) return makeErrorJson("failed to create aggregator");
        json res;
        res["ok"] = true;
        return res.dump();
    } catch (const std::exception& e) {
        return makeErrorJson(e.what());
    }
}

std::string ECloakCoreImpl::reconstructStrike(const std::string& tracingTagHex, const std::string& certificatesJson)
{
    if (!m_aggregator) return makeErrorJson("aggregator not initialized");
    std::vector<uint8_t> tag = hexToBytes(tracingTagHex);
    char* res = ffi_aggregator_reconstruct_strike(
        m_aggregator,
        tag.data(),
        certificatesJson.c_str()
    );
    if (!res) return makeErrorJson("failed to reconstruct strike");
    std::string out(res);
    ffi_free_string(res);
    return out;
}

std::string ECloakCoreImpl::reconstructNsk(const std::string& strikesJson)
{
    if (!m_aggregator) return makeErrorJson("aggregator not initialized");
    char* res = ffi_aggregator_reconstruct_nsk(m_aggregator, strikesJson.c_str());
    if (!res) return makeErrorJson("failed to reconstruct NSK");
    std::string out(res);
    ffi_free_string(res);
    return out;
}

bool ECloakCoreImpl::isRevoked(const std::string& commitmentHex)
{
    if (!m_blacklist) return false;
    std::vector<uint8_t> comm = hexToBytes(commitmentHex);
    if (comm.size() != 32) return false;
    return ffi_blacklist_is_revoked(m_blacklist, comm.data()) == 1;
}

std::string ECloakCoreImpl::revokeCommitment(const std::string& commitmentHex)
{
    if (!m_blacklist) return makeErrorJson("blacklist not initialized");
    std::vector<uint8_t> comm = hexToBytes(commitmentHex);
    if (comm.size() != 32) return makeErrorJson("commitment must be 32 bytes");
    char* res = ffi_blacklist_revoke(m_blacklist, comm.data());
    if (!res) return makeErrorJson("failed to revoke commitment");
    std::string out(res);
    ffi_identity_free_string(res);
    return out;
}


// ---------------------------------------------------------------------------
// Persistent Chat Store Operations (AES-256-GCM + Zstd) & Blob Storage
// ---------------------------------------------------------------------------

std::vector<uint8_t> ECloakCoreImpl::getStorageKey()
{
    loadPersistedIdentity();
    if (m_registration) {
        uint8_t nsk[32];
        ffi_registration_nsk(m_registration, nsk);
        return deriveStorageKey(nsk, 32);
    }
    static const uint8_t fallbackSeed[32] = {
        0x65, 0x43, 0x6c, 0x6f, 0x61, 0x6b, 0x53, 0x74,
        0x6f, 0x72, 0x61, 0x67, 0x65, 0x53, 0x65, 0x65,
        0x64, 0x5f, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c,
        0x74, 0x5f, 0x56, 0x31, 0x30, 0x30, 0x21, 0x23
    };
    return deriveStorageKey(fallbackSeed, 32);
}

std::string ECloakCoreImpl::saveBlob(const std::string& base64Data,
                                         const std::string& fileName,
                                         const std::string& mimeType)
{
    try {
        if (base64Data.empty()) {
            return makeErrorJson("Blob payload cannot be empty");
        }
        std::vector<uint8_t> raw = base64Decode(base64Data);
        if (raw.empty()) {
            return makeErrorJson("Failed to decode base64 blob data");
        }

        std::string blobId = computeSha256Hex(raw.data(), raw.size());
        std::string blobsDir = getBlobsDir();
        std::string targetPath = blobsDir + "/" + blobId;

        // Content-addressed: only write if not already stored
        if (!std::filesystem::exists(targetPath)) {
            std::string tmpPath = targetPath + ".tmp";
            {
                std::ofstream out(tmpPath, std::ios::binary);
                if (!out.is_open()) {
                    return makeErrorJson("Failed to open temporary file for blob");
                }
                out.write(reinterpret_cast<const char*>(raw.data()), raw.size());
            }
            std::error_code ec;
            std::filesystem::rename(tmpPath, targetPath, ec);
            if (ec) {
                std::filesystem::copy_file(tmpPath, targetPath, std::filesystem::copy_options::overwrite_existing, ec);
                std::filesystem::remove(tmpPath, ec);
            }
        }

        json res;
        res["ok"] = true;
        res["blobId"] = blobId;
        res["fileName"] = fileName;
        res["fileSize"] = raw.size();
        res["mimeType"] = mimeType;
        res["localPath"] = targetPath;
        return res.dump();
    } catch (const std::exception& e) {
        return makeErrorJson(std::string("Error saving blob: ") + e.what());
    }
}

std::string ECloakCoreImpl::loadBlob(const std::string& blobId)
{
    try {
        if (blobId.empty()) return "";
        std::string targetPath = getBlobsDir() + "/" + blobId;
        if (!std::filesystem::exists(targetPath)) {
            return "";
        }
        std::ifstream in(targetPath, std::ios::binary | std::ios::ate);
        if (!in.is_open()) return "";
        std::streamsize size = in.tellg();
        in.seekg(0, std::ios::beg);
        std::vector<uint8_t> buffer(size);
        if (!in.read(reinterpret_cast<char*>(buffer.data()), size)) {
            return "";
        }
        return base64Encode(buffer.data(), buffer.size());
    } catch (...) {
        return "";
    }
}

std::string ECloakCoreImpl::getBlobPath(const std::string& blobId)
{
    if (blobId.empty()) return "";
    return getBlobsDir() + "/" + blobId;
}

std::string ECloakCoreImpl::saveChatStore(const std::string& chatStoreJson)
{
    try {
        // Validate valid JSON
        auto parsed = json::parse(chatStoreJson);
        std::string serialized = parsed.dump();

        // 1. Zstd Compression
        std::vector<uint8_t> compressed = compressZstd(serialized);

        // 2. Derive Encryption Key
        std::vector<uint8_t> key = getStorageKey();

        // 3. AES-256-GCM Authenticated Encryption
        std::vector<uint8_t> encrypted = encryptAes256Gcm(key, compressed);

        // 4. Atomic file write
        std::string encPath = getScopedChatStoreEncFilePath();
        std::string tmpPath = encPath + ".tmp";
        {
            std::ofstream file(tmpPath, std::ios::binary);
            if (!file.is_open()) {
                return makeErrorJson("Failed to open temporary file for writing encrypted chat store");
            }
            file.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        }
        std::error_code ec;
        std::filesystem::rename(tmpPath, encPath, ec);
        if (ec) {
            std::filesystem::copy_file(tmpPath, encPath, std::filesystem::copy_options::overwrite_existing, ec);
            std::filesystem::remove(tmpPath, ec);
        }

        // Clean up legacy unencrypted chat_store.json if present
        std::string legacyPath = getChatStoreFilePath();
        if (std::filesystem::exists(legacyPath)) {
            std::filesystem::remove(legacyPath, ec);
        }

        json res;
        res["ok"] = true;
        res["encrypted"] = true;
        res["compressed"] = true;
        res["storedBytes"] = encrypted.size();
        return res.dump();
    } catch (const std::exception& e) {
        return makeErrorJson(std::string("Error saving chat store: ") + e.what());
    }
}

std::string ECloakCoreImpl::loadChatStore()
{
    try {
        std::string encPath = getScopedChatStoreEncFilePath();
        if (std::filesystem::exists(encPath)) {
            std::ifstream file(encPath, std::ios::binary | std::ios::ate);
            if (file.is_open()) {
                std::streamsize size = file.tellg();
                file.seekg(0, std::ios::beg);
                std::vector<uint8_t> encData(size);
                if (file.read(reinterpret_cast<char*>(encData.data()), size)) {
                    std::vector<uint8_t> key = getStorageKey();
                    std::vector<uint8_t> compressed = decryptAes256Gcm(key, encData);
                    std::string jsonStr = decompressZstd(compressed.data(), compressed.size());
                    auto j = json::parse(jsonStr);
                    return j.dump();
                }
            }
        }

        // Backward compatibility fallback to unencrypted chat_store.json
        std::string legacyPath = getChatStoreFilePath();
        if (std::filesystem::exists(legacyPath)) {
            std::ifstream file(legacyPath);
            if (file.is_open()) {
                json j;
                file >> j;
                return j.dump();
            }
        }

        return "{}";
    } catch (...) {
        return "{}";
    }
}

std::string ECloakCoreImpl::clearChatStore()
{
    try {
        std::error_code ec;
        std::string encPath = getScopedChatStoreEncFilePath();
        if (std::filesystem::exists(encPath)) {
            std::filesystem::remove(encPath, ec);
        }
        std::string legacyPath = getChatStoreFilePath();
        if (std::filesystem::exists(legacyPath)) {
            std::filesystem::remove(legacyPath, ec);
        }
        json res;
        res["ok"] = true;
        return res.dump();
    } catch (...) {
        return makeErrorJson("Failed to clear chat store");
    }
}


// ---------------------------------------------------------------------------
// Wallet Store & On-Chain Verification Operations
// ---------------------------------------------------------------------------

std::string ECloakCoreImpl::getLezWalletAccount()
{
    try {
        std::string homeDir;
        const char* leeHomeEnv = std::getenv("LEE_WALLET_HOME_DIR");
        if (leeHomeEnv && *leeHomeEnv) {
            homeDir = std::string(leeHomeEnv);
        } else {
            const char* home = std::getenv("HOME");
            if (home && *home) {
                homeDir = std::string(home) + "/.lee/wallet";
            }
        }
        if (!homeDir.empty()) {
            std::string storagePath = homeDir + "/storage.json";
            if (std::filesystem::exists(storagePath)) {
                std::ifstream f(storagePath);
                if (f.is_open()) {
                    json j;
                    f >> j;
                    if (j.contains("key_chain") && j["key_chain"].contains("accounts") && j["key_chain"]["accounts"].is_array()) {
                        std::string firstPublic;
                        for (const auto& acc : j["key_chain"]["accounts"]) {
                            if (acc.is_object() && acc.contains("Public") && acc["Public"].is_object()) {
                                if (acc["Public"].contains("account_id") && acc["Public"]["account_id"].is_string()) {
                                    std::string accId = acc["Public"]["account_id"].get<std::string>();
                                    if (firstPublic.empty()) {
                                        firstPublic = "Public/" + accId;
                                    }
                                    if (acc["Public"].contains("chain_index") && acc["Public"]["chain_index"].is_array()) {
                                        auto ci = acc["Public"]["chain_index"];
                                        if (ci.size() == 1 && ci[0].is_number() && ci[0].get<int>() == 0) {
                                            return "Public/" + accId;
                                        }
                                    }
                                    if (accId == "9p7BZn9g6UrVMBiatyeNtq4yv9DitxYM1ZXsjYi6vf47") {
                                        return "Public/" + accId;
                                    }
                                }
                            }
                        }
                        if (!firstPublic.empty()) {
                            return firstPublic;
                        }
                    }
                }
            }
        }
    } catch (...) {}
    return "Public/9p7BZn9g6UrVMBiatyeNtq4yv9DitxYM1ZXsjYi6vf47";
}

std::string ECloakCoreImpl::verifyOnChainCollateral(const std::string& accountId)
{
    std::string targetAcc = accountId.empty() ? getLezWalletAccount() : accountId;
    std::string rawAcc = targetAcc;
    if (rawAcc.rfind("Public/", 0) == 0) {
        rawAcc = rawAcc.substr(7);
    }

    uint64_t balance = 0;
    bool queryOk = false;

    json req;
    req["jsonrpc"] = "2.0";
    req["method"] = "getAccountBalance";
    req["params"] = json::array({ rawAcc });
    req["id"] = 1;
    std::string postData = req.dump();

    std::string cmd = "env -u LD_LIBRARY_PATH curl -s --max-time 5 -X POST https://testnet.lez.logos.co/ -H 'Content-Type: application/json' -d '" + postData + "' 2>/dev/null";

    FILE* pipe = popen(cmd.c_str(), "r");
    if (pipe) {
        char buf[256];
        std::string output;
        while (fgets(buf, sizeof(buf), pipe) != nullptr) {
            output += buf;
        }
        pclose(pipe);

        try {
            auto j = json::parse(output);
            if (j.contains("result") && j["result"].is_number()) {
                balance = j["result"].get<uint64_t>();
                queryOk = true;
            }
        } catch (...) {}
    }

    bool verified = queryOk;
    m_staked = true;
    savePersistedIdentity();

    json res;
    res["ok"] = queryOk;
    res["account_id"] = targetAcc;
    res["balance"] = balance;
    res["verified"] = verified;
    res["min_collateral"] = 0;
    res["staked"] = true;
    return res.dump();
}

std::string ECloakCoreImpl::saveWalletStore(const std::string& walletStoreJson)
{
    try {
        auto parsed = json::parse(walletStoreJson);
        std::string path = getScopedWalletStoreFilePath();
        std::ofstream file(path);
        if (!file.is_open()) {
            return makeErrorJson("Failed to open wallet store file for writing");
        }
        file << parsed.dump(2);
        json res;
        res["ok"] = true;
        return res.dump();
    } catch (const std::exception& e) {
        return makeErrorJson(std::string("Error saving wallet store: ") + e.what());
    }
}

std::string ECloakCoreImpl::loadWalletStore()
{
    try {
        std::string path = getScopedWalletStoreFilePath();
        if (std::filesystem::exists(path)) {
            std::ifstream file(path);
            if (file.is_open()) {
                json j;
                file >> j;
                return j.dump();
            }
        }
        json initial;
        initial["version"] = 1;
        initial["available"] = 0;
        initial["collateral"] = m_staked ? m_stakeAmount : 0;
        initial["burned"] = 0;
        initial["history"] = json::array();
        return initial.dump();
    } catch (...) {
        return R"({"version":1,"available":0,"collateral":0,"burned":0,"history":[]})";
    }
}

std::string ECloakCoreImpl::getWalletInfo()
{
    json res;
    res["lez_account"] = getLezWalletAccount();
    res["sequencer_url"] = "https://testnet.lez.logos.co/";
    res["min_collateral"] = 0;
    res["staked"] = true;
    res["stake_amount"] = m_stakeAmount;
    if (m_registration) {
        uint8_t comm[32];
        ffi_registration_commitment(m_registration, comm);
        res["commitment"] = bytesToHex(comm, 32);
    } else {
        res["commitment"] = "";
    }
    return res.dump();
}

std::string ECloakCoreImpl::syncOnChainCollateral(bool verified, uint64_t verifiedBalance)
{
    m_staked = true;
    savePersistedIdentity();

    json j;
    j["ok"] = true;
    j["verified"] = verified;
    j["staked"] = true;
    j["stake_amount"] = m_stakeAmount;
    j["verified_balance"] = verifiedBalance;
    return j.dump();
}

// ---------------------------------------------------------------------------
// MLS Group & 1-on-1 Chat Operations (de-MLS via e_chat_bridge)
// ---------------------------------------------------------------------------

std::string ECloakCoreImpl::createChatRoom(const std::string& roomIdHex, const std::string& username)
{
    loadPersistedIdentity();
    if (!m_registration) {
        return makeErrorJson("No active identity found. Create or load identity first.");
    }
    uint8_t comm[32];
    ffi_registration_commitment(m_registration, comm);

    auto it = m_chatSessions.find(roomIdHex);
    if (it != m_chatSessions.end() && it->second) {
        ffi_chat_session_free(it->second);
        m_chatSessions.erase(it);
    }

    std::string uname = username.empty() ? m_cachedUsername : username;
    FfiChatSession* session = ffi_chat_session_create_room(roomIdHex.c_str(), comm, uname.c_str());
    if (!session) {
        return makeErrorJson("Failed to create MLS chat room session");
    }

    // Auto-initialize Two-Tier SSS moderation with user NSK
    uint8_t nsk[32];
    ffi_registration_nsk(m_registration, nsk);
    char* modInit = ffi_chat_session_init_moderation(session, nsk, 3);
    if (modInit) {
        ffi_chat_free_string(modInit);
    }

    m_chatSessions[roomIdHex] = session;

    // Auto-subscribe to room content topics
    std::string contentTopic = "/e-identity/1/room-" + roomIdHex + "/proto";
    subscribeDeliveryTopic(contentTopic);

    json res;
    res["ok"] = true;
    res["room_id"] = roomIdHex;
    res["creator"] = uname;
    res["commitment"] = bytesToHex(comm, 32);
    return res.dump();
}

std::string ECloakCoreImpl::initChatModeration(const std::string& roomIdHex, uint64_t kStrikes)
{
    loadPersistedIdentity();
    if (!m_registration) {
        return makeErrorJson("No active identity found");
    }
    auto it = m_chatSessions.find(roomIdHex);
    if (it == m_chatSessions.end() || !it->second) {
        return makeErrorJson("Chat session not found for room: " + roomIdHex);
    }
    uint8_t nsk[32];
    ffi_registration_nsk(m_registration, nsk);
    char* res = ffi_chat_session_init_moderation(it->second, nsk, static_cast<uint32_t>(kStrikes));
    if (!res) {
        return makeErrorJson("Failed to initialize chat moderation");
    }
    std::string out(res);
    ffi_chat_free_string(res);
    return out;
}

std::string ECloakCoreImpl::createChatJoiner(const std::string& username)
{
    loadPersistedIdentity();
    if (!m_registration) {
        return makeErrorJson("No active identity found");
    }
    if (m_chatJoiner) {
        ffi_chat_joiner_free(m_chatJoiner);
        m_chatJoiner = nullptr;
    }
    uint8_t comm[32];
    ffi_registration_commitment(m_registration, comm);
    std::string uname = username.empty() ? m_cachedUsername : username;

    m_chatJoiner = ffi_chat_joiner_new(comm, uname.c_str());
    if (!m_chatJoiner) {
        return makeErrorJson("Failed to create chat joiner client");
    }

    char* kp = ffi_chat_joiner_get_key_package(m_chatJoiner);
    if (!kp) {
        return makeErrorJson("Failed to generate KeyPackage for joiner");
    }
    std::string kpStr(kp);
    ffi_chat_free_string(kp);

    std::string kpHex = kpStr;
    try {
        auto parsed = json::parse(kpStr);
        if (parsed.contains("key_package_hex")) {
            kpHex = parsed["key_package_hex"].get<std::string>();
        }
    } catch (...) {}

    json res;
    res["ok"] = true;
    res["username"] = uname;
    res["commitment"] = bytesToHex(comm, 32);
    res["key_package"] = kpHex;
    res["key_package_hex"] = kpHex;
    return res.dump();
}

std::string ECloakCoreImpl::getChatKeyPackage()
{
    if (!m_chatJoiner) {
        return makeErrorJson("No active chat joiner. Call createChatJoiner first.");
    }
    char* kp = ffi_chat_joiner_get_key_package(m_chatJoiner);
    if (!kp) {
        return makeErrorJson("Failed to get KeyPackage from joiner");
    }
    std::string kpStr(kp);
    ffi_chat_free_string(kp);

    std::string kpHex = kpStr;
    try {
        auto parsed = json::parse(kpStr);
        if (parsed.contains("key_package_hex")) {
            kpHex = parsed["key_package_hex"].get<std::string>();
        }
    } catch (...) {}

    json res;
    res["ok"] = true;
    res["key_package"] = kpHex;
    res["key_package_hex"] = kpHex;
    return res.dump();
}

std::string ECloakCoreImpl::addChatMember(const std::string& roomIdHex, const std::string& keyPackageHex)
{
    auto it = m_chatSessions.find(roomIdHex);
    if (it == m_chatSessions.end() || !it->second) {
        return makeErrorJson("Chat session not found for room: " + roomIdHex);
    }
    if (keyPackageHex.empty()) {
        return makeErrorJson("KeyPackage cannot be empty");
    }
    std::string rawHex = keyPackageHex;
    try {
        if (!rawHex.empty() && rawHex[0] == '{') {
            auto j = json::parse(rawHex);
            if (j.contains("key_package_hex")) {
                rawHex = j["key_package_hex"].get<std::string>();
            } else if (j.contains("key_package")) {
                rawHex = j["key_package"].get<std::string>();
            }
        }
    } catch (...) {}

    char* res = ffi_chat_session_add_member(it->second, rawHex.c_str());
    if (!res) {
        return makeErrorJson("Failed to add member to MLS chat session");
    }
    std::string out(res);
    ffi_chat_free_string(res);
    return out;
}

std::string ECloakCoreImpl::completeChatJoin(const std::string& roomIdHex, const std::string& welcomeHex)
{
    if (!m_chatJoiner) {
        return makeErrorJson("No active chat joiner. Call createChatJoiner first.");
    }
    if (welcomeHex.empty()) {
        return makeErrorJson("Welcome message cannot be empty");
    }
    std::string rawHex = welcomeHex;
    try {
        if (!rawHex.empty() && rawHex[0] == '{') {
            auto j = json::parse(rawHex);
            if (j.contains("welcome_hex")) {
                rawHex = j["welcome_hex"].get<std::string>();
            }
        }
    } catch (...) {}

    FfiChatSession* session = ffi_chat_joiner_complete_join(m_chatJoiner, roomIdHex.c_str(), rawHex.c_str());
    m_chatJoiner = nullptr;

    if (!session) {
        return makeErrorJson("Failed to process Welcome message and join MLS chat room");
    }

    loadPersistedIdentity();
    if (m_registration) {
        uint8_t nsk[32];
        ffi_registration_nsk(m_registration, nsk);
        char* modInit = ffi_chat_session_init_moderation(session, nsk, 3);
        if (modInit) {
            ffi_chat_free_string(modInit);
        }
    }

    auto it = m_chatSessions.find(roomIdHex);
    if (it != m_chatSessions.end() && it->second) {
        ffi_chat_session_free(it->second);
    }
    m_chatSessions[roomIdHex] = session;

    std::string contentTopic = "/e-identity/1/room-" + roomIdHex + "/proto";
    subscribeDeliveryTopic(contentTopic);

    json res;
    res["ok"] = true;
    res["room_id"] = roomIdHex;
    res["joined"] = true;
    return res.dump();
}

std::string ECloakCoreImpl::sendProtectedChatMessage(const std::string& roomIdHex, const std::string& text, const std::string& postSaltHex, const std::string& moderatorPubkeysJson, uint64_t threshold)
{
    auto it = m_chatSessions.find(roomIdHex);
    if (it == m_chatSessions.end() || !it->second) {
        return makeErrorJson("Chat session not found for room: " + roomIdHex);
    }
    if (text.empty()) {
        return makeErrorJson("Message text cannot be empty");
    }

    std::vector<uint8_t> postSalt = hexToBytes(postSaltHex);
    if (postSalt.size() != 32) {
        postSalt.resize(32);
        if (RAND_bytes(postSalt.data(), 32) != 1) {
            return makeErrorJson("Failed to generate random post salt");
        }
    }

    std::vector<uint8_t> modPubkeys;
    uint32_t modCount = 0;
    try {
        if (!moderatorPubkeysJson.empty()) {
            auto j = json::parse(moderatorPubkeysJson);
            if (j.is_array()) {
                for (const auto& item : j) {
                    if (item.is_string()) {
                        auto pk = hexToBytes(item.get<std::string>());
                        if (pk.size() == 32) {
                            modPubkeys.insert(modPubkeys.end(), pk.begin(), pk.end());
                            modCount++;
                        }
                    }
                }
            }
        }
    } catch (...) {}

    if (modPubkeys.empty()) {
        std::string myPub = getSchnorrPublicKey();
        auto pk = hexToBytes(myPub);
        if (pk.size() == 32) {
            modPubkeys = pk;
            modCount = 1;
        } else {
            modPubkeys.resize(32, 0x01);
            modCount = 1;
        }
    }

    uint32_t effThreshold = (threshold == 0) ? 1 : static_cast<uint32_t>(threshold);
    if (effThreshold > modCount) effThreshold = modCount;

    char* res = ffi_chat_session_send_protected_message(
        it->second,
        text.c_str(),
        postSalt.data(),
        modPubkeys.data(),
        modCount,
        effThreshold
    );
    if (!res) {
        return makeErrorJson("Failed to encrypt and send protected MLS message");
    }
    std::string out(res);
    ffi_chat_free_string(res);

    try {
        auto parsed = json::parse(out);
        if (parsed.contains("ok") && parsed["ok"].is_boolean() && parsed["ok"].get<bool>() && parsed.contains("ciphertext_hex")) {
            std::string ctHex = parsed["ciphertext_hex"].get<std::string>();
            std::string contentTopic = "/e-identity/1/room-" + roomIdHex + "/proto";
            publishDeliveryMessage(contentTopic, ctHex);
        }
    } catch (...) {}

    return out;
}

std::string ECloakCoreImpl::receiveProtectedChatMessage(const std::string& roomIdHex, const std::string& ciphertextHex)
{
    auto it = m_chatSessions.find(roomIdHex);
    if (it == m_chatSessions.end() || !it->second) {
        return makeErrorJson("Chat session not found for room: " + roomIdHex);
    }
    if (ciphertextHex.empty()) {
        return makeErrorJson("Ciphertext cannot be empty");
    }
    char* res = ffi_chat_session_receive_protected_message(it->second, ciphertextHex.c_str());
    if (!res) {
        return makeErrorJson("Failed to decrypt protected MLS message");
    }
    std::string out(res);
    ffi_chat_free_string(res);
    try {
        auto j = json::parse(out);
        if (j.contains("plaintext") && !j.contains("text")) {
            j["text"] = j["plaintext"];
            return j.dump();
        }
    } catch (...) {}
    return out;
}

std::string ECloakCoreImpl::sendDirectMessage(const std::string& roomIdHex, const std::string& text)
{
    auto it = m_chatSessions.find(roomIdHex);
    if (it == m_chatSessions.end() || !it->second) {
        return makeErrorJson("Chat session not found for DM channel: " + roomIdHex);
    }
    if (text.empty()) {
        return makeErrorJson("DM text cannot be empty");
    }
    char* res = ffi_chat_session_send_dm(it->second, text.c_str());
    if (!res) {
        return makeErrorJson("Failed to encrypt MLS DM");
    }
    std::string out(res);
    ffi_chat_free_string(res);

    try {
        auto parsed = json::parse(out);
        if (parsed.contains("ok") && parsed["ok"].is_boolean() && parsed["ok"].get<bool>() && parsed.contains("ciphertext_hex")) {
            std::string ctHex = parsed["ciphertext_hex"].get<std::string>();
            std::string contentTopic = "/e-identity/1/dm-" + roomIdHex + "/proto";
            publishDeliveryMessage(contentTopic, ctHex);
        }
    } catch (...) {}

    return out;
}

std::string ECloakCoreImpl::receiveDirectMessage(const std::string& roomIdHex, const std::string& ciphertextHex)
{
    auto it = m_chatSessions.find(roomIdHex);
    if (it == m_chatSessions.end() || !it->second) {
        return makeErrorJson("Chat session not found for DM channel: " + roomIdHex);
    }
    if (ciphertextHex.empty()) {
        return makeErrorJson("DM ciphertext cannot be empty");
    }
    char* res = ffi_chat_session_receive_dm(it->second, ciphertextHex.c_str());
    if (!res) {
        return makeErrorJson("Failed to decrypt MLS DM");
    }
    std::string out(res);
    ffi_chat_free_string(res);
    try {
        auto j = json::parse(out);
        if (j.contains("plaintext") && !j.contains("text")) {
            j["text"] = j["plaintext"];
            return j.dump();
        }
    } catch (...) {}
    return out;
}

// ---------------------------------------------------------------------------
// Decentralized Transport Operations (logos-delivery / Waku)
// ---------------------------------------------------------------------------

static void* s_liblogosdeliveryHandle = nullptr;
static bool s_deliveryAttemptedLoad = false;

static void ensureDeliveryLoaded() {
    if (s_deliveryAttemptedLoad) return;
    s_deliveryAttemptedLoad = true;
    const char* paths[] = {
        "liblogosdelivery.so",
        "./lib/liblogosdelivery.so",
        "lib/liblogosdelivery.so",
        "/home/namauser/logos-ecosystem/logos-delivery/build/liblogosdelivery.so",
        nullptr
    };
    for (int i = 0; paths[i] != nullptr; ++i) {
        s_liblogosdeliveryHandle = dlopen(paths[i], RTLD_NOW | RTLD_GLOBAL);
        if (s_liblogosdeliveryHandle) break;
    }
}

std::string ECloakCoreImpl::initDelivery(const std::string& configJson)
{
    ensureDeliveryLoaded();
    m_deliveryConfig = configJson.empty() ? R"({"clusterPreset":"logos.dev","clusterId":3,"shards":[0,1,2,3,4,5,6,7]})" : configJson;
    subscribeDeliveryTopic("/e-identity/1/global-registry/proto");
    json res;
    res["ok"] = true;
    res["cluster"] = "logos.dev";
    res["dynamic_lib_loaded"] = (s_liblogosdeliveryHandle != nullptr);
    res["status"] = "initialized";
    return res.dump();
}

std::string ECloakCoreImpl::startDelivery()
{
    m_deliveryRunning = true;
    json res;
    res["ok"] = true;
    res["running"] = true;
    res["cluster"] = "logos.dev";
    res["dynamic_lib_loaded"] = (s_liblogosdeliveryHandle != nullptr);
    return res.dump();
}

std::string ECloakCoreImpl::stopDelivery()
{
    m_deliveryRunning = false;
    json res;
    res["ok"] = true;
    res["running"] = false;
    return res.dump();
}

std::string ECloakCoreImpl::getDeliveryStatus()
{
    json res;
    res["ok"] = true;
    res["running"] = m_deliveryRunning;
    res["dynamic_lib_loaded"] = (s_liblogosdeliveryHandle != nullptr);
    res["config"] = m_deliveryConfig;
    res["subscribed_topics"] = json::array();
    for (const auto& [topic, msgs] : m_deliveryMessageBuffer) {
        res["subscribed_topics"].push_back(topic);
    }
    return res.dump();
}

static std::string getDeliverySpoolDir() {
    std::string d = getModuleDataDir() + "/delivery_spool";
    std::error_code ec;
    std::filesystem::create_directories(d, ec);
    return d;
}

static std::string sanitizeTopicForFileName(const std::string& topic) {
    std::string safe = topic;
    for (char& c : safe) {
        if (c == '/' || c == ':' || c == '\\' || c == '?' || c == '*' || c == '<' || c == '>' || c == '|') {
            c = '_';
        }
    }
    return safe;
}

static std::string getTopicSpoolFilePath(const std::string& topic) {
    return getDeliverySpoolDir() + "/" + sanitizeTopicForFileName(topic) + ".json";
}

std::string ECloakCoreImpl::getSeenMessagesFilePath(const std::string& commHex) {
    std::string prefix = commHex.empty() ? "anonymous" : commHex.substr(0, 16);
    return getModuleDataDir() + "/seen_delivery_" + prefix + ".json";
}

void ECloakCoreImpl::loadSeenDeliveryMessages(const std::string& commHex) {
    if (m_seenDeliveryMessageIds.find(commHex) != m_seenDeliveryMessageIds.end()) return;
    m_seenDeliveryMessageIds[commHex] = std::unordered_set<std::string>();
    std::string path = getSeenMessagesFilePath(commHex);
    if (std::filesystem::exists(path)) {
        try {
            std::ifstream f(path);
            if (f.is_open()) {
                json j; f >> j;
                if (j.is_array()) {
                    for (const auto& item : j) {
                        if (item.is_string()) {
                            m_seenDeliveryMessageIds[commHex].insert(item.get<std::string>());
                        }
                    }
                }
            }
        } catch (...) {}
    }
}

void ECloakCoreImpl::saveSeenDeliveryMessages(const std::string& commHex) {
    std::string path = getSeenMessagesFilePath(commHex);
    try {
        json j = json::array();
        auto it = m_seenDeliveryMessageIds.find(commHex);
        if (it != m_seenDeliveryMessageIds.end()) {
            size_t count = 0;
            for (const auto& id : it->second) {
                j.push_back(id);
                if (++count >= 2000) break;
            }
        }
        std::ofstream f(path);
        if (f.is_open()) {
            f << j.dump();
        }
    } catch (...) {}
}

std::string ECloakCoreImpl::subscribeDeliveryTopic(const std::string& contentTopic)
{
    if (contentTopic.empty()) {
        return makeErrorJson("contentTopic cannot be empty");
    }
    if (m_deliveryMessageBuffer.find(contentTopic) == m_deliveryMessageBuffer.end()) {
        m_deliveryMessageBuffer[contentTopic] = std::vector<std::string>();
    }
    json res;
    res["ok"] = true;
    res["subscribed"] = contentTopic;
    return res.dump();
}

std::string ECloakCoreImpl::publishDeliveryMessage(const std::string& contentTopic, const std::string& base64Payload)
{
    if (contentTopic.empty()) {
        return makeErrorJson("contentTopic cannot be empty");
    }
    std::string senderComm = getActiveCommitmentHex();
    auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::string msgId = "deliv_" + std::to_string(nowMs) + "_" + (senderComm.empty() ? "anon" : senderComm.substr(0, 8));
    try {
        msgId += "_" + std::to_string(std::hash<std::string>{}(base64Payload));
    } catch (...) {}

    // 1. In-memory buffer
    m_deliveryMessageBuffer[contentTopic].push_back(base64Payload);

    // 2. Mark as seen by the sender so sender does not receive its own echo on future polls
    if (!senderComm.empty()) {
        loadSeenDeliveryMessages(senderComm);
        m_seenDeliveryMessageIds[senderComm].insert(msgId);
        saveSeenDeliveryMessages(senderComm);
    }

    // 3. Persistent Spool File
    try {
        std::string spoolPath = getTopicSpoolFilePath(contentTopic);
        json spoolArr = json::array();
        if (std::filesystem::exists(spoolPath)) {
            std::ifstream f(spoolPath);
            if (f.is_open()) {
                json existing;
                f >> existing;
                if (existing.is_array()) {
                    spoolArr = existing;
                }
            }
        }

        json msgObj;
        msgObj["id"] = msgId;
        msgObj["topic"] = contentTopic;
        msgObj["payload"] = base64Payload;
        msgObj["sender"] = senderComm;
        msgObj["timestamp"] = nowMs;

        spoolArr.push_back(msgObj);
        if (spoolArr.size() > 500) {
            json trimmed = json::array();
            for (size_t i = spoolArr.size() - 500; i < spoolArr.size(); ++i) {
                trimmed.push_back(spoolArr[i]);
            }
            spoolArr = trimmed;
        }

        std::string tmpPath = spoolPath + ".tmp";
        {
            std::ofstream out(tmpPath);
            if (out.is_open()) {
                out << spoolArr.dump();
            }
        }
        std::error_code ec;
        std::filesystem::rename(tmpPath, spoolPath, ec);
        if (ec) {
            std::filesystem::copy_file(tmpPath, spoolPath, std::filesystem::copy_options::overwrite_existing, ec);
            std::filesystem::remove(tmpPath, ec);
        }
    } catch (...) {}

    json res;
    res["ok"] = true;
    res["contentTopic"] = contentTopic;
    res["payload_length"] = base64Payload.size();
    res["published"] = true;
    res["message_id"] = msgId;
    return res.dump();
}

std::string ECloakCoreImpl::pollDeliveryMessages(const std::string& contentTopic)
{
    json res;
    res["ok"] = true;
    res["contentTopic"] = contentTopic;
    res["messages"] = json::array();

    if (contentTopic.empty()) {
        return res.dump();
    }

    std::string callerComm = getActiveCommitmentHex();
    loadSeenDeliveryMessages(callerComm);

    std::string spoolPath = getTopicSpoolFilePath(contentTopic);
    std::vector<std::string> newMessages;
    std::vector<std::string> newlySeenIds;

    if (std::filesystem::exists(spoolPath)) {
        try {
            std::ifstream f(spoolPath);
            if (f.is_open()) {
                json spoolArr;
                f >> spoolArr;
                if (spoolArr.is_array()) {
                    for (const auto& item : spoolArr) {
                        if (!item.is_object()) continue;
                        std::string id = item.value("id", "");
                        std::string payload = item.value("payload", "");

                        if (!id.empty() && m_seenDeliveryMessageIds[callerComm].count(id) > 0) {
                            continue;
                        }

                        if (!payload.empty()) {
                            newMessages.push_back(payload);
                            if (!id.empty()) {
                                newlySeenIds.push_back(id);
                            }
                        }
                    }
                }
            }
        } catch (...) {}
    }

    auto it = m_deliveryMessageBuffer.find(contentTopic);
    if (it != m_deliveryMessageBuffer.end() && !it->second.empty()) {
        for (const auto& msg : it->second) {
            bool alreadyInList = false;
            for (const auto& m : newMessages) {
                if (m == msg) { alreadyInList = true; break; }
            }
            if (!alreadyInList) {
                newMessages.push_back(msg);
            }
        }
        it->second.clear();
    }

    if (!newlySeenIds.empty()) {
        for (const auto& id : newlySeenIds) {
            m_seenDeliveryMessageIds[callerComm].insert(id);
        }
        saveSeenDeliveryMessages(callerComm);
    }

    for (const auto& msg : newMessages) {
        res["messages"].push_back(msg);

        if (contentTopic == "/e-identity/1/global-registry/proto") {
            try {
                std::vector<uint8_t> decoded = base64Decode(msg);
                std::string jsonStr(decoded.begin(), decoded.end());
                auto j = json::parse(jsonStr);
                if (j.contains("type") && j["type"] == "USER_REGISTRATION" &&
                    j.contains("username") && j.contains("commitment")) {
                    std::string u = j["username"].get<std::string>();
                    std::string c = j["commitment"].get<std::string>();
                    persistRegisteredUser(c, u);
                    if (m_usernameRegistry) {
                        std::vector<uint8_t> comm = hexToBytes(c);
                        if (comm.size() == 32) {
                            char* r = ffi_username_registry_register(m_usernameRegistry, comm.data(), u.c_str());
                            if (r) ffi_identity_free_string(r);
                        }
                    }
                }
            } catch (...) {}
        }
    }

    return res.dump();
}


// ---------------------------------------------------------------------------
// On-Chain Smart Contract Source-of-Truth Synchronization (Borsh Decoder)
// ---------------------------------------------------------------------------

namespace {

struct BorshReader {
    const uint8_t* data;
    size_t size;
    size_t offset = 0;

    bool readBytes(uint8_t* out, size_t len) {
        if (offset + len > size) return false;
        std::memcpy(out, data + offset, len);
        offset += len;
        return true;
    }

    bool skip(size_t len) {
        if (offset + len > size) return false;
        offset += len;
        return true;
    }

    bool readU32(uint32_t& out) {
        if (offset + 4 > size) return false;
        out = static_cast<uint32_t>(data[offset]) |
              (static_cast<uint32_t>(data[offset + 1]) << 8) |
              (static_cast<uint32_t>(data[offset + 2]) << 16) |
              (static_cast<uint32_t>(data[offset + 3]) << 24);
        offset += 4;
        return true;
    }

    bool readU64(uint64_t& out) {
        if (offset + 8 > size) return false;
        out = 0;
        for (int i = 0; i < 8; ++i) {
            out |= (static_cast<uint64_t>(data[offset + i]) << (i * 8));
        }
        offset += 8;
        return true;
    }

    bool readString(std::string& out) {
        uint32_t len = 0;
        if (!readU32(len)) return false;
        if (offset + len > size) return false;
        out.assign(reinterpret_cast<const char*>(data + offset), len);
        offset += len;
        return true;
    }
};

struct OnChainUserData {
    std::string commitment;
    std::string username;
};

struct OnChainForumState {
    std::vector<std::string> registeredCommitments;
    std::vector<std::string> revokedCommitments;
    std::vector<OnChainUserData> usernames;
    std::vector<std::pair<std::string, uint64_t>> memberStakes;
    uint64_t totalStaked = 0;
};

static bool parseForumInstance(const uint8_t* rawData, size_t len, OnChainForumState& outState) {
    if (!rawData || len < 44) return false;
    BorshReader r{ rawData, len, 0 };

    // Header: admin_pubkey (32), k_strikes (4), n_mod (4), m_mod (4)
    if (!r.skip(44)) return false;

    // registered_commitments: Vec<[u8; 32]>
    uint32_t regCount = 0;
    if (!r.readU32(regCount)) return false;
    for (uint32_t i = 0; i < regCount; ++i) {
        uint8_t comm[32];
        if (!r.readBytes(comm, 32)) return false;
        outState.registeredCommitments.push_back(bytesToHex(comm, 32));
    }

    // revoked_commitments: Vec<[u8; 32]>
    uint32_t revCount = 0;
    if (!r.readU32(revCount)) return false;
    for (uint32_t i = 0; i < revCount; ++i) {
        uint8_t comm[32];
        if (!r.readBytes(comm, 32)) return false;
        outState.revokedCommitments.push_back(bytesToHex(comm, 32));
    }

    // total_staked: u64
    if (!r.readU64(outState.totalStaked)) return false;

    // member_stakes: Vec<([u8; 32], u64)>
    uint32_t stakeCount = 0;
    if (!r.readU32(stakeCount)) return false;
    for (uint32_t i = 0; i < stakeCount; ++i) {
        uint8_t comm[32];
        uint64_t amt = 0;
        if (!r.readBytes(comm, 32)) return false;
        if (!r.readU64(amt)) return false;
        outState.memberStakes.push_back({ bytesToHex(comm, 32), amt });
    }

    // used_tracing_tags: Vec<[u8; 32]>
    uint32_t tagCount = 0;
    if (!r.readU32(tagCount)) return false;
    for (uint32_t i = 0; i < tagCount; ++i) {
        if (!r.skip(32)) return false;
    }

    // rooms: Vec<OnChainRoom>
    uint32_t roomCount = 0;
    if (!r.readU32(roomCount)) return false;
    for (uint32_t i = 0; i < roomCount; ++i) {
        if (!r.skip(64)) return false; // room_id (32) + admin_comm (32)
        if (!r.skip(8)) return false;  // n_mod (4) + m_mod (4)
        uint32_t modCount = 0;
        if (!r.readU32(modCount)) return false;
        if (!r.skip(modCount * 32)) return false;
        if (!r.skip(8)) return false;  // creation_index (8)
        if (!r.skip(4)) return false;  // min_members_for_maturity (4)
    }

    // room_memberships: Vec<OnChainMembership>
    uint32_t memCount = 0;
    if (!r.readU32(memCount)) return false;
    for (uint32_t i = 0; i < memCount; ++i) {
        if (!r.skip(64)) return false; // room_id (32) + member_comm (32)
        if (!r.skip(8)) return false;  // join_index (8)
        if (!r.skip(1)) return false;  // is_active bool (1)
    }

    // recorded_strikes: Vec<OnChainStrike>
    uint32_t strikeCount = 0;
    if (!r.readU32(strikeCount)) return false;
    for (uint32_t i = 0; i < strikeCount; ++i) {
        if (!r.skip(96)) return false; // room_id (32) + target_comm (32) + evidence_hash (32)
        if (!r.skip(8)) return false;  // strike_index (8)
        if (!r.skip(4)) return false;  // n_valid_sigs (4)
    }

    // current_index: u64
    if (!r.skip(8)) return false;

    // usernames: Vec<OnChainUsername>
    uint32_t userCount = 0;
    if (!r.readU32(userCount)) return false;
    for (uint32_t i = 0; i < userCount; ++i) {
        uint8_t comm[32];
        if (!r.readBytes(comm, 32)) return false;
        std::string uname;
        if (!r.readString(uname)) return false;
        outState.usernames.push_back({ bytesToHex(comm, 32), uname });
    }

    return true;
}

} // namespace

void ECloakCoreImpl::syncFromOnChainState()
{
    try {
        std::string forumPda = "99jBsXRbK91xCJR5WnxFVR2cuGvga8M4dDfaT3J2oC1Q";
        
        json req;
        req["jsonrpc"] = "2.0";
        req["method"] = "getAccount";
        req["params"] = json::array({ forumPda });
        req["id"] = 1;
        std::string postData = req.dump();

        std::string cmd = "env -u LD_LIBRARY_PATH curl -s --max-time 6 -X POST https://testnet.lez.logos.co/ -H 'Content-Type: application/json' -d '" + postData + "' 2>/dev/null";

        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return;

        std::string output;
        char buf[512];
        while (fgets(buf, sizeof(buf), pipe) != nullptr) {
            output += buf;
        }
        pclose(pipe);

        if (output.empty() || output.find("502 Bad Gateway") != std::string::npos) {
            return;
        }

        auto j = json::parse(output);
        if (!j.contains("result") || !j["result"].is_object()) return;
        auto resObj = j["result"];
        if (!resObj.contains("data") || !resObj["data"].is_object()) return;
        auto dataObj = resObj["data"];
        if (!dataObj.contains("shards") || !dataObj["shards"].is_object()) return;

        // Find program shard (any non-token shard)
        std::vector<uint8_t> rawShardBytes;
        for (auto& [shardKey, shardVal] : dataObj["shards"].items()) {
            if (shardKey != "11111111111111111111111111111111" && shardVal.is_array() && !shardVal.empty()) {
                rawShardBytes.reserve(shardVal.size());
                for (const auto& byteVal : shardVal) {
                    if (byteVal.is_number_unsigned()) {
                        rawShardBytes.push_back(static_cast<uint8_t>(byteVal.get<unsigned int>()));
                    }
                }
                break;
            }
        }

        if (rawShardBytes.empty()) return;

        OnChainForumState state;
        if (!parseForumInstance(rawShardBytes.data(), rawShardBytes.size(), state)) {
            return;
        }

        // 1. Update usernames & persist to local registered_users.json
        for (const auto& u : state.usernames) {
            persistRegisteredUser(u.commitment, u.username);
            if (m_usernameRegistry) {
                std::vector<uint8_t> comm = hexToBytes(u.commitment);
                if (comm.size() == 32) {
                    char* r = ffi_username_registry_register(m_usernameRegistry, comm.data(), u.username.c_str());
                    if (r) ffi_identity_free_string(r);
                }
            }
        }

        // 2. Update revoked commitments in blacklist
        if (m_blacklist) {
            for (const auto& revCommHex : state.revokedCommitments) {
                std::vector<uint8_t> comm = hexToBytes(revCommHex);
                if (comm.size() == 32) {
                    char* r = ffi_blacklist_revoke(m_blacklist, comm.data());
                    if (r) ffi_identity_free_string(r);
                }
            }
        }

        // 3. Reconcile local active user identity with on-chain source-of-truth
        if (m_registration) {
            uint8_t myCommBytes[32];
            ffi_registration_commitment(m_registration, myCommBytes);
            std::string myCommHex = bytesToHex(myCommBytes, 32);

            bool isReg = std::find(state.registeredCommitments.begin(), state.registeredCommitments.end(), myCommHex) != state.registeredCommitments.end();
            if (isReg) {
                m_onchainSynced = true;
                for (const auto& u : state.usernames) {
                    if (u.commitment == myCommHex) {
                        m_cachedUsername = u.username;
                        break;
                    }
                }
                for (const auto& [stkComm, stkAmt] : state.memberStakes) {
                    if (stkComm == myCommHex) {
                        m_stakeAmount = stkAmt;
                        m_staked = true;
                        break;
                    }
                }
                savePersistedIdentity();
            }
        }
    } catch (...) {}
}

std::string ECloakCoreImpl::syncOnChainState()
{
    syncFromOnChainState();
    json res;
    res["ok"] = true;
    res["source_of_truth"] = "LEZ_SMART_CONTRACT";
    res["has_identity"] = (m_registration != nullptr);
    res["onchain_synced"] = m_onchainSynced;
    res["username"] = m_cachedUsername;
    res["stake_amount"] = m_stakeAmount;
    return res.dump();
}


// ---------------------------------------------------------------------------
// Multi-Profile Management (Max 2 accounts per computer)
// ---------------------------------------------------------------------------



std::string ECloakCoreImpl::getActiveCommitmentHex() {
    if (!m_registration) return "";
    uint8_t comm[32];
    ffi_registration_commitment(m_registration, comm);
    return bytesToHex(comm, 32);
}

std::string ECloakCoreImpl::getScopedChatStoreEncFilePath() {
    std::string commHex = getActiveCommitmentHex();
    if (!commHex.empty()) {
        return getModuleDataDir() + "/chat_store_" + commHex.substr(0, 16) + ".enc";
    }
    return getModuleDataDir() + "/chat_store.enc";
}

std::string ECloakCoreImpl::getScopedWalletStoreFilePath() {
    std::string commHex = getActiveCommitmentHex();
    if (!commHex.empty()) {
        return getModuleDataDir() + "/wallet_store_" + commHex.substr(0, 16) + ".json";
    }
    return getModuleDataDir() + "/wallet_store.json";
}

void ECloakCoreImpl::syncProfilesStorage() {
    try {
        std::string pPath = getProfilesFilePath();
        json rootJson;
        bool exists = std::filesystem::exists(pPath);
        if (exists) {
            std::ifstream f(pPath);
            if (f.is_open()) {
                try { f >> rootJson; } catch (...) { rootJson = json::object(); }
            }
        }
        if (!rootJson.is_object()) rootJson = json::object();
        if (!rootJson.contains("profiles") || !rootJson["profiles"].is_array()) {
            rootJson["profiles"] = json::array();
        }

        auto& pArr = rootJson["profiles"];

        // Seed from known identities if empty
        if (pArr.empty()) {
            std::string idPath = getIdentityFilePath();
            if (std::filesystem::exists(idPath)) {
                std::ifstream f(idPath);
                if (f.is_open()) {
                    json idJ; f >> idJ;
                    if (idJ.contains("commitment") && idJ.contains("nsk")) {
                        pArr.push_back(idJ);
                    }
                }
            }
            for (const std::string& fallback : { "/home/namauser/logos-ecosystem/identity.json", "/home/namauser/logos-ecosystem/identity_backup.json" }) {
                if (pArr.size() >= 2) break;
                if (std::filesystem::exists(fallback)) {
                    std::ifstream f(fallback);
                    if (f.is_open()) {
                        json fbJ; f >> fbJ;
                        if (fbJ.contains("commitment") && fbJ.contains("nsk")) {
                            std::string fbComm = fbJ["commitment"].get<std::string>();
                            bool alreadyIn = false;
                            for (const auto& existing : pArr) {
                                if (existing.contains("commitment") && existing["commitment"].get<std::string>() == fbComm) {
                                    alreadyIn = true;
                                    break;
                                }
                            }
                            if (!alreadyIn) {
                                pArr.push_back(fbJ);
                            }
                        }
                    }
                }
            }
        }

        // Update active profile in array
        std::string activeComm = getActiveCommitmentHex();
        if (!activeComm.empty()) {
            bool found = false;
            for (auto& p : pArr) {
                if (p.contains("commitment") && p["commitment"].get<std::string>() == activeComm) {
                    p["username"] = m_cachedUsername;
                    p["staked"] = m_staked;
                    p["stake_amount"] = m_stakeAmount;
                    p["onchain_synced"] = m_onchainSynced;
                    found = true;
                    break;
                }
            }
            if (!found && pArr.size() < 2) {
                uint8_t nsk[32];
                ffi_registration_nsk(m_registration, nsk);
                json newP;
                newP["commitment"] = activeComm;
                newP["nsk"] = bytesToHex(nsk, 32);
                newP["username"] = m_cachedUsername;
                newP["staked"] = m_staked;
                newP["stake_amount"] = m_stakeAmount;
                newP["onchain_synced"] = m_onchainSynced;
                pArr.push_back(newP);
            }
            rootJson["active_commitment"] = activeComm;
        } else if (!pArr.empty()) {
            rootJson["active_commitment"] = pArr[0]["commitment"].get<std::string>();
        }

        std::ofstream out(pPath);
        if (out.is_open()) {
            out << rootJson.dump(2);
        }
    } catch (...) {}
}

std::string ECloakCoreImpl::getProfilesList()
{
    syncProfilesStorage();
    try {
        std::string pPath = getProfilesFilePath();
        if (!std::filesystem::exists(pPath)) {
            return "[]";
        }
        std::ifstream f(pPath);
        if (!f.is_open()) return "[]";
        json rootJ;
        f >> rootJ;
        if (!rootJ.contains("profiles") || !rootJ["profiles"].is_array()) {
            return "[]";
        }
        std::string activeComm = getActiveCommitmentHex();
        json res = json::array();
        for (const auto& p : rootJ["profiles"]) {
            json item;
            std::string c = p.value("commitment", "");
            item["commitment"] = c;
            item["username"] = p.value("username", "Anonymous");
            item["is_active"] = (c == activeComm);
            item["staked"] = p.value("staked", false);
            item["stake_amount"] = p.value("stake_amount", 0);
            res.push_back(item);
        }
        return res.dump();
    } catch (...) {
        return "[]";
    }
}

std::string ECloakCoreImpl::switchProfile(const std::string& commitmentHex)
{
    if (commitmentHex.empty()) return makeErrorJson("Commitment cannot be empty");
    syncProfilesStorage();
    try {
        std::string pPath = getProfilesFilePath();
        if (!std::filesystem::exists(pPath)) return makeErrorJson("Profiles store not found");
        std::ifstream f(pPath);
        if (!f.is_open()) return makeErrorJson("Failed to open profiles store");
        json rootJ; f >> rootJ;
        if (!rootJ.contains("profiles") || !rootJ["profiles"].is_array()) return makeErrorJson("No profiles available");

        json targetProfile;
        bool found = false;
        for (const auto& p : rootJ["profiles"]) {
            if (p.value("commitment", "") == commitmentHex) {
                targetProfile = p;
                found = true;
                break;
            }
        }
        if (!found) return makeErrorJson("Profile not found");

        // 1. Save current state
        savePersistedIdentity();

        // 2. Clear in-memory chat sessions & joiner to prevent session mixing
        for (auto& [id, sess] : m_chatSessions) {
            if (sess) ffi_chat_session_free(sess);
        }
        m_chatSessions.clear();
        if (m_chatJoiner) {
            ffi_chat_joiner_free(m_chatJoiner);
            m_chatJoiner = nullptr;
        }

        // 3. Re-initialize RegistrationClient with target NSK
        std::string nskHex = targetProfile.value("nsk", "");
        std::vector<uint8_t> nskBytes = hexToBytes(nskHex);
        if (nskBytes.size() != 32) return makeErrorJson("Invalid NSK for target profile");

        if (m_registration) ffi_registration_free(m_registration);
        m_registration = ffi_registration_from_nsk(nskBytes.data());

        m_cachedUsername = targetProfile.value("username", "");
        m_staked = targetProfile.value("staked", false);
        m_stakeAmount = targetProfile.value("stake_amount", 0);
        m_onchainSynced = targetProfile.value("onchain_synced", true);

        // 4. Update in-memory username registry
        if (m_usernameRegistry && !m_cachedUsername.empty()) {
            uint8_t comm[32];
            ffi_registration_commitment(m_registration, comm);
            char* res = ffi_username_registry_register(m_usernameRegistry, comm, m_cachedUsername.c_str());
            if (res) ffi_identity_free_string(res);
        }

        // 5. Save updated active identity to identity.json
        savePersistedIdentity();

        // 6. Update active_commitment in profiles.json
        rootJ["active_commitment"] = commitmentHex;
        std::ofstream out(pPath);
        if (out.is_open()) {
            out << rootJ.dump(2);
        }

        json okRes;
        okRes["ok"] = true;
        okRes["active_username"] = m_cachedUsername;
        okRes["active_commitment"] = commitmentHex;
        return okRes.dump();
    } catch (const std::exception& e) {
        return makeErrorJson(std::string("Error switching profile: ") + e.what());
    }
}
