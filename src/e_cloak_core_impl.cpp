#include "e_cloak_core_impl.h"
#include "../lib/e_identity_sdk.h"
#include "../lib/e_moderation_sdk.h"

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

using json = nlohmann::json;

// --- Internal Helper Functions ---

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

// --- Implementation ---

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

    std::string newBase = root + "/e-cloak-core";
    std::string oldBase = root + "/ecloakcore";

    std::error_code ec;
    std::filesystem::create_directories(newBase, ec);

    // Backward compatibility: If old data dir exists and new does not have files yet, migrate them
    if (std::filesystem::exists(oldBase, ec)) {
        if (!std::filesystem::exists(newBase + "/identity.json", ec) && std::filesystem::exists(oldBase + "/identity.json", ec)) {
            std::filesystem::copy_file(oldBase + "/identity.json", newBase + "/identity.json", std::filesystem::copy_options::skip_existing, ec);
        }
        if (!std::filesystem::exists(newBase + "/chat_store.enc", ec) && std::filesystem::exists(oldBase + "/chat_store.enc", ec)) {
            std::filesystem::copy_file(oldBase + "/chat_store.enc", newBase + "/chat_store.enc", std::filesystem::copy_options::skip_existing, ec);
        }
        if (!std::filesystem::exists(newBase + "/chat_store.json", ec) && std::filesystem::exists(oldBase + "/chat_store.json", ec)) {
            std::filesystem::copy_file(oldBase + "/chat_store.json", newBase + "/chat_store.json", std::filesystem::copy_options::skip_existing, ec);
        }
    }

    return newBase;
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
    res["schnorr_pubkey"] = getSchnorrPublicKey();
    return res.dump();
}

std::string ECloakCoreImpl::getNetworkStatus()
{
    json res;
    res["connected"] = true;
    res["network_name"] = "Logos Execution Zone (LEZ) Testnet";
    res["sequencer_url"] = "https://testnet.lez.logos.co/";
    res["min_stake_amount"] = 150;
    res["required_collateral_lez"] = 150;
    res["collateral_active"] = m_staked;
    res["stake_amount"] = m_stakeAmount;
    res["has_active_identity"] = (m_registration != nullptr);
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

    json res;
    res["commitment"] = bytesToHex(comm, 32);
    res["nsk"] = bytesToHex(nsk, 32);
    savePersistedIdentity();
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

std::string ECloakCoreImpl::registerUsername(const std::string& username)
{
    if (!m_registration) return makeErrorJson("identity not initialized — generate or restore identity first");
    if (!m_usernameRegistry) return makeErrorJson("username registry not initialized");
    if (username.empty()) return makeErrorJson("username cannot be empty");
    if (username.length() < 3 || username.length() > 32) {
        return makeErrorJson("Username must be between 3 and 32 characters");
    }
    for (char c : username) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') {
            return makeErrorJson("Username can only contain alphanumeric characters and underscores");
        }
    }

    uint8_t comm[32];
    ffi_registration_commitment(m_registration, comm);
    std::string myCommHex = bytesToHex(comm, 32);

    if (m_blacklist && ffi_blacklist_is_revoked(m_blacklist, comm) == 1) {
        return makeErrorJson("identity has been revoked — cannot register username");
    }

    // Ownership & Collision Check: If username is already taken by a DIFFERENT commitment, reject
    char* lookupJson = ffi_username_registry_lookup_by_username(m_usernameRegistry, username.c_str());
    if (lookupJson) {
        std::string s(lookupJson);
        ffi_identity_free_string(lookupJson);
        try {
            json j = json::parse(s);
            if (j.contains("commitment") && j["commitment"].is_string()) {
                std::string owner = j["commitment"].get<std::string>();
                if (!owner.empty() && owner != myCommHex) {
                    return makeErrorJson("Username already taken");
                }
            }
        } catch (...) {}
    }

    // Upsert semantic: Reset local registry so previous aliases for this commitment are released
    ffi_username_registry_free(m_usernameRegistry);
    m_usernameRegistry = ffi_username_registry_new();

    char* res = ffi_username_registry_register(
        m_usernameRegistry,
        comm,
        username.c_str()
    );

    if (!res) return makeErrorJson("failed to register username");
    std::string out(res);
    ffi_identity_free_string(res);
    m_cachedUsername = username;
    savePersistedIdentity();
    return out;
}

std::string ECloakCoreImpl::lookupUsername(const std::string& commitmentHex)
{
    if (!m_usernameRegistry) return "";
    std::vector<uint8_t> comm = hexToBytes(commitmentHex);
    if (comm.size() != 32) return "";

    char* name = ffi_username_registry_lookup_by_commitment(m_usernameRegistry, comm.data());
    if (!name) return "";
    std::string out(name);
    ffi_identity_free_string(name);
    return out;
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
        std::string encPath = getChatStoreEncFilePath();
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
        std::string encPath = getChatStoreEncFilePath();
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
        std::string encPath = getChatStoreEncFilePath();
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
