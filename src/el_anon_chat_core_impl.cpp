#include "el_anon_chat_core_impl.h"
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

using json = nlohmann::json;

// --- Internal Helper Functions ---

static std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        if (i + 1 < hex.length()) {
            uint8_t byte = static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16));
            bytes.push_back(byte);
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

static std::string getIdentityFilePath() {
    const char* customDir = std::getenv("LOGOS_USER_DIR");
    std::string base;
    if (customDir && std::strlen(customDir) > 0) {
        base = std::string(customDir) + "/module_data/ecloakcore";
    } else {
        const char* home = std::getenv("HOME");
        if (home && std::strlen(home) > 0) {
            base = std::string(home) + "/.local/share/Logos/LogosBasecamp/module_data/ecloakcore";
        } else {
            base = "/tmp/ecloakcore";
        }
    }
    std::error_code ec;
    std::filesystem::create_directories(base, ec);
    return base + "/identity.json";
}

ElAnonChatCoreImpl::ElAnonChatCoreImpl()
{
    m_usernameRegistry = ffi_username_registry_new();
    m_roomRegistry = ffi_room_registry_new();
    m_moderatorRegistry = ffi_moderator_registry_new();
    m_blacklist = ffi_blacklist_new();
    loadPersistedIdentity();
}

ElAnonChatCoreImpl::~ElAnonChatCoreImpl()
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

void ElAnonChatCoreImpl::loadPersistedIdentity()
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

void ElAnonChatCoreImpl::savePersistedIdentity()
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

        std::string path = getIdentityFilePath();
        std::ofstream file(path);
        if (file.is_open()) {
            file << j.dump(2);
        }
    } catch (...) {}
}

std::string ElAnonChatCoreImpl::getIdentityInfo()
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
    res["schnorr_pubkey"] = getSchnorrPublicKey();
    return res.dump();
}

std::string ElAnonChatCoreImpl::getNetworkStatus()
{
    json res;
    res["connected"] = true;
    res["network_name"] = "Logos Execution Zone (LEZ) Testnet";
    res["sequencer_url"] = "https://testnet.lez.logos.co/";
    res["min_stake_amount"] = 150;
    res["required_collateral_lez"] = 150;
    res["collateral_active"] = (m_registration != nullptr);
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

std::string ElAnonChatCoreImpl::createIdentity(const std::string& nskHex)
{
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

std::string ElAnonChatCoreImpl::getCommitment()
{
    if (!m_registration) return "";
    uint8_t comm[32];
    ffi_registration_commitment(m_registration, comm);
    return bytesToHex(comm, 32);
}

bool ElAnonChatCoreImpl::hasActiveIdentity()
{
    return m_registration != nullptr;
}

std::string ElAnonChatCoreImpl::getSchnorrPublicKey()
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

std::string ElAnonChatCoreImpl::prepareRegistration(const std::string& username,
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

std::string ElAnonChatCoreImpl::registerUsername(const std::string& username)
{
    if (!m_registration) return makeErrorJson("identity not initialized — generate or restore identity first");
    if (!m_usernameRegistry) return makeErrorJson("username registry not initialized");
    if (username.empty()) return makeErrorJson("username cannot be empty");

    uint8_t comm[32];
    ffi_registration_commitment(m_registration, comm);

    if (m_blacklist && ffi_blacklist_is_revoked(m_blacklist, comm) == 1) {
        return makeErrorJson("identity has been revoked — cannot register username");
    }

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

std::string ElAnonChatCoreImpl::lookupUsername(const std::string& commitmentHex)
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

std::string ElAnonChatCoreImpl::createRoom(const std::string& adminCommitmentHex,
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

std::string ElAnonChatCoreImpl::signRoomConsent(const std::string& roomIdHex)
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

std::string ElAnonChatCoreImpl::joinRoom(const std::string& roomIdHex,
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

std::string ElAnonChatCoreImpl::leaveRoom(const std::string& roomIdHex, const std::string& memberCommitmentHex)
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

int64_t ElAnonChatCoreImpl::getRoomMemberCount(const std::string& roomIdHex)
{
    if (!m_roomRegistry) return 0;
    std::vector<uint8_t> roomId = hexToBytes(roomIdHex);
    if (roomId.size() != 32) return 0;
    return static_cast<int64_t>(ffi_room_registry_active_member_count(m_roomRegistry, roomId.data()));
}

bool ElAnonChatCoreImpl::isRoomMember(const std::string& roomIdHex, const std::string& memberCommitmentHex)
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

std::string ElAnonChatCoreImpl::preparePost(const std::string& message,
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
        return out;
    } catch (const std::exception& e) {
        return makeErrorJson(e.what());
    }
}

// ---------------------------------------------------------------------------
// Moderation Operations
// ---------------------------------------------------------------------------

std::string ElAnonChatCoreImpl::createModerator(const std::string& privkeyHex)
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

std::string ElAnonChatCoreImpl::getModeratorPubkey()
{
    if (!m_moderator) return "";
    uint8_t pub[32];
    ffi_moderator_public_key(m_moderator, pub);
    return bytesToHex(pub, 32);
}

std::string ElAnonChatCoreImpl::issueStrike(const std::string& /*roomIdHex*/,
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

std::string ElAnonChatCoreImpl::validateStrike(const std::string& certificateJson, int64_t nThreshold)
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

std::string ElAnonChatCoreImpl::createAggregator(int64_t nThreshold, int64_t kStrikes, const std::string& moderatorPubkeysJson)
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

std::string ElAnonChatCoreImpl::reconstructStrike(const std::string& tracingTagHex, const std::string& certificatesJson)
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

std::string ElAnonChatCoreImpl::reconstructNsk(const std::string& strikesJson)
{
    if (!m_aggregator) return makeErrorJson("aggregator not initialized");
    char* res = ffi_aggregator_reconstruct_nsk(m_aggregator, strikesJson.c_str());
    if (!res) return makeErrorJson("failed to reconstruct NSK");
    std::string out(res);
    ffi_free_string(res);
    return out;
}

bool ElAnonChatCoreImpl::isRevoked(const std::string& commitmentHex)
{
    if (!m_blacklist) return false;
    std::vector<uint8_t> comm = hexToBytes(commitmentHex);
    if (comm.size() != 32) return false;
    return ffi_blacklist_is_revoked(m_blacklist, comm.data()) == 1;
}

std::string ElAnonChatCoreImpl::revokeCommitment(const std::string& commitmentHex)
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
