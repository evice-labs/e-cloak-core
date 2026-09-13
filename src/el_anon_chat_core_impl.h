#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "logos_module_context.h"

// Forward declaration of FFI types from vendor headers
struct FfiRegistrationClient;
struct FfiUsernameRegistry;
struct FfiRoomRegistry;
struct FfiModeratorRegistry;
struct FfiBlacklist;
struct FfiMemberClient;
struct FfiModeratorClient;
struct FfiSlashAggregator;

/**
 * @brief Universal Logos Module implementing AnonChat Core capabilities
 *
 * Wraps e_identity_sdk and e_moderation_sdk via C-ABI FFI.
 * The Qt plugin glue and QML bindings are generated automatically by logos-module-builder.
 * All integer types in the public interface must be 64-bit (uint64_t or int64_t) for LIDL compatibility.
 */
class ElAnonChatCoreImpl : public LogosModuleContext
{
public:
    ElAnonChatCoreImpl();
    ~ElAnonChatCoreImpl() override;

    // --- Identity Operations ---
    std::string createIdentity(const std::string& nskHex);
    std::string getCommitment();
    std::string prepareRegistration(const std::string& username, uint64_t kSssThreshold, const std::string& nodePubkeysJson);
    std::string registerUsername(const std::string& username);
    std::string lookupUsername(const std::string& commitmentHex);
    bool hasActiveIdentity();
    std::string getSchnorrPublicKey();
    std::string getIdentityInfo();
    std::string getNetworkStatus();

    // --- Room Operations ---
    std::string createRoom(const std::string& adminCommitmentHex, uint64_t nThreshold, uint64_t mTotal, const std::string& moderatorPubkeysJson, uint64_t creationIndex, uint64_t minMembersForMaturity);
    std::string joinRoom(const std::string& roomIdHex, const std::string& memberCommitmentHex, const std::string& memberPubkeyHex, const std::string& consentSignatureHex, uint64_t joinIndex);
    std::string leaveRoom(const std::string& roomIdHex, const std::string& memberCommitmentHex);
    int64_t getRoomMemberCount(const std::string& roomIdHex);
    bool isRoomMember(const std::string& roomIdHex, const std::string& memberCommitmentHex);
    std::string signRoomConsent(const std::string& roomIdHex);

    // --- Messaging (Two-Tier SSS) ---
    std::string preparePost(const std::string& message, const std::string& postSaltHex, const std::string& moderatorPubkeysJson, int64_t nThreshold);

    // --- Moderation Operations ---
    std::string createModerator(const std::string& privkeyHex);
    std::string getModeratorPubkey();
    std::string issueStrike(const std::string& roomIdHex, const std::string& targetCommitmentHex, const std::string& evidenceHashHex, const std::string& tracingTagHex, const std::string& encryptedShareJson, int64_t moderatorIndex);
    std::string validateStrike(const std::string& certificateJson, int64_t nThreshold);

    // --- Slashing & Reconstruction ---
    std::string createAggregator(int64_t nThreshold, int64_t kStrikes, const std::string& moderatorPubkeysJson);
    std::string reconstructStrike(const std::string& tracingTagHex, const std::string& certificatesJson);
    std::string reconstructNsk(const std::string& strikesJson);
    bool isRevoked(const std::string& commitmentHex);
    std::string revokeCommitment(const std::string& commitmentHex);

private:
    FfiRegistrationClient* m_registration = nullptr;
    FfiUsernameRegistry* m_usernameRegistry = nullptr;
    FfiRoomRegistry* m_roomRegistry = nullptr;
    FfiModeratorRegistry* m_moderatorRegistry = nullptr;
    FfiBlacklist* m_blacklist = nullptr;
    FfiMemberClient* m_member = nullptr;
    FfiModeratorClient* m_moderator = nullptr;
    FfiSlashAggregator* m_aggregator = nullptr;
    std::string m_cachedUsername;
    void loadPersistedIdentity();
    void savePersistedIdentity();
};
