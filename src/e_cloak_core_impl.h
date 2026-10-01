#pragma once

#include <string>
#include <vector>
#include <unordered_map>
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
struct FfiChatSession;
struct FfiChatJoiner;

/**
 * @brief Universal Logos Module implementing AnonChat Core capabilities
 *
 * Wraps e_identity_sdk, e_moderation_sdk, and e_chat_bridge via C-ABI FFI.
 * The Qt plugin glue and QML bindings are generated automatically by logos-module-builder.
 * All integer types in the public interface must be 64-bit (uint64_t or int64_t) for LIDL compatibility.
 */
class ECloakCoreImpl : public LogosModuleContext
{
public:
    ECloakCoreImpl();
    ~ECloakCoreImpl() override;

    // Identity Operations
    std::string createIdentity(const std::string& nskHex);
    std::string getCommitment();
    std::string prepareRegistration(const std::string& username, uint64_t kSssThreshold, const std::string& nodePubkeysJson);
    std::string registerUsername(const std::string& username);
    std::string lookupUsername(const std::string& commitmentHex);
    bool hasActiveIdentity();
    std::string getSchnorrPublicKey();
    std::string getIdentityInfo();
    std::string getNetworkStatus();
    std::string recordStake(uint64_t amount);

    // Room Operations
    std::string createRoom(const std::string& adminCommitmentHex, uint64_t nThreshold, uint64_t mTotal, const std::string& moderatorPubkeysJson, uint64_t creationIndex, uint64_t minMembersForMaturity);
    std::string joinRoom(const std::string& roomIdHex, const std::string& memberCommitmentHex, const std::string& memberPubkeyHex, const std::string& consentSignatureHex, uint64_t joinIndex);
    std::string leaveRoom(const std::string& roomIdHex, const std::string& memberCommitmentHex);
    int64_t getRoomMemberCount(const std::string& roomIdHex);
    bool isRoomMember(const std::string& roomIdHex, const std::string& memberCommitmentHex);
    std::string signRoomConsent(const std::string& roomIdHex);

    // Messaging (Two-Tier SSS)
    std::string preparePost(const std::string& message, const std::string& postSaltHex, const std::string& moderatorPubkeysJson, int64_t nThreshold);

    // Moderation Operations
    std::string createModerator(const std::string& privkeyHex);
    std::string getModeratorPubkey();
    std::string issueStrike(const std::string& roomIdHex, const std::string& targetCommitmentHex, const std::string& evidenceHashHex, const std::string& tracingTagHex, const std::string& encryptedShareJson, int64_t moderatorIndex);
    std::string validateStrike(const std::string& certificateJson, int64_t nThreshold);

    // Slashing & Reconstruction
    std::string createAggregator(int64_t nThreshold, int64_t kStrikes, const std::string& moderatorPubkeysJson);
    std::string reconstructStrike(const std::string& tracingTagHex, const std::string& certificatesJson);
    std::string reconstructNsk(const std::string& strikesJson);
    bool isRevoked(const std::string& commitmentHex);
    std::string revokeCommitment(const std::string& commitmentHex);

    // Blob Media Storage Operations
    std::string saveBlob(const std::string& base64Data, const std::string& fileName, const std::string& mimeType);
    std::string loadBlob(const std::string& blobId);
    std::string getBlobPath(const std::string& blobId);

    // Persistent Chat Store Operations (AES-256-GCM + Zstd)
    std::string saveChatStore(const std::string& chatStoreJson);
    std::string loadChatStore();
    std::string clearChatStore();

    // Wallet Store & On-Chain Verification Operations
    std::string saveWalletStore(const std::string& walletStoreJson);
    std::string loadWalletStore();
    std::string getWalletInfo();
    std::string syncOnChainCollateral(bool verified, uint64_t verifiedBalance);
    std::string getLezWalletAccount();
    std::string verifyOnChainCollateral(const std::string& accountId);

    // MLS Group & 1-on-1 Chat Operations (de-MLS via e_chat_bridge)
    std::string createChatRoom(const std::string& roomIdHex, const std::string& username);
    std::string initChatModeration(const std::string& roomIdHex, uint64_t kStrikes);
    std::string createChatJoiner(const std::string& username);
    std::string getChatKeyPackage();
    std::string addChatMember(const std::string& roomIdHex, const std::string& keyPackageHex);
    std::string completeChatJoin(const std::string& roomIdHex, const std::string& welcomeHex);
    std::string sendProtectedChatMessage(const std::string& roomIdHex, const std::string& text, const std::string& postSaltHex, const std::string& moderatorPubkeysJson, uint64_t threshold);
    std::string receiveProtectedChatMessage(const std::string& roomIdHex, const std::string& ciphertextHex);
    std::string sendDirectMessage(const std::string& roomIdHex, const std::string& text);
    std::string receiveDirectMessage(const std::string& roomIdHex, const std::string& ciphertextHex);

    // Decentralized Transport Operations (logos-delivery / Waku)
    std::string initDelivery(const std::string& configJson);
    std::string startDelivery();
    std::string stopDelivery();
    std::string getDeliveryStatus();
    std::string publishDeliveryMessage(const std::string& contentTopic, const std::string& base64Payload);
    std::string subscribeDeliveryTopic(const std::string& contentTopic);
    std::string pollDeliveryMessages(const std::string& contentTopic);

private:
    FfiRegistrationClient* m_registration = nullptr;
    FfiUsernameRegistry* m_usernameRegistry = nullptr;
    FfiRoomRegistry* m_roomRegistry = nullptr;
    FfiModeratorRegistry* m_moderatorRegistry = nullptr;
    FfiBlacklist* m_blacklist = nullptr;
    FfiMemberClient* m_member = nullptr;
    FfiModeratorClient* m_moderator = nullptr;
    FfiSlashAggregator* m_aggregator = nullptr;

    // MLS Chat Sessions
    std::unordered_map<std::string, FfiChatSession*> m_chatSessions;
    FfiChatJoiner* m_chatJoiner = nullptr;

    // Decentralized Transport State
    void* m_deliveryCtx = nullptr;
    bool m_deliveryRunning = false;
    std::string m_deliveryConfig;
    std::unordered_map<std::string, std::vector<std::string>> m_deliveryMessageBuffer;

    std::string m_cachedUsername;
    bool m_staked = false;
    uint64_t m_stakeAmount = 0;
    void loadPersistedIdentity();
    void savePersistedIdentity();
    std::vector<uint8_t> getStorageKey();
};
