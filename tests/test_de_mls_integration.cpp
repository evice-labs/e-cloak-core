#include <iostream>
#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <nlohmann/json.hpp>
#include "../src/e_cloak_core_impl.h"

using json = nlohmann::json;

int main() {
    std::cout << "=== Running ECloakCore de-MLS & Logos Delivery Integration Tests ===" << std::endl;

    // 1. Isolate and Initialize Alice Core
    setenv("XDG_DATA_HOME", "/tmp/alice_e_cloak_test", 1);
    std::filesystem::remove_all("/tmp/alice_e_cloak_test");

    ECloakCoreImpl alice;
    std::string aliceIdRes = alice.createIdentity("");
    std::cout << "[Alice] createIdentity: " << aliceIdRes << std::endl;
    auto aliceIdJson = json::parse(aliceIdRes);
    assert(aliceIdJson.contains("commitment"));
    std::string aliceComm = aliceIdJson["commitment"].get<std::string>();

    // 2. Initialize Delivery Transport for Alice
    std::string deliveryInit = alice.initDelivery("");
    std::cout << "[Alice] initDelivery: " << deliveryInit << std::endl;
    auto delInitJson = json::parse(deliveryInit);
    assert(delInitJson["ok"] == true);

    std::string deliveryStart = alice.startDelivery();
    std::cout << "[Alice] startDelivery: " << deliveryStart << std::endl;
    auto delStartJson = json::parse(deliveryStart);
    assert(delStartJson["running"] == true);

    // 3. Alice creates MLS Chat Room
    std::string roomId = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    std::string createRoomRes = alice.createChatRoom(roomId, "Alice");
    std::cout << "[Alice] createChatRoom: " << createRoomRes << std::endl;
    auto crJson = json::parse(createRoomRes);
    assert(crJson["ok"] == true);
    assert(crJson["room_id"] == roomId);

    // 4. Isolate and Initialize Bob Core
    setenv("XDG_DATA_HOME", "/tmp/bob_e_cloak_test", 1);
    std::filesystem::remove_all("/tmp/bob_e_cloak_test");

    ECloakCoreImpl bob;
    std::string bobIdRes = bob.createIdentity("");
    std::cout << "[Bob] createIdentity: " << bobIdRes << std::endl;
    auto bobIdJson = json::parse(bobIdRes);
    assert(bobIdJson.contains("commitment"));

    // 5. Bob creates Joiner Client and generates KeyPackage
    std::string joinerRes = bob.createChatJoiner("Bob");
    std::cout << "[Bob] createChatJoiner: " << joinerRes << std::endl;
    auto joinerJson = json::parse(joinerRes);
    assert(joinerJson["ok"] == true);
    assert(joinerJson.contains("key_package"));
    std::string bobKeyPackage = joinerJson["key_package"].get<std::string>();
    assert(!bobKeyPackage.empty());

    // 6. Alice adds Bob to Room -> generates Welcome message
    std::string addMemberRes = alice.addChatMember(roomId, bobKeyPackage);
    std::cout << "[Alice] addChatMember: " << addMemberRes << std::endl;
    auto addJson = json::parse(addMemberRes);
    assert(addJson["ok"] == true);
    assert(addJson.contains("welcome_hex"));
    std::string welcomeHex = addJson["welcome_hex"].get<std::string>();
    assert(!welcomeHex.empty());

    // 7. Bob completes Join using Welcome message
    std::string completeJoinRes = bob.completeChatJoin(roomId, welcomeHex);
    std::cout << "[Bob] completeChatJoin: " << completeJoinRes << std::endl;
    auto cjJson = json::parse(completeJoinRes);
    assert(cjJson["ok"] == true);
    assert(cjJson["joined"] == true);

    // 8. Alice sends Protected Chat Message with Two-Tier SSS shares
    std::string salt = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    std::string msgText = "Hello from Logos de-MLS with Two-Tier SSS!";
    std::string aliceSchnorrPub = alice.getSchnorrPublicKey();
    std::string modPubkeysJson = "["" + aliceSchnorrPub + ""]";
    std::string sendRes = alice.sendProtectedChatMessage(roomId, msgText, salt, modPubkeysJson, 1);
    std::cout << "[Alice] sendProtectedChatMessage: " << sendRes << std::endl;
    auto sendJson = json::parse(sendRes);
    assert(sendJson["ok"] == true);
    assert(sendJson.contains("ciphertext_hex"));
    std::string ciphertextHex = sendJson["ciphertext_hex"].get<std::string>();

    // 9. Bob receives and decrypts Protected Message
    std::string recvRes = bob.receiveProtectedChatMessage(roomId, ciphertextHex);
    std::cout << "[Bob] receiveProtectedChatMessage: " << recvRes << std::endl;
    auto recvJson = json::parse(recvRes);
    assert(recvJson["ok"] == true);
    assert(recvJson.contains("text"));
    assert(recvJson["text"] == msgText);
    std::cout << "[SUCCESS] Decrypted message matches: " << recvJson["text"].get<std::string>() << std::endl;

    // 10. Direct Messaging (1-on-1 MLS DM)
    std::string dmText = "Private 1-on-1 message between Alice and Bob";
    std::string sendDmRes = alice.sendDirectMessage(roomId, dmText);
    std::cout << "[Alice] sendDirectMessage: " << sendDmRes << std::endl;
    auto dmSendJson = json::parse(sendDmRes);
    assert(dmSendJson["ok"] == true);
    assert(dmSendJson.contains("ciphertext_hex"));
    std::string dmCiphertext = dmSendJson["ciphertext_hex"].get<std::string>();

    std::string recvDmRes = bob.receiveDirectMessage(roomId, dmCiphertext);
    std::cout << "[Bob] receiveDirectMessage: " << recvDmRes << std::endl;
    auto dmRecvJson = json::parse(recvDmRes);
    assert(dmRecvJson["ok"] == true);
    assert(dmRecvJson.contains("text"));
    assert(dmRecvJson["text"] == dmText);
    std::cout << "[SUCCESS] Decrypted DM matches: " << dmRecvJson["text"].get<std::string>() << std::endl;

    // 11. Verify Transport message buffering and polling
    std::string pollRes = alice.pollDeliveryMessages("/e-identity/1/room-" + roomId + "/proto");
    std::cout << "[Alice] pollDeliveryMessages: " << pollRes << std::endl;
    auto pollJson = json::parse(pollRes);
    assert(pollJson["ok"] == true);
    assert(pollJson["messages"].is_array());
    assert(pollJson["messages"].size() >= 1);

    // Cleanup test directories
    std::filesystem::remove_all("/tmp/alice_e_cloak_test");
    std::filesystem::remove_all("/tmp/bob_e_cloak_test");

    std::cout << "\n>>> ALL DE-MLS & LOGOS DELIVERY INTEGRATION TESTS PASSED! <<<\n" << std::endl;
    return 0;
}
