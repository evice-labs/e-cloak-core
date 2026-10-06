#include <iostream>
#include <cassert>
#include <vector>
#include <nlohmann/json.hpp>
#include "e_cloak_core_impl.h"

using json = nlohmann::json;

// Base64 helper for test
static std::string base64Encode(const std::string& in) {
    static const char lookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(lookup[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(lookup[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

int main() {
    std::cout << "=== Running User Discovery & On-Chain Validation Integration Tests ===\n";

    // Instance 1: Alice
    ECloakCoreImpl alice;
    std::string aliceComm = alice.getCommitment();
    if (aliceComm.empty()) {
        std::string aliceId = alice.createIdentity("");
        auto aliceJson = json::parse(aliceId);
        aliceComm = aliceJson["commitment"].get<std::string>();
    }
    std::cout << "[Alice] Identity commitment: " << aliceComm << "\n";

    // 1. Validation: Reject invalid username (< 3 chars or special chars)
    std::string badRes1 = alice.registerUsername("al");
    assert(json::parse(badRes1).contains("error"));
    std::cout << "[Test 1] Short username correctly rejected: " << badRes1 << "\n";

    std::string badRes2 = alice.registerUsername("alice!@#");
    assert(json::parse(badRes2).contains("error"));
    std::cout << "[Test 2] Invalid characters correctly rejected: " << badRes2 << "\n";

    // 2. Register valid username
    std::string regAlice = alice.registerUsername("AliceUser");
    auto regAliceJson = json::parse(regAlice);
    assert(regAliceJson["ok"].get<bool>() == true);
    assert(regAliceJson["username"].get<std::string>() == "AliceUser");
    std::cout << "[Test 3] AliceUser registered successfully!\n";

    // 3. Lookup Alice by username and by commitment
    std::string lookupComm = alice.lookupCommitment("AliceUser");
    auto lCommJson = json::parse(lookupComm);
    assert(lCommJson["ok"].get<bool>() == true);
    assert(lCommJson["commitment"].get<std::string>() == aliceComm);
    std::cout << "[Test 4] lookupCommitment(AliceUser) -> " << lCommJson["commitment"] << "\n";

    std::string lookupName = alice.lookupUsername(aliceComm);
    assert(lookupName == "AliceUser");
    std::cout << "[Test 5] lookupUsername(" << aliceComm.substr(0, 10) << "...) -> " << lookupName << "\n";

    // 4. Ingest Bob registration via peer discovery announcement on /e-identity/1/global-registry/proto
    std::string bobComm = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    json bobAnnouncement;
    bobAnnouncement["type"] = "USER_REGISTRATION";
    bobAnnouncement["username"] = "BobUser";
    bobAnnouncement["commitment"] = bobComm;
    bobAnnouncement["timestamp"] = 1791180000000ULL;
    std::string b64 = base64Encode(bobAnnouncement.dump());

    alice.publishDeliveryMessage("/e-identity/1/global-registry/proto", b64);
    alice.pollDeliveryMessages("/e-identity/1/global-registry/proto");
    std::cout << "[Test 6] Ingested BobUser registration announcement over Delivery transport!\n";

    // 5. Global Discovery: Alice discovers Bob
    std::string allUsersList = alice.getRegisteredUsersList();
    auto aList = json::parse(allUsersList);
    std::cout << "[Test 7] Discovered users list: " << aList.dump(2) << "\n";
    assert(aList.size() >= 2);

    bool foundAlice = false, foundBob = false;
    for (const auto& u : aList) {
        if (u["username"] == "AliceUser" && u["commitment"] == aliceComm) foundAlice = true;
        if (u["username"] == "BobUser" && u["commitment"] == bobComm) foundBob = true;
    }
    assert(foundAlice && foundBob);
    std::cout << "[Test 8] Both Alice and Bob present in discovered registry!\n";

    // 6. Cross-lookup: Alice can lookup Bob commitment
    std::string aliceLookupBob = alice.lookupCommitment("BobUser");
    assert(json::parse(aliceLookupBob)["commitment"].get<std::string>() == bobComm);
    std::cout << "[Test 9] Cross-resolved Bob commitment successfully: " << aliceLookupBob << "\n";

    std::cout << "\n>>> ALL USER DISCOVERY & VALIDATION TESTS PASSED! <<<\n";
    return 0;
}
