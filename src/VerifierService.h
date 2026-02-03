#pragma once
#include <string>
#include <openssl/cms.h>

namespace VerifierService {
    struct VerificationResult {
        bool isValid;
        std::string status;         // "VALIDO" ou "INVALIDO" (JSON Requirement)
        std::string signerName;     // Certificate Common Name (CN)
        std::string signingTime;    // Signing time (UTC)
        std::string hashHex;        // Hexadecimal hash do doc
        std::string hashAlgo;       // Digest algorithm
    };

    CMS_ContentInfo* loadCMS(const std::string& signaturePath);

    VerificationResult verifyAndGetDetails(const std::string& signaturePath);

    bool verifyAndExtract(CMS_ContentInfo* cms, const std::string& recoveredPath);

    void printSignerDetails(CMS_ContentInfo* cms);

    bool executeStep3(const std::string& signaturePath);
}