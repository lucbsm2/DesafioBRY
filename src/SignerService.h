#pragma once
#include <string>
#include <openssl/pkcs12.h>
#include <openssl/cms.h>

namespace SignerService {
    bool loadCredentials(const std::string& p12Path, const std::string& password, 
                         PKCS12** p12, EVP_PKEY** pkey, X509** cert, STACK_OF(X509)** ca);

    CMS_ContentInfo* signData(const std::string& docPath, X509* cert, EVP_PKEY* pkey, STACK_OF(X509)* ca);

    bool generateSignature(const std::string& p12Path, const std::string& password, const std::string& docPath, const std::string& outPath);

    bool executeStep2(const std::string& p12Path, const std::string& docPath, const std::string& outPath, const std::string& password);
}