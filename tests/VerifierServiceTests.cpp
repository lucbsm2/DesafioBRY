#include <gtest/gtest.h>
#include <fstream>
#include <cstdio>
#include <string>
#include "../src/VerifierService.h"
#include "../src/SignerService.h"

class VerifierServiceTest : public ::testing::Test {
protected:
    std::string validP12 = "resources/pkcs12/certificado_teste_hub.pfx";
    std::string validPass = "bry123456";

    std::string tempDoc;
    std::string validSig;
    
    void SetUp() override {

        const testing::TestInfo* const test_info = testing::UnitTest::GetInstance()->current_test_info();
        std::string testName = test_info->name();

        tempDoc = "doc_" + testName + ".txt";
        validSig = "sig_" + testName + ".p7s";

        // Cria um doc mockado
        std::ofstream out(tempDoc);
        out << "Conteudo critico para verificacao";
        out.close();

        // Cria uma assinatura valida
        bool signedOk = SignerService::executeStep2(validP12, tempDoc, validSig, validPass);
        ASSERT_TRUE(signedOk) << "Setup falhou: Nao foi possivel gerar a assinatura.";
    }

    void TearDown() override {
        std::remove(tempDoc.c_str());
        std::remove(validSig.c_str());
    }
};

// CENARIO 1: Load CMS 
// Quando o p7s for valido deve fazer o parse corretamente
TEST_F(VerifierServiceTest, LoadCMS_LoadsExistingFile) {
    CMS_ContentInfo* cms = VerifierService::loadCMS(validSig);
    EXPECT_NE(cms, nullptr);
    if (cms) CMS_ContentInfo_free(cms);
}

// CENARIO 2: Load CMS (File Not Found)
TEST_F(VerifierServiceTest, LoadCMS_ReturnsNullIfFileDontExist) {
    CMS_ContentInfo* cms = VerifierService::loadCMS("arquivo_inexistente.p7s");
    EXPECT_EQ(cms, nullptr);
}

// CENARIO 3: Verify and Get Details (Assinatura valida)
// Quando assinatura for valida deve retornar status valido e popular metadata
TEST_F(VerifierServiceTest, VerifyDetails_ReturnsValidForGoodSignature) {
    VerifierService::VerificationResult res = VerifierService::verifyAndGetDetails(validSig);

    EXPECT_TRUE(res.isValid);
    EXPECT_EQ(res.status, "VALIDO");

    EXPECT_FALSE(res.signerName.empty()) << "Signer name should be extracted";
    EXPECT_FALSE(res.signingTime.empty()) << "Signing time should be extracted";
    EXPECT_FALSE(res.hashHex.empty()) << "Hash digest should be extracted";
    EXPECT_FALSE(res.hashAlgo.empty());
}

// CENARIO 4: Verify and Get Details (Invalid File)
TEST_F(VerifierServiceTest, VerifyDetails_ReturnsInvalidForMissingFile) {
    VerifierService::VerificationResult res = VerifierService::verifyAndGetDetails("ghost_sig.p7s");

    EXPECT_FALSE(res.isValid);
    EXPECT_EQ(res.status, "INVALIDO");
}

// CENARIO 5: Execute Step 3 (Full Flow)
// Quando assinatura for valida, deve retornar true
TEST_F(VerifierServiceTest, ExecuteStep3_ReturnsTrueOnSuccess) {
    bool success = VerifierService::executeStep3(validSig);
    EXPECT_TRUE(success);
}