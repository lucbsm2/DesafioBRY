#include <gtest/gtest.h>
#include <fstream>
#include <cstdio>
#include <string>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "../src/SignerService.h"

class SignerServiceTest : public ::testing::Test {
protected:
    std::string validP12 = "resources/pkcs12/certificado_teste_hub.pfx";
    std::string validPass = "bry123456";
    std::string tempDoc;
    std::string tempSig;

    void SetUp() override {
        // Cria um doc temporario para teste
        const testing::TestInfo* const test_info = testing::UnitTest::GetInstance()->current_test_info();
        std::string testName = test_info->name();

        tempDoc = "doc_" + testName + ".txt";
        tempSig = "sig_" + testName + ".p7s";

        // Cria o documento de teste especifico para este cenario
        std::ofstream out(tempDoc);
        out << "Dados para serem assinados no teste unitario";
        out.close();
    }

    void TearDown() override {
        std::remove(tempDoc.c_str());
        std::remove(tempSig.c_str());
    }

    // HELPER carrega credenciais manualmente para testar signData isolado
    bool loadRawCredentials(EVP_PKEY** pkey, X509** cert, STACK_OF(X509)** ca) {
        FILE* fp = fopen(validP12.c_str(), "rb");
        if (!fp) return false;

        PKCS12* p12 = d2i_PKCS12_fp(fp, nullptr);
        fclose(fp);
        if (!p12) return false;

        int result = PKCS12_parse(p12, validPass.c_str(), pkey, cert, ca);
        PKCS12_free(p12);
        return result != 0;
    }
};

// CENARIO 1 Assinar Dados Sucesso
// Quando as credenciais e o arquivo sao validos deve retornar estrutura CMS
TEST_F(SignerServiceTest, SignData_RetornaCMS_QuandoEntradasValidas) {
    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;
    STACK_OF(X509)* ca = nullptr;

    ASSERT_TRUE(loadRawCredentials(&pkey, &cert, &ca));

    CMS_ContentInfo* cms = SignerService::signData(tempDoc, cert, pkey, ca);

    EXPECT_NE(cms, nullptr);

    if (cms) CMS_ContentInfo_free(cms);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    sk_X509_pop_free(ca, X509_free);
}

// CENARIO 2 Assinar Dados Arquivo Faltando
// Quando o arquivo de entrada nao existe deve retornar nulo
TEST_F(SignerServiceTest, SignData_RetornaNull_QuandoArquivoFalta) {
    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;
    STACK_OF(X509)* ca = nullptr;

    ASSERT_TRUE(loadRawCredentials(&pkey, &cert, &ca));

    CMS_ContentInfo* cms = SignerService::signData("ghost_file.txt", cert, pkey, ca);

    EXPECT_EQ(cms, nullptr);

    EVP_PKEY_free(pkey);
    X509_free(cert);
    sk_X509_pop_free(ca, X509_free);
}
    
// CENARIO 3 Gerar Assinatura Sucesso
// Verifica se generateSignature cria o arquivo p7s corretamente
TEST_F(SignerServiceTest, GenerateSignature_CriaArquivo_Sucesso) {
    bool result = SignerService::generateSignature(validP12, validPass, tempDoc, tempSig);

    EXPECT_TRUE(result);

    // verifica a existencia do arquivo fisico
    std::ifstream f(tempSig);
    EXPECT_TRUE(f.good());
}

// CENARIO 4 Gerar Assinatura Falha Senha
// Verifica se retorna falso ao usar senha errada
TEST_F(SignerServiceTest, GenerateSignature_Falha_SenhaIncorreta) {
    bool result = SignerService::generateSignature(validP12, "senha_errada", tempDoc, tempSig);
    EXPECT_FALSE(result);
}

// CENARIO 5 Gerar Assinatura Falha Caminho
// Verifica se retorna falso quando nao consegue salvar no disco
TEST_F(SignerServiceTest, GenerateSignature_Falha_CaminhoInvalido) {
    std::string caminhoRuim = "pasta_inexistente/<>:assinatura.p7s";
    bool result = SignerService::generateSignature(validP12, validPass, tempDoc, caminhoRuim);
    EXPECT_FALSE(result);
}

// CENARIO 6 Executar Etapa 2
// Verifica se a funcao principal wrapper funciona
TEST_F(SignerServiceTest, ExecuteStep2_FluxoCompleto) {
    bool result = SignerService::executeStep2(validP12, tempDoc, tempSig, validPass);
    EXPECT_TRUE(result);
}