#include "SignerService.h"
#include "Utils.h"
#include <cstdio>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>

namespace SignerService {

    bool loadCredentials(const std::string& p12Path, const std::string& password, 
                         PKCS12** p12, EVP_PKEY** pkey, X509** cert, STACK_OF(X509)** ca) {
        
        BIO* bio = BIO_new_file(p12Path.c_str(), "rb");
        if (!bio) {
            Utils::logInfo("Não foi possível abrir o arquivo P12: " + p12Path);
            return false;
        }


        *p12 = d2i_PKCS12_bio(bio, nullptr);
        BIO_free(bio);

        if (!*p12) {
            Utils::logInfo("Falha ao ler o arquivo P12: " + p12Path);
            return false;
        }

        // extrai chave privada e certificado usando a senha
        if (!PKCS12_parse(*p12, password.c_str(), pkey, cert, ca)) {
            Utils::logInfo("Falha ao processar o arquivo P12: " + p12Path);
            return false;
        }
        return true;
    }       

    CMS_ContentInfo* signData(const std::string& docPath, X509* cert, EVP_PKEY* pkey, STACK_OF(X509)* ca) {

        BIO* content = BIO_new_file(docPath.c_str(), "rb");
        if (!content) {
            Utils::printOpenSSLError("Arquivo de entrada não encontrado: " + docPath);
            return nullptr;
        }

        // flags partial permite configurar o hash sha512 depois e binary evita corrupcao de quebra de linha
        int flags = CMS_BINARY | CMS_PARTIAL;

        CMS_ContentInfo* cms = CMS_sign(nullptr, nullptr, ca, content, flags);
        
        if (!cms) {
            Utils::printOpenSSLError("Falha ao inicializar CMS");
            BIO_free(content);
            return nullptr;
        }

        // adiciona o signatario forçando o uso de sha512
        if (!CMS_add1_signer(cms, cert, pkey, EVP_sha512(), CMS_BINARY)) {
            Utils::printOpenSSLError("Falha ao adicionar signatário");
            CMS_ContentInfo_free(cms);
            BIO_free(content);
            return nullptr;
        }

        // Finalize signature generation
        if (!CMS_final(cms, content, nullptr, flags)) {
            Utils::printOpenSSLError("Falha ao finalizar assinatura");
            CMS_ContentInfo_free(cms);
            BIO_free(content);
            return nullptr;
        }

        BIO_free(content);
        return cms; 
    }

    bool generateSignature(const std::string& p12Path, const std::string& password, const std::string& docPath, const std::string& outPath) {
        PKCS12* p12 = nullptr;
        EVP_PKEY* pkey = nullptr;
        X509* cert = nullptr;
        STACK_OF(X509)* ca = nullptr;
            
        if (!loadCredentials(p12Path, password, &p12, &pkey, &cert, &ca)) {
            Utils::printOpenSSLError("Falha ao carregar credenciais P12");
            if (p12) PKCS12_free(p12);
            return false;
        }

        CMS_ContentInfo* cms = signData(docPath, cert, pkey, ca);
        bool success = false;

        if (cms) {
            BIO* out = BIO_new_file(outPath.c_str(), "wb");
            if (out) {
                // salva a estrutura cms em formato der binario
                if (i2d_CMS_bio(out, cms)) {
                    success = true;
                }
                else {
                    Utils::printOpenSSLError("Falha ao escrever arquivo de assinatura");
                }
                BIO_free(out);
            }
            else {
                Utils::logInfo("Não foi possível criar o arquivo de saída: " + outPath);
            }
            CMS_ContentInfo_free(cms);
        }

        if (p12) PKCS12_free(p12);
        if (pkey) EVP_PKEY_free(pkey);
        if (cert) X509_free(cert);
        if (ca) sk_X509_pop_free(ca, X509_free);

        return success;
    }

    bool executeStep2(const std::string& p12Path, const std::string& docPath, const std::string& outPath, const std::string& password) {
        Utils::logInfo("Iniciando Etapa 2: Assinatura Digital...");

        if (generateSignature(p12Path, password, docPath, outPath)) {
            Utils::logInfo("--- Assinatura Criada ---");
            Utils::logInfo("Assinatura salva em " + outPath);
            return 1;
        }

        return 0;
    }
}