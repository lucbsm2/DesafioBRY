#include "VerifierService.h"
#include "Utils.h"
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <iomanip>
#include <sstream>

namespace VerifierService {

    CMS_ContentInfo* loadCMS(const std::string& signaturePath) {
        BIO* in = BIO_new_file(signaturePath.c_str(), "rb");
        if (!in) return nullptr;
        CMS_ContentInfo* cms = d2i_CMS_bio(in, nullptr);
        BIO_free(in);
        return cms;
    }

    std::string bytesToHex(const unsigned char* bytes, int len) {
        std::stringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0');
        for (int i = 0; i < len; ++i) {
            ss << std::setw(2) << (int)bytes[i];
        }
        return ss.str();
    }

    std::string asn1TimeToString(ASN1_TIME* time) {
        if (!time) return "";
        BIO* b = BIO_new(BIO_s_mem());
        ASN1_TIME_print(b, time);
        char* data;
        long len = BIO_get_mem_data(b, &data);
        std::string str(data, len);
        BIO_free(b);
        return str;
    }

    VerificationResult verifyAndGetDetails(const std::string& signaturePath) {
        VerificationResult res;
        res.isValid = false;
        res.status = "INVALIDO";

        CMS_ContentInfo* cms = loadCMS(signaturePath);
        if (!cms) return res;

        // bio de saida eh obrigatorio no verify mesmo descartando conteudo
        BIO* out = BIO_new(BIO_s_mem()); 
        if (!out) {
            CMS_ContentInfo_free(cms);
            return res;
        }
        
        // verifica apenas integridade ignora cadeia de confianca ca raiz
        int flags = CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY;
        
        if (CMS_verify(cms, nullptr, nullptr, nullptr, out, flags)) {
            res.isValid = true;
            res.status = "VALIDO";
        } else {
            fprintf(stderr, "\n[OPENSSL ERROR STACK START]\n");
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "[OPENSSL ERROR STACK END]\n\n");
            Utils::printOpenSSLError("Falha na verificacao da assinatura");
        }

        BIO_free(out);
        
        // extrai metadados como signatario data e hash
        STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms);
        if (signers && sk_CMS_SignerInfo_num(signers) > 0) {
            CMS_SignerInfo* si = sk_CMS_SignerInfo_value(signers, 0);
            
            // retorna pilha nova que precisa ser liberada mas certificados sao ponteiros internos
            STACK_OF(X509)* certs = CMS_get0_signers(cms);
            if (certs && sk_X509_num(certs) > 0) {
                X509* cert = sk_X509_value(certs, 0);
                X509_NAME* subject = X509_get_subject_name(cert);

                char cn[256] = {0};
                int cn_len = X509_NAME_get_text_by_NID(subject, NID_commonName, cn, sizeof(cn));

                if (cn_len > 0) {
                    res.signerName = std::string(cn);
                } else {
                    char* subject_str = X509_NAME_oneline(subject, nullptr, 0);
                    if (subject_str) {
                        res.signerName = std::string(subject_str);
                        OPENSSL_free(subject_str);
                    }
                }
                sk_X509_free(certs); 
            }

            int timeIdx = CMS_signed_get_attr_by_NID(si, NID_pkcs9_signingTime, -1);
            if (timeIdx >= 0) {
                X509_ATTRIBUTE* attr = CMS_signed_get_attr(si, timeIdx);

                if (X509_ATTRIBUTE_count(attr) > 0) {
                    ASN1_TYPE* at = X509_ATTRIBUTE_get0_type(attr, 0);

                    if (at->type == V_ASN1_UTCTIME) {
                        res.signingTime = asn1TimeToString(at->value.utctime);

                    } else if (at->type == V_ASN1_GENERALIZEDTIME) {
                        res.signingTime = asn1TimeToString(at->value.generalizedtime);
                    }                
                }
            }

            int digestIdx = CMS_signed_get_attr_by_NID(si, NID_pkcs9_messageDigest, -1);
            if (digestIdx >= 0) {
                X509_ATTRIBUTE* attr = CMS_signed_get_attr(si, digestIdx);
                if (attr && X509_ATTRIBUTE_count(attr) > 0) {
                    ASN1_TYPE* at = X509_ATTRIBUTE_get0_type(attr, 0);
                    if (at && at->type == V_ASN1_OCTET_STRING && at->value.octet_string) {
                        res.hashHex = bytesToHex(
                            at->value.octet_string->data, 
                            at->value.octet_string->length
                        );
                    }
                }
            }
            
            X509_ALGOR* digestAlg = nullptr;
            CMS_SignerInfo_get0_algs(si, nullptr, nullptr, &digestAlg, nullptr);
            if (digestAlg) {
                const ASN1_OBJECT* oid = nullptr;
                X509_ALGOR_get0(&oid, nullptr, nullptr, digestAlg);
                if (oid) {
                    char buf[128];
                    OBJ_obj2txt(buf, sizeof(buf), oid, 0);
                    res.hashAlgo = std::string(buf);
                }
            }
        }

        CMS_ContentInfo_free(cms);
        return res;
    }


    bool executeStep3(const std::string& signaturePath) {
        Utils::logInfo("Iniciando Etapa 3 Verificacao de Assinatura...");

        VerificationResult res = verifyAndGetDetails(signaturePath);

        Utils::logInfo(" -------------------  ");
        Utils::logInfo("    Status: " + res.status);
        Utils::logInfo(" -------------------  ");

        if (res.isValid) {
            Utils::logInfo(" Detalhes da Assinatura");

            if (!res.signerName.empty()) 
                Utils::logInfo("    Signer: " + res.signerName);
            if (!res.signingTime.empty()) 
                Utils::logInfo("    Signing Time: " + res.signingTime);
            if (!res.hashAlgo.empty()) 
                Utils::logInfo("    Hash Algorithm: " + res.hashAlgo);
            if (!res.hashHex.empty()) 
                Utils::logInfo("    Document Hash: " + res.hashHex);

            Utils::logInfo(" ------------------- ");
        }

        return res.isValid;
    }
}