#include "DigestService.h"
#include "SignerService.h"
#include "VerifierService.h"
#include "Utils.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstdlib> 
#include <fstream>
#include <string>
#include <iostream>
#include <filesystem>

#ifdef _WIN32
    #include <direct.h>
    #define setenv(k, v, o) _putenv_s(k, v)
#endif

void loadEnvFile() {
    std::ifstream file(".env");
    if (!file.is_open()) {
        Utils::logInfo("Aviso: Arquivo .env nao encontrado. Usando variaveis do sistema ou padroes.");
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        size_t delimiterPos = line.find('=');
        if (delimiterPos != std::string::npos) {
            std::string key = line.substr(0, delimiterPos);
            std::string value = line.substr(delimiterPos + 1);
            
            // Remove \r (comum em arquivos editados no Windows)
            if (!value.empty() && value.back() == '\r') value.pop_back();

            // Lógica Cross-Platform
            #ifdef _WIN32
                _putenv_s(key.c_str(), value.c_str());
            #else
                setenv(key.c_str(), value.c_str(), 1);
            #endif
        }
    }
    Utils::logInfo("Configuracao carregada do arquivo .env");
}

/*
void loadEnvFile() {
    std::ifstream file(".env");
    if (!file.is_open()) {
        Utils::logInfo("Aviso: Arquivo .env nao encontrado. Usando variaveis do sistema ou padroes.");
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        size_t delimiterPos = line.find('=');
        if (delimiterPos != std::string::npos) {
            std::string key = line.substr(0, delimiterPos);
            std::string value = line.substr(delimiterPos + 1);
            
            if (!value.empty() && value.back() == '\r') value.pop_back();

            setenv(key.c_str(), value.c_str(), 1);
        }
    }
    Utils::logInfo("Configuracao carregada do arquivo .env");
}
*/

std::string getEnvVar(const std::string& key, const std::string& defaultValue = "") {
    const char* val = std::getenv(key.c_str());
    if (val == nullptr) {
        return defaultValue;
    }
    return std::string(val);
}

int main() {
    
    // Global OpenSSL Init
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    loadEnvFile();

    // Configuration
    const std::string docFile = "resources/arquivos/doc.txt";
    const std::string hashFile = "resultado_etapa1.txt";
    const std::string p12File = "resources/pkcs12/certificado_teste_hub.pfx";
    const std::string signatureFile = "assinatura.p7s";

    std::string p12Password = getEnvVar("P12_PASSWORD");

    // --- Execute Flow ---

    if (!DigestService::executeStep1(docFile, hashFile)) {
        return 1;
    }

    if (!SignerService::executeStep2(p12File, docFile, signatureFile, p12Password)) {
        return 1;
    }

    if (!VerifierService::executeStep3(signatureFile)) {
        return 1;
    }

    Utils::logInfo("Todos os passos executados corretamente");
    return 0;
}