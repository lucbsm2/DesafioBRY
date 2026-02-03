#include "DigestService.h"
#include "Utils.h"
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <openssl/evp.h>

namespace DigestService {

    std::string calculateSHA512(const std::string& filePath) {
        // Abre com a flag 'ate' (at the end) para posicionar o cursor no fim e obter o tamanho imediatamente
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file) {
            Utils::logInfo("Não foi possível abrir o arquivo: " + filePath);
            return "";
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        std::vector<char> buffer(size);

        if (!file.read(buffer.data(), size)) {
            Utils::logInfo("Falha ao ler o arquivo: " + filePath);
            return "";
        }
        
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int length = 0;
            
        if (!EVP_Digest(buffer.data(), size, hash, &length, EVP_sha512(), nullptr)) {
            Utils::printOpenSSLError("Falha ao calcular o hash SHA-512");
            return "";
        }

        std::stringstream ss;
        for (unsigned int i = 0; i < length; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    bool executeStep1(const std::string& inputFile, const std::string& outputFile) {
        Utils::logInfo("Iniciando Etapa 1: Calculo de Hash...");

        std::string digest = calculateSHA512(inputFile);
        if (digest.empty()) {
            return false;
        }

        std::ofstream out(outputFile);
        if (!out.is_open()) {
            Utils::logInfo("Nao foi possível escrever em " + outputFile);
            return false;
        }
        
        out << digest;
        Utils::logInfo("Hash salvo em " + outputFile);
        return true;
    }
}