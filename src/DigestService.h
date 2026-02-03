#pragma once
#include <string>

namespace DigestService {
    std::string calculateSHA512(const std::string& filePath);
    
    bool executeStep1(const std::string& inputFile, const std::string& outputFile);
}