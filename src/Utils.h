#pragma once
#include <iostream>
#include <openssl/err.h>

namespace Utils {
    inline void printOpenSSLError(const std::string& message) {
        std::cerr << "[ERROR] " << message << std::endl;
        ERR_print_errors_fp(stderr);
    }

    inline void logInfo(const std::string& message) {
        std::cout << "[INFO] " << message << std::endl;
    }
}