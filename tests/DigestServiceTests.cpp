#include <gtest/gtest.h>
#include <fstream>
#include <cstdio>
#include <string>
#include "../src/DigestService.h"


void createTestFile(const std::string& filename, const std::string& content) {
    std::ofstream out(filename, std::ios::binary);
    out << content;
    out.close();
}

// CENARIO 1 Sucesso Padrao
// Verifica se uma entrada conhecida produz o hash SHA512 exato
TEST(DigestServiceTest, CalculateSHA512_StandardContent) {
    std::string filename = "test_standard.txt";
    createTestFile(filename, "123456");

    // Hash SHA512 conhecido para 123456
    std::string expectedHash = "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413";

    std::string result = DigestService::calculateSHA512(filename);
    EXPECT_EQ(result, expectedHash);

    std::remove(filename.c_str());
}

// CENARIO 2 Arquivo Vazio
// Verifica se nao falha e retorna o hash especifico para arquivo vazio
TEST(DigestServiceTest, CalculateSHA512_EmptyFile) {
    std::string filename = "test_empty.txt";
    createTestFile(filename, "");

    // Hash SHA512 conhecido para ""
    std::string expectedHash = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

    std::string result = DigestService::calculateSHA512(filename);
    EXPECT_EQ(result, expectedHash);

    std::remove(filename.c_str());
}

// CENARIO 3 Arquivo Faltando
// O servico deve lidar com arquivos inexistentes retornando string vazia
TEST(DigestServiceTest, CalculateSHA512_FileNotFound) {
    std::string result = DigestService::calculateSHA512("ghost_file.txt");
    EXPECT_EQ(result, "");
}

// CENARIO 4 Execucao Completa Leitura e Escrita
// Verifica se executeStep1 coordena corretamente a leitura e escrita do hash
TEST(DigestServiceTest, ExecuteStep1_FullSuccess) {
    std::string inFile = "test_input_full.txt";
    std::string outFile = "test_output_hash.txt";
    
    createTestFile(inFile, "abc");

    bool success = DigestService::executeStep1(inFile, outFile);
    EXPECT_TRUE(success);

    std::ifstream out(outFile);
    ASSERT_TRUE(out.is_open());
    
    std::string fileContent;
    out >> fileContent;
    
    std::string expected = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    EXPECT_EQ(fileContent, expected);

    out.close();
    std::remove(inFile.c_str());
    std::remove(outFile.c_str());
}

// CENARIO 5 Falha na Escrita
// Verifica comportamento quando o caminho de saida e invalido
TEST(DigestServiceTest, ExecuteStep1_InvalidOutputPath) {
    std::string inFile = "test_input_valid.txt";

    std::string outFile = "/invalid_dir/output.txt"; 

    createTestFile(inFile, "data");

    bool success = DigestService::executeStep1(inFile, outFile);
    EXPECT_FALSE(success);

    std::remove(inFile.c_str());
}