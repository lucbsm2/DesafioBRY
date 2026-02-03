cmake_minimum_required(VERSION 3.15)

project(DesafioBry CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL CONFIG REQUIRED)
find_package(Poco CONFIG REQUIRED COMPONENTS Net Util JSON Foundation Crypto)
find_package(GTest CONFIG REQUIRED)


include(GoogleTest)
include_directories(src)

add_executable(Bry_API 
    src/Server.cpp
    src/DigestService.cpp 
    src/SignerService.cpp 
    src/VerifierService.cpp
)

target_link_libraries(Bry_API PRIVATE 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    Poco::Net 
    Poco::Util 
    Poco::JSON 
    Poco::Foundation
    Poco::Crypto
)

add_executable(Bry_CLI 
    src/main.cpp 
    src/DigestService.cpp 
    src/SignerService.cpp 
    src/VerifierService.cpp
)

target_link_libraries(Bry_CLI PRIVATE 
    OpenSSL::SSL 
    OpenSSL::Crypto
    Poco::Foundation
    Poco::Util
    Poco::Crypto
)

set(MAIN_TARGETS Bry_API Bry_CLI)

foreach(TARGET ${MAIN_TARGETS})
    add_custom_command(TARGET ${TARGET} POST_BUILD
        # 1. Copia o arquivo .env (apenas se ele existir na raiz)
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/.env"
            "$<TARGET_FILE_DIR:${TARGET}>/.env"
        
        # 2. Copia a pasta resources inteira
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/resources"
            "$<TARGET_FILE_DIR:${TARGET}>/resources"
            
    )
endforeach()

enable_testing()

function(create_test_executable name source)
    add_executable(${name} ${source} ${ARGN})
    
    target_link_libraries(${name} PRIVATE 
        GTest::gtest_main 
        OpenSSL::SSL 
        OpenSSL::Crypto
        Poco::Foundation 
        Poco::Crypto
    )
    
    if(WIN32)
        add_custom_command(TARGET ${name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy -t $<TARGET_FILE_DIR:${name}> 
            $<TARGET_RUNTIME_DLLS:${name}>
            COMMAND_EXPAND_LISTS
        )
    endif()

    if(EXISTS "${CMAKE_SOURCE_DIR}/resources")
        add_custom_command(TARGET ${name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/resources"
            "$<TARGET_FILE_DIR:${name}>/resources"
        )

        add_custom_command(TARGET ${name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/resources"
            "${CMAKE_BINARY_DIR}/resources"
        )
    endif()

    gtest_discover_tests(${name})
endfunction()

create_test_executable(digest_tests tests/DigestServiceTests.cpp src/DigestService.cpp)
create_test_executable(signer_tests tests/SignerServiceTests.cpp src/SignerService.cpp)
create_test_executable(verifier_tests tests/VerifierServiceTests.cpp src/VerifierService.cpp src/SignerService.cpp)

install(TARGETS Bry_API Bry_CLI RUNTIME DESTINATION bin)

if(WIN32)
    file(GLOB RUNTIME_DLLS "${CMAKE_BINARY_DIR}/bin/*.dll")
    if(RUNTIME_DLLS)
        install(FILES ${RUNTIME_DLLS} DESTINATION bin)
    endif()
endif()