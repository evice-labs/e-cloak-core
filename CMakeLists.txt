# e-cloak-core: Core Module wrapping e-identity-stack (e_identity_sdk and e_moderation_sdk) via FFI

cmake_minimum_required(VERSION 3.14)
project(ECloakCorePlugin LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include the Logos Module CMake helper
if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/LogosModule.cmake")
    include(cmake/LogosModule.cmake)
else()
    message(FATAL_ERROR "LogosModule.cmake not found")
endif()

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/metadata.json" METADATA_JSON)
string(JSON MODULE_NAME GET ${METADATA_JSON} name)

# Define the module with external libraries
logos_module(
    NAME ${MODULE_NAME}
    SOURCES 
        src/e_cloak_core_impl.h
        src/e_cloak_core_impl.cpp
    EXTERNAL_LIBS
        e_identity_sdk
        e_moderation_sdk
    LINK_LIBRARIES
        crypto
        zstd
)
