cmake_minimum_required(VERSION 3.2)

project(jwtpp LANGUAGES C CXX)

include(CheckCSourceCompiles)
include(CheckCCompilerFlag)
include(CheckCXXSourceCompiles)
include(CheckCXXSymbolExists)
include(CheckCXXCompilerFlag)
include(CheckFunctionExists)
include(CheckTypeSize)
include(CheckIncludeFiles)
include(CheckIncludeFileCXX)

check_include_file_cxx(iostream HAVE_IOSTREAM)
check_include_file_cxx(memory HAVE_MEMORY)
check_include_file_cxx(functional HAVE_FUNCTIONAL)
check_include_file_cxx(string HAVE_STRING)
check_include_file_cxx(atomic HAVE_ATOMIC)
check_include_file_cxx(mutex HAVE_MUTEX)
check_include_file_cxx(exception HAVE_EXCEPTION)
check_include_file_cxx(stdexcept HAVE_STDEXCEPT)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")

set(LIB_SOURCES
        src/jwt.cpp
        src/base64.cpp
        src/tools.cpp
)

set(EXPORT_INCLUDES
        ${CMAKE_CURRENT_SOURCE_DIR}/include/export
)

add_library(${PROJECT_NAME} STATIC ${LIB_SOURCES})

target_include_directories(${PROJECT_NAME} PUBLIC ${EXPORT_INCLUDES} ${OPENSSL_INCLUDE_DIR})

target_link_libraries(${PROJECT_NAME}
        jsoncpp
)

set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)
find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
