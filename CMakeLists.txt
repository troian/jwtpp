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
check_include_file(json/json.h HAVE_JSON_H)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")

set(EXPORT_INCLUDES
        ${CMAKE_CURRENT_SOURCE_DIR}/include/export
)

set(LIB_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/jwt.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/base64.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tools.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/

        ${EXPORT_INCLUDES}/jwt/jwt.hpp
        ${EXPORT_INCLUDES}/tools/base64.hpp
        ${EXPORT_INCLUDES}/tools/tools.hpp
)

add_library(${PROJECT_NAME} STATIC ${LIB_SOURCES})

target_link_libraries(${PROJECT_NAME}
        jsoncpp
)

set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)
find_package(OpenSSL REQUIRED)

find_package(Jsoncpp REQUIRED)

include_directories()

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${EXPORT_INCLUDES}
                           ${OPENSSL_INCLUDE_DIR}
                           ${JSONCPP_INCLUDE_DIRS}
)

include_directories(${OPENSSL_INCLUDE_DIR})

target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES} ${JSONCPP_LIBRARIES})
