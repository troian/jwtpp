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

option(JWTPP_TESTS "Build tests" ON)

find_package(PkgConfig REQUIRED)

find_package(OpenSSL REQUIRED)
pkg_check_modules(JsonCPP REQUIRED jsoncpp)

include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${JsonCPP_INCLUDE_DIRS})

link_directories(${JsonCPP_LIBRARY_DIRS})

check_include_file_cxx(memory HAVE_MEMORY)
check_include_file_cxx(functional HAVE_FUNCTIONAL)
check_include_file_cxx(string HAVE_STRING)
check_include_file_cxx(vector HAVE_VECTOR)
check_include_file_cxx(mutex HAVE_MUTEX)
check_include_file_cxx(exception HAVE_EXCEPTION)
check_include_file_cxx(stdexcept HAVE_STDEXCEPT)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated")

set(EXPORT_INCLUDES
	${CMAKE_CURRENT_SOURCE_DIR}/include/export
)

set(LIB_SOURCES
    src/tools.cpp
    src/claims.cpp
    src/crypto.cpp
    src/hmac.cpp
    src/rsa.cpp
    src/jws.cpp
   	src/b64.cpp
    src/header.cpp

    ${EXPORT_INCLUDES}/jwt/buffer.hpp
    ${EXPORT_INCLUDES}/jwt/claims.hpp
    ${EXPORT_INCLUDES}/jwt/header.hpp
    ${EXPORT_INCLUDES}/jwt/crypto.hpp
    ${EXPORT_INCLUDES}/../tools/tools.hpp
)

add_library(${PROJECT_NAME} STATIC ${LIB_SOURCES})

target_include_directories(
	${PROJECT_NAME}
    PRIVATE
    include
)
target_include_directories(
	${PROJECT_NAME}
	PUBLIC
		${EXPORT_INCLUDES}
		${JsonCPP_INCLUDE_DIRS}
)

target_link_libraries(
	${PROJECT_NAME}
	${OPENSSL_LIBRARIES}
	${JsonCPP_LIBRARIES}
)

if (JWTPP_TESTS)
	enable_testing()
	add_subdirectory(gtest)

	include_directories(${PROJECT_SOURCE_DIR}/gtest/googletest/include)

	set(JWTPP_TEST_SRS ${PROJECT_SOURCE_DIR}/tests/jwtpp_test.cpp)

	add_executable(jwtpp_test ${JWTPP_TEST_SRS})

	target_link_libraries(
		jwtpp_test
		gtest_main
		jwtpp
	)

	add_test(UnitTests jwtpp_test)
endif()

