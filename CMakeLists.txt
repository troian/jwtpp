cmake_minimum_required(VERSION 3.2)

project(jwtpp LANGUAGES C CXX)

set(VERSION 0.1.0)

include(CheckCSourceCompiles)
include(CheckCCompilerFlag)
include(CheckCXXSourceCompiles)
include(CheckCXXSymbolExists)
include(CheckCXXCompilerFlag)
include(CheckFunctionExists)
include(CheckTypeSize)
include(CheckIncludeFiles)
include(CheckIncludeFileCXX)

option(WITH_TESTS "Build tests" OFF)
option(BUILD_SHARED_LIBS "Build shared library" OFF)

set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH "Installation directory for libraries")
set(INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Installation directory for headers")
set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_PREFIX}/share/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")

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
	include/export
)

#set(JWTPP_INCLUDE_DIR ${EXPORT_INCLUDES} PARENT_SCOPE)

set(LIB_SOURCES
    src/tools.cpp
    src/claims.cpp
    src/crypto.cpp
    src/hmac.cpp
    src/rsa.cpp
    src/jws.cpp
   	src/b64.cpp
    src/header.cpp

    ${EXPORT_INCLUDES}/jwtpp/claims.hpp
    ${EXPORT_INCLUDES}/jwtpp/header.hpp
    ${EXPORT_INCLUDES}/jwtpp/crypto.hpp
    ${EXPORT_INCLUDES}/../tools/tools.hpp
)

include_directories(include)

add_library(${PROJECT_NAME}-static STATIC ${LIB_SOURCES})
set_target_properties(${PROJECT_NAME}-static PROPERTIES OUTPUT_NAME ${PROJECT_NAME} CLEAN_DIRECT_OUTPUT 1)

target_include_directories(
	${PROJECT_NAME}-static
	PUBLIC
	${EXPORT_INCLUDES}
	${JsonCPP_INCLUDE_DIRS}
)

target_link_libraries(
	${PROJECT_NAME}-static
	${OPENSSL_LIBRARIES}
	${JsonCPP_LIBRARIES}
)

install(
	TARGETS
	${PROJECT_NAME}-static
		ARCHIVE
			DESTINATION
				lib
)

if (BUILD_SHARED_LIBS)
	add_library(${PROJECT_NAME}-shared SHARED ${LIB_SOURCES})
	set_target_properties(${PROJECT_NAME}-shared PROPERTIES POSITION_INDEPENDENT_CODE TRUE)
	set_target_properties(${PROJECT_NAME}-shared PROPERTIES OUTPUT_NAME ${PROJECT_NAME} CLEAN_DIRECT_OUTPUT 1)
	target_include_directories(
		${PROJECT_NAME}-shared
		PUBLIC
		${EXPORT_INCLUDES}
		${JsonCPP_INCLUDE_DIRS}
	)

	target_link_libraries(
		${PROJECT_NAME}-shared
		${OPENSSL_LIBRARIES}
		${JsonCPP_LIBRARIES}
	)

	install(
		TARGETS
			${PROJECT_NAME}-shared
		LIBRARY
			DESTINATION
				lib
	)
endif()

install(
	DIRECTORY
	${EXPORT_INCLUDES}/jwtpp
	DESTINATION include
	FILES_MATCHING PATTERN "*.hpp"
)

set(JWTPP_PC ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc)

configure_file(
	pkgconfig.pc.in
	${JWTPP_PC}
	@ONLY
)

install(FILES ${JWTPP_PC} DESTINATION "${INSTALL_PKGCONFIG_DIR}")

if (WITH_TESTS)
	enable_testing()
	add_subdirectory(gtest EXCLUDE_FROM_ALL)

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


