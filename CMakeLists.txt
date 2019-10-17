cmake_minimum_required(VERSION 3.2)

project(josepp LANGUAGES C CXX)

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
option(WITH_INSTALL "Allow root targets to not issue install" ON)
option(BUILD_SHARED_LIBS "Build shared library" OFF)

set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH "Installation directory for libraries")
set(INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Installation directory for headers")
set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_PREFIX}/share/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")

find_package(OpenSSL REQUIRED)
if (NOT WIN32 AND NOT JsonCPP_FOUND)
	find_package(PkgConfig REQUIRED)
	pkg_check_modules(JsonCPP REQUIRED jsoncpp)
endif ()

include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})
include_directories(SYSTEM ${JsonCPP_INCLUDE_DIRS})
link_directories(${JsonCPP_LIBRARY_DIRS})

check_include_file_cxx(memory HAVE_MEMORY)
check_include_file_cxx(functional HAVE_FUNCTIONAL)
check_include_file_cxx(string HAVE_STRING)
check_include_file_cxx(vector HAVE_VECTOR)
check_include_file_cxx(mutex HAVE_MUTEX)
check_include_file_cxx(exception HAVE_EXCEPTION)
check_include_file_cxx(stdexcept HAVE_STDEXCEPT)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (NOT MSVC)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated")
endif ()

set(LIB_SOURCES
	src/b64.cpp
	src/claims.cpp
	src/crypto.cpp
	src/digest.cpp
	src/ecdsa.cpp
	src/header.cpp
	src/hmac.cpp
	src/jws.cpp
	src/rsa.cpp
	src/tools.cpp
	src/pss.cpp
	src/statics.cpp

	include/export/josepp/b64.hpp
	include/export/josepp/claims.hpp
	include/export/josepp/crypto.hpp
	include/export/josepp/digest.hpp
	include/export/josepp/header.hpp
	include/export/josepp/jws.hpp
	include/export/josepp/tools.hpp
	include/export/josepp/types.hpp
	include/export/josepp/sstring.hh
	include/local/josepp/statics.hh
)

add_library(${PROJECT_NAME}-static STATIC ${LIB_SOURCES})
set_target_properties(${PROJECT_NAME}-static PROPERTIES OUTPUT_NAME ${PROJECT_NAME} CLEAN_DIRECT_OUTPUT 1)

target_include_directories(
	${PROJECT_NAME}-static
	PUBLIC
		include/export
		${JsonCPP_INCLUDE_DIRS}
	PRIVATE
		include/local
)

target_link_libraries(
	${PROJECT_NAME}-static
	${OPENSSL_LIBRARIES}
	${JsonCPP_LIBRARIES}
)

if (WITH_INSTALL)
	install(
		TARGETS
			${PROJECT_NAME}-static
		ARCHIVE
		DESTINATION
			lib
	)
endif ()

if (BUILD_SHARED_LIBS)
	add_library(${PROJECT_NAME}-shared SHARED ${LIB_SOURCES})
	set_target_properties(${PROJECT_NAME}-shared PROPERTIES POSITION_INDEPENDENT_CODE TRUE)
	set_target_properties(${PROJECT_NAME}-shared PROPERTIES OUTPUT_NAME ${PROJECT_NAME} CLEAN_DIRECT_OUTPUT 1)
	target_include_directories(
		${PROJECT_NAME}-shared
		PUBLIC
			include/export
			${JsonCPP_INCLUDE_DIRS}
		PRIVATE
			include/local
	)

	target_link_libraries(
		${PROJECT_NAME}-shared
		PUBLIC
			${OPENSSL_LIBRARIES}
			${JsonCPP_LIBRARIES}
	)

	if (WITH_INSTALL)
		install(
			TARGETS
				${PROJECT_NAME}-shared
			LIBRARY
			DESTINATION
				lib
		)
	endif ()
endif ()

if (WITH_INSTALL)
	install(
		DIRECTORY
		include/export/josepp
		DESTINATION include
		FILES_MATCHING PATTERN "*.hpp"
	)
endif ()

set(JOSEPP_PC ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc)

if (WITH_INSTALL)
	configure_file(
		pkgconfig.pc.in
		${JOSEPP_PC}
		@ONLY
	)

	install(FILES ${JOSEPP_PC} DESTINATION "${INSTALL_PKGCONFIG_DIR}")
endif ()

if (WITH_TESTS)
	enable_testing()
	add_subdirectory(gtest EXCLUDE_FROM_ALL)

	include_directories(${PROJECT_SOURCE_DIR}/gtest/googletest/include)

	set(JOSEPP_TEST_SRS
		tests/b64.cpp
		tests/claims.cpp
		tests/ecdsa.cpp
		tests/hmac.cpp
		tests/rsa.cpp
		tests/pss.cpp
	)

	add_executable(josepp_test ${JOSEPP_TEST_SRS})

	if (WIN32)
		set(WIN32_DEP_LIBS crypt32.lib ws2_32.lib)
	endif (WIN32)

	target_link_libraries(
		josepp_test
		gtest_main
		${PROJECT_NAME}-static
		${WIN32_DEP_LIBS}
	)

	add_test(UnitTests josepp_test)
endif ()


