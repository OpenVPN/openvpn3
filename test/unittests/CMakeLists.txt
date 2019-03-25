cmake_minimum_required(VERSION 3.5)

project(tests)

# CMake is currently only used for the unit tests, so once we use CMAKE for more
# we should move parts of this file to a CMAKEFile higher up in the tree

set(CMAKE_CXX_STANDARD 14)

# We still depend on the normal instructions to build the dependencies

set(DEP_DIR ${O3_DIR}/deps CACHE PATH "Dependencies")
option(USE_MBEDTLS "Use mbed TLS instead of OpenSSL")

# For the mbedtls cmake script
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake;${CMAKE_MODULE_PATH}")

# Include our DEP_DIR in path used to find libraries

if (APPLE)
    set(PLAT osx)
elseif(WIN32)
    set(PLAT amd64)
else()
    set(PLAT linux)
endif()

set(CORE_INCLUDES
        ../..
        ${DEP_DIR}/asio/asio/include
        )
set(CORE_TEST_DEFINES
        -DASIO_STANDALONE
        -DUSE_ASIO
        -DHAVE_LZ4
        -DLZ4_DISABLE_DEPRECATE_WARNINGS
        -DOPENVPN_FORCE_TUN_NULL
        -DMBEDTLS_DEPRECATED_REMOVED
        -DUNIT_TEST
        -DUNITTEST_SOURCE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}/\"
        )

if (WIN32)
    list (APPEND CMAKE_PREFIX_PATH
            ${DEP_DIR}/${PLAT}/mbedtls
            ${DEP_DIR}/${PLAT}/lz4/lib
            )
    list (APPEND CMAKE_LIBRARY_PATH
            ${DEP_DIR}/${PLAT}/mbedtls/library
            )
    list (APPEND CORE_INCLUDES
            ${DEP_DIR}/${PLAT}/asio/asio/include
            ${DEP_DIR}/${PLAT}/lz4/lz4/include
            ${DEP_DIR}/${PLAT}/tap-windows/src
            )
    list (APPEND CORE_TEST_DEFINES
            -DTAP_WIN_COMPONENT_ID=tap0901
            -D_CRT_SECURE_NO_WARNINGS
            )
    set (EXTRA_LIBS fwpuclnt.lib Iphlpapi.lib)
else()
    list (APPEND CMAKE_PREFIX_PATH
            ${DEP_DIR}/mbedtls/mbedtls-${PLAT}
            ${DEP_DIR}/lz4/lz4-${PLAT}
            )
    list (APPEND CMAKE_LIBRARY_PATH
            ${DEP_DIR}/mbedtls/mbedtls-${PLAT}/library
            )
endif()



if (${USE_MBEDTLS})
    find_package(mbedTLS REQUIRED)

    set(SSL_LIBRARY ${MBEDTLS_LIBRARIES})

    list(APPEND CORE_TEST_DEFINES -DUSE_MBEDTLS)

    # The findmbedTLS does not set these automatically :(
    list(APPEND CORE_INCLUDES ${MBEDTLS_INCLUDE_DIR})

else()
    find_package(OpenSSL REQUIRED)
    SET(SSL_LIBRARY OpenSSL::SSL)
    list(APPEND CORE_TEST_DEFINES -DUSE_OPENSSL)
endif()

FIND_PATH(LZO_INCLUDE_DIR NAMES lzo/lzo1x.h)
FIND_LIBRARY(LZO_LIBRARIES NAMES lzo2)

find_package(LZ4 REQUIRED)
list(APPEND CORE_INCLUDES ${LZ4_INCLUDE_DIR})


if (LZO_INCLUDE_DIR AND LZO_LIBRARIES)
    list(APPEND CORE_TEST_DEFINES -DHAVE_LZO)
    list(APPEND EXTRA_LIBS ${LZO_LIBRARIES})
    list(APPEND CORE_INCLUDES ${LZO_INCLUDE_DIR})
    message("lzo found, running lzo compression tests")
else()
    message("lzo not found, skipping lzo compression tests")
endif()

# Google Test Unit testing
# Download and unpack googletest at configure time
configure_file(CMakeLists.txt.in googletest-download/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
if(result)
    message(FATAL_ERROR "CMake step for googletest failed: ${result}")
endif()
execute_process(COMMAND ${CMAKE_COMMAND} --build .
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
if(result)
    message(FATAL_ERROR "Build step for googletest failed: ${result}")
endif()

# Prevent overriding the parent project's compiler/linker
# settings on Windows
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

# Add googletest directly to our build. This defines
# the gtest and gtest_main targets.
add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/googletest-src
        ${CMAKE_CURRENT_BINARY_DIR}/googletest-build
        EXCLUDE_FROM_ALL)



add_executable(coreUnitTests
        core_tests.cpp
        test_route_emulation.cpp
        test_log.cpp
        test_comp.cpp
        test_b64.cpp
        )

target_link_libraries(coreUnitTests gtest_main)
target_include_directories(coreUnitTests PRIVATE ${CORE_INCLUDES})
target_compile_definitions(coreUnitTests PRIVATE ${CORE_TEST_DEFINES})
target_link_libraries(coreUnitTests gtest_main ${SSL_LIBRARY} ${EXTRA_LIBS} ${LZ4_LIBRARY})

add_test(NAME CoreTests COMMAND coreUnitTests)
