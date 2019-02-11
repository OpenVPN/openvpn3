cmake_minimum_required(VERSION 3.5)

project(tests)

# CMake is currently only used for the unit tests, so once we use CMAKE for more
# we should move parts of this file to a CMAKEFile higher up in the tree

set(CMAKE_CXX_STANDARD 14)

# We still depend on the normal instructions to build the dependencies

set(DEP_DIR ${O3_DIR}/deps CACHE PATH "Dependencies")


set(CORE_INCLUDES
        ../..
        ${DEP_DIR}/asio/asio/include
        )

set(CORE_TEST_DEFINES
        -DASIO_STANDALONE
        -DUSE_ASIO
        -DUSE_OPENSSL
        -DLZ4_DISABLE_DEPRECATE_WARNINGS
        -DOPENVPN_FORCE_TUN_NULL
        )

find_package(OpenSSL REQUIRED)

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
        )

target_link_libraries(coreUnitTests gtest_main)
target_include_directories(coreUnitTests PRIVATE ${CORE_INCLUDES})
target_compile_definitions(coreUnitTests PRIVATE ${CORE_TEST_DEFINES})
target_link_libraries(coreUnitTests gtest_main OpenSSL::SSL)

add_test(NAME CoreTests COMMAND coreUnitTests)
