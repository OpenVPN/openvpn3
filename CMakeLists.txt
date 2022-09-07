cmake_minimum_required(VERSION 3.5)
cmake_policy(SET CMP0048 NEW)

project(OpenVPN3-core VERSION 3)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake
                      ${CMAKE_MODULE_PATH})
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 99)

include(findcoredeps)
include(ovpn-doxygen)

add_subdirectory(client)
add_subdirectory(test/unittests)
add_subdirectory(test/ovpncli)
add_subdirectory(test/ssl)


if (WIN32)
    add_subdirectory(openvpn/omi)
    add_subdirectory(openvpn/ovpnagent/win)
endif ()

if (APPLE)
    add_subdirectory(openvpn/ovpnagent/mac)
endif ()


if (ENABLE_DOXYGEN)
    # Exclude some project specific directories
    set(DOXYGEN_EXCLUDE_PATTERNS
        ${CMAKE_BINARY_DIR}/test/unittests/googletest-*
        ${PROJECT_SOURCE_DIR}/deps/*
        ${PROJECT_SOURCE_DIR}/test/unittests/googletest-*)

    # Use README.rst as the Doxygen main page
    # Due to some doxygen oddities, it rejects processing README.rst, but a .md file is fine
    # So we copy it into our build tree as a .md file and use that
    file(COPY "${CMAKE_SOURCE_DIR}/README.rst" DESTINATION "${CMAKE_BINARY_DIR}/doxygen")
    file(RENAME "${CMAKE_BINARY_DIR}/doxygen/README.rst" "${CMAKE_BINARY_DIR}/doxygen/mainpage.md")
    set(DOXYGEN_USE_MDFILE_AS_MAINPAGE "${CMAKE_BINARY_DIR}/doxygen/mainpage.md")

    configure_doxygen("OpenVPN 3 Core Library" "doxygen/core")
endif ()
