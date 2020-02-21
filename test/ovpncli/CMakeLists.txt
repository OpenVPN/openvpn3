cmake_minimum_required(VERSION 3.5)
set(CMAKE_CXX_STANDARD 14)

include(findcoredeps)

option(CLI_NULLTUN "Build ovpncli variant with null tun" OFF)
option(CLI_DCO "Build ovpncli variant with Data Channel Offload (DCO) feature" OFF)

set(KOVPN_SOURCE "${CORE_DIR}/../kovpn" CACHE PATH "ovpn-dco kernel module source tree")

add_executable(ovpncli cli.cpp)

add_core_dependencies(ovpncli)

if (${CLI_NULLTUN})
    add_executable(ovpnclinull cli.cpp)
    add_core_dependencies(ovpnclinull)
    target_compile_definitions(ovpnclinull PRIVATE -DOPENVPN_FORCE_TUN_NULL)
endif ()

if (${CLI_DCO})
    include(kovpn)

    add_executable(ovpnclidco cli.cpp)
    add_core_dependencies(ovpnclidco)
    add_kovpn_dependency(ovpnclidco)
    target_include_directories(ovpnclidco PRIVATE ${KOVPN_SOURCE})
    target_compile_definitions(ovpnclidco PRIVATE -DENABLE_DCO)
endif ()

if (WIN32)
    # for macos, agent-enabled client requires common and is built by scripts there
    add_executable(ovpncliagent cli.cpp)
    add_core_dependencies(ovpncliagent)
    add_json_library(ovpncliagent)
    target_compile_definitions(ovpncliagent PRIVATE -DOPENVPN_COMMAND_AGENT -DOVPNAGENT_DISABLE_PATH_CHECK)
endif ()
