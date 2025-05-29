
option(CLI_NULLTUN "Build ovpncli variant with null tun" OFF)
option(CLI_KOVPN "Build ovpncli variant with kovpn kernel module support" OFF)
option(CLI_OVPNDCO "Build ovpncli with ovpn-dco kernel module support" OFF)
option(CLI_OVPNDCOWIN "Build ovpncli with ovpn-dco-win driver support" OFF)
option(CLI_TUNBUILDER "Build ovpncli with tunbuilder interface support" OFF)
option(CLI_SINGLETHREAD "Build ovpncli with single thread support" ON)

set(KOVPN_SOURCE "${CORE_DIR}/../kovpn" CACHE PATH "ovpn-dco kernel module source tree")

add_library(
        xkey
        ${CORE_DIR}/openvpn/openssl/xkey/xkey_helper.c
        ${CORE_DIR}/openvpn/openssl/xkey/xkey_provider.c
)

set(OVPNCLI_SOURCES src/main.cpp)
set(OVPNCLI_LIBS xkey ovpncliwrapper)


target_compile_definitions(xkey INTERFACE -DENABLE_EXTERNAL_PKI)
add_ssl_library(xkey)

add_library(openvpn_headers INTERFACE)
target_include_directories(openvpn_headers INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)


add_library(ovpncliwrapper STATIC src/ovpncli.cpp)
target_compile_definitions(ovpncliwrapper PUBLIC)
if (${CLI_SINGLETHREAD})
    target_compile_definitions(ovpncliwrapper PRIVATE -DOPENVPN_OVPNCLI_SINGLE_THREAD)
endif ()
add_core_dependencies(ovpncliwrapper)
add_library(openvpn3::ovpncliwrapper ALIAS ovpncliwrapper)
target_link_libraries(ovpncliwrapper openvpn_headers)



add_executable(ovpncli ${OVPNCLI_SOURCES})
target_compile_definitions(ovpncli PRIVATE)
target_link_libraries(ovpncli ${OVPNCLI_LIBS})

add_core_dependencies(ovpncli)

if (${CLI_NULLTUN})
    add_executable(ovpnclinull ${OVPNCLI_SOURCES})
    add_core_dependencies(ovpnclinull)
    target_compile_definitions(ovpnclinull PRIVATE -DOPENVPN_FORCE_TUN_NULL)
    target_link_libraries(ovpnclinull ${OVPNCLI_LIBS})
endif ()

if (${CLI_KOVPN})
    add_executable(ovpnclikovpn ${OVPNCLI_SOURCES})
    add_core_dependencies(ovpnclikovpn)
    target_link_libraries(ovpnclikovpn ${OVPNCLI_LIBS})

    target_compile_definitions(ovpnclikovpn PRIVATE -DENABLE_KOVPN
      -DOPENVPN_REMOTE_OVERRIDE -DPRIVATE_TUNNEL_PROXY)

    include(kovpn)
    add_kovpn_dependency(ovpnclikovpn)
    target_include_directories(ovpnclikovpn PRIVATE ${KOVPN_SOURCE})

endif()

if (${CLI_OVPNDCO})
    target_compile_definitions(ovpncli PRIVATE -DENABLE_OVPNDCO )

    find_package(PkgConfig)
    pkg_search_module(LIBNL REQUIRED libnl-genl-3.0)

    target_include_directories(ovpncli PRIVATE ${LIBNL_INCLUDE_DIRS})
    target_link_libraries(ovpncli ${LIBNL_LIBRARIES})
endif()

if (WIN32)
    add_executable(ovpncliagent ${OVPNCLI_SOURCES})
    add_core_dependencies(ovpncliagent)
    add_json_library(ovpncliagent)
    target_link_libraries(ovpncliagent ${OVPNCLI_LIBS})
    target_compile_definitions(ovpncliagent PRIVATE OPENVPN_COMMAND_AGENT
                                                    OVPNAGENT_DISABLE_PATH_CHECK)

    if (${CLI_OVPNDCOWIN})
        target_compile_definitions(ovpncliagent PRIVATE ENABLE_OVPNDCOWIN)
        target_compile_definitions(ovpncli PRIVATE ENABLE_OVPNDCOWIN)
        target_link_libraries(ovpncli "bcrypt.lib")
        target_link_libraries(ovpncliagent "bcrypt.lib")
    endif()
endif ()

if (APPLE)
    add_executable(ovpncliagent ${OVPNCLI_SOURCES})
    target_link_libraries(ovpncliagent ${OVPNCLI_LIBS})
    add_core_dependencies(ovpncliagent)
    add_json_library(ovpncliagent)
    target_compile_definitions(ovpncliagent PRIVATE -DOPENVPN_COMMAND_AGENT)
endif ()

if (${CLI_TUNBUILDER})
    target_compile_definitions(ovpncli PRIVATE USE_TUN_BUILDER)
endif ()
