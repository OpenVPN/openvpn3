# ovpnserv exists to drive the integration tests below, so it follows
# test/unittests in dropping out entirely when testing is off -- the PGMT
# package build configures with -DBUILD_TESTING=OFF in an sbuild chroot that
# has neither jsoncpp nor libnl-genl-3.0, and add_json_library() below would
# fail the configure outright.
if (NOT BUILD_TESTING)
    return ()
endif ()

# Linux-only: needs <linux/if_tun.h>, openvpn/dco/*, sitnl.hpp, and
# libnl-genl-3.0, none of which exist on macOS/Android (both UNIX).
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(ovpnserv serv.cpp)
    add_core_dependencies(ovpnserv)
    add_json_library(ovpnserv)

    # Kernel DCO (see openvpn/server/dcoserv.hpp) is attempted opportunistically
    # at runtime, matching OpenVPN 2's own --disable-dco convention -- there is
    # no separate DCO/non-DCO build variant, so libnl-genl-3.0 and
    # ENABLE_OVPNDCO (which selects KoRekey::OvpnDcoKey in kocrypto.hpp) are
    # unconditional for this target, not opt-in the way CLI_OVPNDCO is for
    # ovpncli.
    target_compile_definitions(ovpnserv PRIVATE -DENABLE_OVPNDCO)
    find_package(PkgConfig)
    pkg_search_module(LIBNL REQUIRED libnl-genl-3.0)
    target_include_directories(ovpnserv PRIVATE ${LIBNL_INCLUDE_DIRS})
    target_link_libraries(ovpnserv ${LIBNL_LIBRARIES})

    # Real client-server integration tests, run via ctest alongside the unit
    # tests. Each self-skips (SKIP_RETURN_CODE 77) rather than failing when its
    # prerequisites (a binary built with the right option, root/CAP_NET_ADMIN,
    # the ovpn kernel module) aren't met -- see each script's own header.

    # One ctest entry per control-channel mode. The sequence is the same for
    # each; splitting them lets ctest run the three in parallel and names the
    # failing mode directly. Runtime is dominated by deliberate keepalive
    # timeouts (~34s per mode), so the timeout has headroom rather than being
    # tuned to a fast machine -- the whole-script form needs ~102s and used to
    # be declared at 60.
    foreach (cc_mode none tls-auth tls-crypt-v2)
        add_test(NAME ServerTunSinkIntegration-${cc_mode}
            COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/integration/test_server_tunsink.sh
                    ${PROJECT_BINARY_DIR} ${cc_mode})
        set_tests_properties(ServerTunSinkIntegration-${cc_mode} PROPERTIES
            SKIP_RETURN_CODE 77 TIMEOUT 180 LABELS "integration")
    endforeach ()

    # Client-to-client policy on the classic path, one entry per scenario.
    # deny-dco/allow-dco run the same policy assertions on the kernel DCO netdev
    # rather than the classic tun. Enforcement lives in netfilter (netpolicy.hpp)
    # and attaches to whichever netdev the active data path created, so these are
    # what demonstrate the policy is datapath-independent. They self-skip without
    # the ovpn module, and assert an ovpn-type netdev exists so a silent fallback
    # to the classic path cannot pass as a DCO run.
    foreach (c2c_mode deny allow spoof spoof-allow deny-dco allow-dco)
        add_test(NAME ServerC2CIntegration-${c2c_mode}
            COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/integration/test_server_c2c.sh
                    ${PROJECT_BINARY_DIR} ${c2c_mode})
        set_tests_properties(ServerC2CIntegration-${c2c_mode} PROPERTIES
            SKIP_RETURN_CODE 77 TIMEOUT 180 LABELS "integration;privileged")
    endforeach ()

    add_test(NAME ServerClassicIntegration
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/integration/test_server_classic.sh ${PROJECT_BINARY_DIR})
    set_tests_properties(ServerClassicIntegration PROPERTIES
        SKIP_RETURN_CODE 77 TIMEOUT 90 LABELS "integration;privileged")

    add_test(NAME ServerDcoIntegration
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/integration/test_server_dco.sh ${PROJECT_BINARY_DIR})
    set_tests_properties(ServerDcoIntegration PROPERTIES
        SKIP_RETURN_CODE 77 TIMEOUT 90 LABELS "integration;privileged")
endif ()
