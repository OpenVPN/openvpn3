#include "test_common.h"
#include <iostream>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/options.hpp>

using namespace openvpn;

static std::string expected = "0 [errors-to-stderr] \n"
                              "1 [log] [/Library/Application Support/OpenVPN/log/ovpn3_yonan_net_p0977.log] \n"
                              "2 [config] [stdin] \n"
                              "3 [proto-force] [udp] \n"
                              "4 [management] [/Library/Application Support/OpenVPN/sock/ovpn-6QSai9SzvRcm.sock] [unix] \n"
                              "5 [setenv] [UV_ASCLI_VER] [2.0.18.200] \n"
                              "6 [setenv] [UV_PLAT_REL] [12.5.0] \n"
                              "7 [auth-nocache] \n"
                              "8 [management-hold] \n"
                              "9 [management-client] \n"
                              "10 [management-query-passwords] \n"
                              "11 [management-query-remote] \n"
                              "12 [management-up-down] \n"
                              "13 [management-client-user] [root] \n"
                              "14 [allow-pull-fqdn] \n"
                              "15 [auth-retry] [interact] \n"
                              "16 [push-peer-info] \n"
                              "17 [setenv] [UV_ASCLI_VER] [2.0.18.200] \n"
                              "18 [setenv] [UV_PLAT_REL] [12.5.0] \n";

static const char *input[] = {"unittest",
                              "--errors-to-stderr",
                              "--log", "/Library/Application Support/OpenVPN/log/ovpn3_yonan_net_p0977.log",
                              "--config", "stdin",
                              "--proto-force", "udp",
                              "--management", "/Library/Application Support/OpenVPN/sock/ovpn-6QSai9SzvRcm.sock",
                              "unix",
                              "--setenv", "UV_ASCLI_VER", "2.0.18.200",
                              "--setenv", "UV_PLAT_REL", "12.5.0", "--auth-nocache",
                              "--management-hold", "--management-client", "--management-query-passwords",
                              "--management-query-remote", "--management-up-down",
                              "--management-client-user", "root", "--allow-pull-fqdn",
                              "--auth-retry", "interact", "--push-peer-info", "--setenv",
                              "UV_ASCLI_VER", "2.0.18.200", "--setenv", "UV_PLAT_REL", "12.5.0"};

TEST(misc, parseargv){
  const OptionList opt = OptionList::parse_from_argv_static(string::from_argv(sizeof(input)/sizeof(char*),
                                                                              const_cast<char **>(input), true));
  ASSERT_EQ(expected, opt.render(Option::RENDER_NUMBER|Option::RENDER_BRACKET));
}
