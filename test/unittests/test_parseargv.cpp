#include "test_common.h"
#include <iostream>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/server/listenlist.hpp>

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

TEST(argv, parse) {
  const OptionList opt = OptionList::parse_from_argv_static(string::from_argv(sizeof(input)/sizeof(char *),
                                                                              const_cast<char **>(input), true));
  ASSERT_EQ(expected, opt.render(Option::RENDER_NUMBER | Option::RENDER_BRACKET));
}

static const char config[] =
    "listen 1.2.3.4 1000 tcp 2\n"
    "listen 0.0.0.0 4000 tcp 4*N\n"
    "listen ::0 8000 tcp\n"
    "listen sock/ststrack-%s.sock unix-stream\n";

TEST(argv, portoffset1) {
  const OptionList opt1 = OptionList::parse_from_config_static(config, nullptr);
  const Listen::List ll1(opt1, "listen", Listen::List::Nominal, 4);

  EXPECT_EQ(
      "listen 1.2.3.4 1000 TCPv4 2\nlisten 0.0.0.0 4000 TCPv4 16\nlisten ::0 8000 TCPv6 1\nlisten sock/ststrack-%s.sock UnixStream 1\n",
      ll1.to_string());

  std::string exp2("listen 1.2.3.4 1000 TCPv4 0\nlisten 1.2.3.4 1001 TCPv4 0\n");

  for (int i = 4000; i < 4016; i++)
    exp2 += "listen 0.0.0.0 " + std::to_string(i) + " TCPv4 0\n";

  exp2 += "listen ::0 8000 TCPv6 0\n"
          "listen sock/ststrack-0.sock UnixStream 0\n";

  const Listen::List ll2 = ll1.expand_ports_by_n_threads(100);
  EXPECT_EQ(exp2, ll2.to_string());
}

TEST(argv, portoffset2) {
  const OptionList opt = OptionList::parse_from_config_static(config, nullptr);
  const Listen::List ll(opt, "listen", Listen::List::Nominal, 4);
  for (unsigned int unit = 0; unit < 4; ++unit) {
    std::stringstream exp;
    exp << "listen 1.2.3.4 " << 1000 + unit << " TCPv4 0\n";;
    exp << "listen 0.0.0.0 400" << unit << " TCPv4 0\n";
    exp << "listen ::0 800" << unit << " TCPv6 0\n";
    exp << "listen sock/ststrack-" << unit << ".sock UnixStream 0\n";

    const Listen::List llu = ll.expand_ports_by_unit(unit);
    EXPECT_EQ(exp.str(), llu.to_string());
  }
}
