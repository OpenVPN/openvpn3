//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2021 OpenVPN Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.

#include "test_common.h"

#include <openvpn/client/remotelist.hpp>

using namespace openvpn;

TEST(RemoteList, RemoteRandomHostname)
{
  OptionList cfg;
  cfg.parse_from_config(
    "remote-random-hostname\n"
    "remote 1.1.1.1\n"
    "remote 2.domain.invalid\n"
    "<connection>\n"
    "  remote 3.domain.invalid\n"
    "</connection>\n"
    "<connection>\n"
    "  remote 4:cafe::1\n"
    "</connection>\n"
    , nullptr);
  cfg.update_map();

  RandomAPI::Ptr rng(new FakeSecureRand(0xf7));
  RemoteList rl(cfg, "", 0, nullptr, rng);

  ASSERT_EQ(rl.size(), 4);
  ASSERT_EQ(rl.get_item(0).actual_host(), "1.1.1.1");
  ASSERT_EQ(rl.get_item(1).actual_host(), "f7f8f9fafbfc.2.domain.invalid");
  ASSERT_EQ(rl.get_item(2).actual_host(), "fdfeff000102.3.domain.invalid");
  ASSERT_EQ(rl.get_item(3).actual_host(), "4:cafe::1");
}

TEST(RemoteList, RemoteRandomHostnameNoPRNG)
{
  OptionList cfg;
  cfg.parse_from_config(
    "remote-random-hostname\n"
    "remote domain.invalid\n"
    , nullptr);
  cfg.update_map();

  ASSERT_THROW(RemoteList(cfg, "", 0, nullptr), RemoteList::remote_list_error);
}
