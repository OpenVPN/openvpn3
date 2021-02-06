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

#include <openvpn/client/optfilt.hpp>

using namespace openvpn;

const std::string filtered_options(
  "ip-win32\n"
  "tap-sleep\n"
  "block-ipv6\n"
  "client-nat\n"
  "register-dns\n"

  "dhcp-renew\n"
  "dhcp-option\n"
  "dhcp-release\n"
  "dhcp-pre-release\n"

  "route\n"
  "route-ipv6\n"
  "route-delay\n"
  "route-metric\n"
  "route-method\n"

  "redirect-gateway\n"
  "redirect-private\n"
);

TEST(PushedOptionsFilter, RouteNopullEnabled)
{
  PushedOptionsFilter route_nopull_enabled(true);
  const std::string extra_option("unfiltered-option");
  OptionList src;
  OptionList dst;

  testLog->startCollecting();
  src.parse_from_config(filtered_options + extra_option, nullptr);
  dst.extend(src, &route_nopull_enabled);
  std::string filter_output(testLog->stopCollecting());

  ASSERT_EQ(1, dst.size())
    << "Too few options have been filtered by --route-nopull" << std::endl
    << filter_output;

  dst.update_map();
  ASSERT_TRUE(dst.exists(extra_option))
    << "The wrong options have been filtered by --route-nopull:" << std::endl
    << "expected: " << extra_option << " got: " << dst[0].get(0, 0) << std::endl
    << filter_output;
}

TEST(PushedOptionsFilter, RouteNopullDisabled)
{
  PushedOptionsFilter route_nopull_disabled(false);
  const std::string extra_option("unfiltered-option");
  OptionList src;
  OptionList dst;

  testLog->startCollecting();
  src.parse_from_config(filtered_options + extra_option, nullptr);
  dst.extend(src, &route_nopull_disabled);
  std::string filter_output(testLog->stopCollecting());

  ASSERT_EQ(src.size(), dst.size())
    << "Too many options have been filtered by --route-nopull" << std::endl
    << filter_output;
}
