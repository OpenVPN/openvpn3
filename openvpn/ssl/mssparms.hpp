//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
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
//    If not, see <http://www.gnu.org/licenses/>.

#ifndef OPENVPN_SSL_MSSPARMS_H
#define OPENVPN_SSL_MSSPARMS_H

#include <openvpn/common/options.hpp>
#include <openvpn/common/number.hpp>

namespace openvpn {
  struct MSSParms
  {
    MSSParms() : mssfix(0),
		 mtu(false)
    {
    }

    void parse(const OptionList& opt)
    {
      const Option *o = opt.get_ptr("mssfix");
      if (o)
	{
	  const bool status = parse_number_validate<unsigned int>(o->get(1, 16),
								  16,
								  576,
								  65535,
								  &mssfix);
	  if (!status)
	    throw option_error("mssfix: parse/range issue");
	  mtu = (o->get_optional(2, 16) == "mtu");
	}
    }

    unsigned int mssfix;  // standard OpenVPN mssfix parm
    bool mtu;             // consider transport packet overhead in MSS adjustment
  };
}

#endif
