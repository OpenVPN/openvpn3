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

#ifndef OPENVPN_SERVER_VPNSERVPOOL_H
#define OPENVPN_SERVER_VPNSERVPOOL_H

#include <sstream>
#include <vector>
#include <memory>
#include <mutex>
#include <thread>
#include <cstdint> // for std::uint32_t

#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/arraysize.hpp>
#include <openvpn/server/vpnservnetblock.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/addr/route.hpp>
#include <openvpn/addr/pool.hpp>

namespace openvpn {
  namespace VPNServerPool {

    OPENVPN_EXCEPTION(vpn_serv_pool_error);

    class Set;
    class IP46;

    enum Index {
      GENERAL_POOL=0,
      //OTHER_POOL,

      SIZE
    };

    inline const char *pool_name(const unsigned int i)
    {
      static const char *const names[] = {
	"server",
	//"other-pool",
      };

      static_assert(SIZE == array_size(names), "VPNServerPool::pool_name() size inconsistency");

      if (i < SIZE)
	return names[i];
      else
	return "UNDEF_POOL";
    }

    class Pool : public VPNServerNetblock
    {
    public:
      friend IP46;

      Pool(const OptionList& opt,
	   const std::string& opt_name,
	   const bool ipv4_optional)
	: VPNServerNetblock(opt, opt_name, ipv4_optional, 0)
      {
	pool4.add_range(netblock4().clients);
	pool6.add_range(netblock6().clients);
      }

    private:
      IP::Pool pool4;
      IP::Pool pool6;
    };

    class IP46
    {
    public:
      friend Set;

      enum Flags {
	IPv4_DEPLETION=(1<<0),
	IPv6_DEPLETION=(1<<1),
      };

      IP46()
	: pool_index(-1)
      {}

      void add_routes(std::vector<IP::Route>& rtvec,
		      const std::uint32_t mark)
      {
	if (ip4.defined())
	  rtvec.emplace_back(ip4, ip4.size(), mark);
	if (ip6.defined())
	  rtvec.emplace_back(ip6, ip6.size(), mark);
      }

      bool defined() const
      {
	return pool_index >= 0 && pool_index < SIZE;
      }

      std::string to_string() const
      {
	std::ostringstream os;
	os << '[' << ip4 << ' ' << ip6 << ']';
	return os.str();
      }

      IP::Addr ip4;
      IP::Addr ip6;

    private:
      // returns flags
      unsigned int acquire(Pool& pool, const unsigned int index)
      {
	unsigned int flags = 0;
	pool_index = index;
	if (!pool.pool4.acquire_addr(ip4))
	  flags |= IPv4_DEPLETION;
	if (pool.netblock6().defined())
	  {
	    if (!pool.pool6.acquire_addr(ip6))
	      flags |= IPv6_DEPLETION;
	  }
	return flags;
      }

      void release(Pool& pool)
      {
	if (ip4.defined())
	  pool.pool4.release_addr(ip4);
	if (ip6.defined())
	  pool.pool6.release_addr(ip6);
	pool_index = -1;
      }

      int pool_index;
    };

    class Set
    {
    public:
      Set(const OptionList& opt)
      {
	for (unsigned int i = 0; i < SIZE; ++i)
	  {
	    const std::string opt_name = pool_name(i);
	    const bool ipv4_optional = (i > 0);
	    if (VPNServerNetblock::configured(opt, opt_name, ipv4_optional))
	      pools.emplace_back(new Pool(opt, opt_name, ipv4_optional));
	    else
	      pools.emplace_back();
	  }
      }

      // returns IP46::Flags
      unsigned int acquire(IP46& ip46, const unsigned int index)
      {
	std::lock_guard<std::mutex> lock(mutex);
	if (index >= SIZE)
	  OPENVPN_THROW(vpn_serv_pool_error, "pool index=" << index << " is out of range (must be less than " << SIZE << ')');
	if (!pools[index])
	  OPENVPN_THROW(vpn_serv_pool_error, pool_name(index) << " IP address pool is undefined");
	return ip46.acquire(*pools[index], index);
      }

      void release(IP46& ip46)
      {
	std::lock_guard<std::mutex> lock(mutex);
	if (!ip46.defined())
	  return;
	if (!pools[ip46.pool_index])
	  return;
	ip46.release(*pools[ip46.pool_index]);
      }

      const VPNServerNetblock* snb(const IP46& ip46)
      {
	if (!ip46.defined())
	  return nullptr;
	return pools[ip46.pool_index].get();
      }

      const VPNServerNetblock* snb(const unsigned int index)
      {
	if (index >= SIZE)
	  return nullptr;
	return pools[index].get();
      }

    private:
      std::vector<std::unique_ptr<Pool>> pools; // size is always SIZE after construction
      std::mutex mutex;
    };

    class IP46AutoRelease : public IP46, public RC<thread_safe_refcount>
    {
    public:
      typedef RCPtr<IP46AutoRelease> Ptr;

      IP46AutoRelease(Set& set_arg)
	: set(set_arg)
      {
      }

      ~IP46AutoRelease()
      {
	set.release(*this);
      }

    private:
      Set& set;
    };
  }
}

#endif
