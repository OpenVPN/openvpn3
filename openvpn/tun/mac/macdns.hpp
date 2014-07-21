//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
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

// DNS utilities for Mac OS X.

#ifndef OPENVPN_TUN_MAC_MACDNS_H
#define OPENVPN_TUN_MAC_MACDNS_H

#include <string>
#include <sstream>

#include <boost/algorithm/string.hpp> // for boost::algorithm::starts_with

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/common/process.hpp>
#include <openvpn/apple/macver.hpp>
#include <openvpn/apple/scdynstore.hpp>
#include <openvpn/applecrypto/cf/cfhelper.hpp>
#include <openvpn/tun/builder/capture.hpp>

namespace openvpn {
  class MacDNS : public RC<thread_unsafe_refcount>
  {
    class Info;

  public:
    typedef boost::intrusive_ptr<MacDNS> Ptr;

    OPENVPN_EXCEPTION(macdns_error);

    class Config : public RC<thread_safe_refcount>
    {
    public:
      typedef boost::intrusive_ptr<Config> Ptr;

      Config()
	: redirect_gateway(false),
	  reroute_dns_partial(false),
	  search_order(0)
      {
      }

      Config(const TunBuilderCapture& settings)
	: redirect_gateway(settings.reroute_gw.ipv4),
	  reroute_dns_partial(false),
	  search_order(0),
	  dns_servers(get_dns_servers(settings)),
	  search_domains(get_search_domains(settings))
      {
      }

      static Config::Ptr block(const Config* orig)
      {
	Config::Ptr ret;
	if (orig && orig->redirect_gateway_setting())
	  {
	    ret.reset(new Config);

	    ret->redirect_gateway = orig->redirect_gateway;
	    ret->reroute_dns_partial = orig->reroute_dns_partial;
	    ret->search_order = orig->search_order;

	    {
	      CF::MutableArray a(CF::mutable_array());
	      CF::array_append_str(a, "127.0.0.1");
	      ret->dns_servers = CF::const_array(a);
	    }
	  }
	return ret;
      }

      bool redirect_gateway_setting() const
      {
	bool rg = redirect_gateway;
	if (reroute_dns_partial && rg && search_domains.defined())
	  rg = false;
	return rg;
      }

      std::string to_string() const
      {
	std::ostringstream os;
	os << "rg=" << redirect_gateway;
	os << " rdp=" << reroute_dns_partial;
	os << " so=" << search_order;
	os << " dns=" << CF::array_to_string(dns_servers);
	os << " dom=" << CF::array_to_string(search_domains);
	return os.str();
      }

      bool redirect_gateway;
      bool reroute_dns_partial;
      int search_order;
      CF::Array dns_servers;
      CF::Array search_domains;

    private:
      static CF::Array get_dns_servers(const TunBuilderCapture& settings)
      {
	CF::MutableArray ret(CF::mutable_array());
	for (std::vector<TunBuilderCapture::DNSServer>::const_iterator i = settings.dns_servers.begin();
	     i != settings.dns_servers.end(); ++i)
	  {
	    const TunBuilderCapture::DNSServer& ds = *i;
	    CF::array_append_str(ret, ds.address);
	  }
	return CF::const_array(ret);
      }

      static CF::Array get_search_domains(const TunBuilderCapture& settings)
      {
	CF::MutableArray ret(CF::mutable_array());
	for (std::vector<TunBuilderCapture::SearchDomain>::const_iterator i = settings.search_domains.begin();
	     i != settings.search_domains.end(); ++i)
	  {
	    const TunBuilderCapture::SearchDomain& sd = *i;
	    CF::array_append_str(ret, sd.domain);
	  }
	return CF::const_array(ret);
      }
    };

    MacDNS(const std::string& sname_arg)
      : sname(sname_arg)
    {
    }

    void flush_cache()
    {
      const int v = ver.major();
      if (v < Mac::Version::OSX_10_6)
	OPENVPN_LOG("MacDNS: Error: No support for Mac OS X versions earlier than 10.6");
      if (v == Mac::Version::OSX_10_6 || v >= Mac::Version::OSX_10_9)
	{
	  Argv args;
	  args.push_back("/usr/bin/dscacheutil");
	  args.push_back("-flushcache");
	  OPENVPN_LOG(args.to_string());
	  system_cmd(args);
	}
      if (v >= Mac::Version::OSX_10_7)
	{
	  Argv args;
	  args.push_back("/usr/bin/killall");
	  args.push_back("-HUP");
	  args.push_back("mDNSResponder");
	  OPENVPN_LOG(args.to_string());
	  system_cmd(args);
	}
    }

    bool signal_network_reconfiguration()
    {
      const char *key = "Setup:/Network/Global/IPv4";
      CF::DynamicStore sc = ds_create();
      const CF::String cfkey = CF::string(key);
      OPENVPN_LOG("MacDNS: SCDynamicStoreNotifyValue " << key);
      return bool(SCDynamicStoreNotifyValue(sc(), cfkey()));
    }

    bool setdns(const Config& config)
    {
      bool mod = false;

      try {
	const bool redirect_gateway = config.redirect_gateway_setting();

	int search_order = config.search_order;
	if (!search_order)
	  search_order = 5000;

	CF::DynamicStore sc = ds_create();
	Info::Ptr info(new Info(sc, sname));

	// cleanup settings applied to previous interface
	interface_change_cleanup(info.get());

	if (redirect_gateway)
	  {
	    info->dns.will_modify();

	    // set DNS servers
	    if (CF::array_len(config.dns_servers))
	      {
		info->dns.backup_orig("ServerAddresses");
		CF::dict_set_obj(info->dns.mod, "ServerAddresses", config.dns_servers());
	      }

	    // set search domains
	    info->dns.backup_orig("SearchDomains");
	    if (CF::array_len(config.search_domains))
	      CF::dict_set_obj(info->dns.mod, "SearchDomains", config.search_domains());

	    // set search order
	    info->dns.backup_orig("SearchOrder");
	    CF::dict_set_int(info->dns.mod, "SearchOrder", search_order);

	    // push it
	    mod |= info->dns.push_to_store();
	  }
	else
	  {
	    info->ovpn.mod_reset();
	    if (CF::array_len(config.dns_servers) && CF::array_len(config.search_domains))
	      {
		// set DNS servers
		CF::dict_set_obj(info->ovpn.mod, "ServerAddresses", config.dns_servers());

		// set search domains, reverse domains can be added here as well
		CF::dict_set_obj(info->ovpn.mod, "SupplementalMatchDomains", config.search_domains());
	      }

	    // push it
	    mod |= info->ovpn.push_to_store();
	  }

	if (mod)
	  {
            // As a backup, save PrimaryService in private dict (if network goes down while
            // we are set, we can lose info about PrimaryService in State:/Network/Global/IPv4
            // and be unable to reset ourselves).
	    const CFTypeRef ps = CF::dict_get_obj(info->ipv4.dict, "PrimaryService");
	    if (ps)
	      {
		info->info.mod_reset();
		CF::dict_set_obj(info->info.mod, "PrimaryService", ps);
		info->info.push_to_store();
	      }
	  }

	prev = info;
	if (mod)
	  OPENVPN_LOG("MacDNS: SETDNS " << ver.to_string() << std::endl << info->to_string());
      }
      catch (const std::exception& e)
	{
	  OPENVPN_LOG("MacDNS: setdns: " << e.what());
	}
      return mod;
    }

    bool resetdns()
    {
      bool mod = false;
      try {
	CF::DynamicStore sc = ds_create();
	Info::Ptr info(new Info(sc, sname));

	// cleanup settings applied to previous interface
	interface_change_cleanup(info.get());

	// undo primary dns changes
	mod |= reset_primary_dns(info.get());

	// undo non-redirect-gateway changes
	if (CF::dict_len(info->ovpn.dict))
	  mod |= info->ovpn.remove_from_store();

	// remove private info dict
	if (CF::dict_len(info->info.dict))
	  mod |= info->info.remove_from_store();

	if (mod)
	  OPENVPN_LOG("MacDNS: RESETDNS " << ver.to_string() << std::endl << info->to_string());
      }
      catch (const std::exception& e)
	{
	  OPENVPN_LOG("MacDNS: resetdns: " << e.what());
	}
      return mod;
    }

    std::string to_string() const
    {
      CF::DynamicStore sc = ds_create();
      Info::Ptr info(new Info(sc, sname));
      return info->to_string();
    }

    CF::Array dskey_array() const
    {
      CF::DynamicStore sc = ds_create();
      Info::Ptr info(new Info(sc, sname));
      CF::MutableArray ret(CF::mutable_array());
      CF::array_append_str(ret, info->ipv4.dskey);
      CF::array_append_str(ret, info->info.dskey);
      CF::array_append_str(ret, info->ovpn.dskey);
      CF::array_append_str(ret, info->dns.dskey);
      return CF::const_array(ret);
    }

  private:
    void interface_change_cleanup(Info* info)
    {
      if (info->interface_change(prev.get()))
	{
	  reset_primary_dns(prev.get());
	  prev.reset();
	}
    }

    bool reset_primary_dns(Info* info)
    {
      bool mod = false;
      if (info)
	{
	  if (ver.major() < Mac::Version::OSX_10_8)
	    {
	      // Mac OS X 10.7 and lower.
	      //
	      // We want to avoid executing this code block on OS X 10.8+
	      // because it might cause our VPN DNS settings to persist after
	      // disconnect.  Conversely, for 10.7 and earlier, we should
	      // execute this code to prevent our VPN DNS settings from
	      // persisting after disconnect.
	      info->dns.will_modify();
	      info->dns.restore_orig();
	      mod |= info->dns.push_to_store();
	    }
	  else
	    {
	      // Mac OS X 10.8 and higher
	      info->dns.mod_reset();
	      mod |= info->dns.push_to_store();
	    }
	}
      return mod;
    }

    class DSDict {
    public:
      DSDict(CF::DynamicStore& sc_arg, const std::string& sname_arg, const std::string& dskey_arg)
	: sc(sc_arg),
	  sname(sname_arg),
	  dskey(dskey_arg),
	  dict(CF::DynamicStoreCopyDict(sc_arg, dskey))
      {
      }

      bool dirty() const
      {
	return mod.defined() ? !CFEqual(dict(), mod()) : false;
      }

      bool push_to_store()
      {
	if (dirty())
	  {
	    const CF::String keystr = CF::string(dskey);
	    if (SCDynamicStoreSetValue(sc(), keystr(), mod()))
	      {
		OPENVPN_LOG("MacDNS: updated " << dskey);
		return true;
	      }
	    else
	      OPENVPN_LOG("MacDNS: ERROR updating " << dskey);
	  }
	return false;
      }

      bool remove_from_store()
      {
	if (dirty())
	  throw macdns_error("internal error: remove_from_store called on modified dict");
	const CF::String keystr = CF::string(dskey);
	if (SCDynamicStoreRemoveValue(sc(), keystr()))
	  {
	    OPENVPN_LOG("MacDNS: removed " << dskey);
	    return true;
	  }
	else
	  {
	    OPENVPN_LOG("MacDNS: ERROR removing " << dskey);
	    return false;
	  }
      }

      void will_modify()
      {
	if (!mod.defined())
	  mod = CF::mutable_dict_copy(dict);
      }

      void mod_reset()
      {
	mod = CF::mutable_dict();
      }

      void backup_orig(const std::string& key, const bool wipe_orig=true)
      {
	const CF::String k = CF::string(key);
	const CF::String orig = orig_key(key);
	if (!CFDictionaryContainsKey(dict(), orig()))
	  {
	    const CF::String delval = delete_value();
	    CFTypeRef v = CFDictionaryGetValue(dict(), k());
	    if (!v)
	      v = delval();
	    will_modify();
	    CFDictionarySetValue(mod(), orig(), v);
	  }
	if (wipe_orig)
	  {
	    will_modify();
	    CFDictionaryRemoveValue(mod(), k());
	  }
      }

      void restore_orig()
      {
	const CFIndex size = CFDictionaryGetCount(dict());
	ScopedPtr<const void *, PtrArrayFree> keys(new const void *[size]);
	ScopedPtr<const void *, PtrArrayFree> values(new const void *[size]);
	CFDictionaryGetKeysAndValues(dict(), keys(), values());
	const CF::String orig_prefix = orig_key("");
	const CFIndex orig_prefix_len = CFStringGetLength(orig_prefix());
	const CF::String delval = delete_value();
	for (CFIndex i = 0; i < size; ++i)
	  {
	    const CF::String key = CF::string_cast(keys()[i]);
	    if (CFStringHasPrefix(key(), orig_prefix()))
	      {
		const CFIndex key_len = CFStringGetLength(key());
		if (key_len > orig_prefix_len)
		  {
		    const CFRange r = CFRangeMake(orig_prefix_len, key_len - orig_prefix_len);
		    const CF::String k(CFStringCreateWithSubstring(kCFAllocatorDefault, key(), r));
		    const CFTypeRef v = values()[i];
		    const CF::String vstr = CF::string_cast(v);
		    will_modify();
		    if (vstr.defined() && CFStringCompare(vstr(), delval(), 0) == kCFCompareEqualTo)
		      CFDictionaryRemoveValue(mod(), k());
		    else
		      CFDictionaryReplaceValue(mod(), k(), v);
		    CFDictionaryRemoveValue(mod(), key());
		  }
	      }
	  }
      }

      std::string to_string() const
      {
	std::ostringstream os;
	os << "*** DSDict " << dskey << std::endl;
	std::string orig = CF::description(dict());
	string::trim_crlf(orig);
	os << "ORIG " << orig << std::endl;
	if (dirty())
	  {
	    std::string modstr = CF::description(mod());
	    string::trim_crlf(modstr);
	    os << "MODIFIED " << modstr << std::endl;
	  }
	return os.str();
      }

      CF::DynamicStore sc;
      const std::string sname;
      const std::string dskey;
      const CF::Dict dict;
      CF::MutableDict mod;

    private:
      CF::String orig_key(const std::string& key) const
      {
	return CF::string(sname + "Orig" + key);
      }

      CF::String delete_value() const
      {
	return CF::string(sname + "DeleteValue");
      }
    };

    class Info : public RC<thread_unsafe_refcount>
    {
    public:
      typedef boost::intrusive_ptr<Info> Ptr;

      Info(CF::DynamicStore& sc, const std::string& sname)
	: ipv4(sc, sname, "State:/Network/Global/IPv4"),
	  info(sc, sname, "State:/Network/Service/" + sname + "/Info"),
	  ovpn(sc, sname, "State:/Network/Service/" + sname + "/DNS"),
	  dns(sc, sname, primary_dns(ipv4.dict, info.dict))
      {
      }

      std::string to_string() const
      {
	std::ostringstream os;
	os << ipv4.to_string();
	os << info.to_string();
	os << ovpn.to_string();
	os << dns.to_string();
	return os.str();
      }

      bool interface_change(Info* other) const
      {
	return other && dns.dskey != other->dns.dskey;
      }

      DSDict ipv4;
      DSDict info; // we may modify
      DSDict ovpn; // we may modify
      DSDict dns;  // we may modify

    private:
      static std::string primary_dns(const CF::Dict& ipv4, const CF::Dict& info)
      {
	std::string serv = CF::dict_get_str(ipv4, "PrimaryService");
	if (serv.empty())
	  serv = CF::dict_get_str(info, "PrimaryService");
	if (serv.empty())
	  throw macdns_error("no primary service");
	return "Setup:/Network/Service/" + serv + "/DNS";
      }
    };

    CF::DynamicStore ds_create() const
    {
      CF::String sn = CF::string(sname);
      return CF::DynamicStore(SCDynamicStoreCreate(kCFAllocatorDefault, sn(), NULL, NULL));
    }

    const std::string sname;
    Mac::Version ver;
    Info::Ptr prev;
  };
}

#endif
