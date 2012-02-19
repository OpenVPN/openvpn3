#ifndef OPENVPN_OPTIONS_RGOPT_H
#define OPENVPN_OPTIONS_RGOPT_H

#include <openvpn/common/options.hpp>

namespace openvpn {
  class RedirectGatewayFlags {
  public:
    enum Flags {
      RG_ENABLE      = (1<<0),
      RG_REROUTE_GW  = (1<<1),
      RG_LOCAL       = (1<<2),
      RG_AUTO_LOCAL  = (1<<3),
      RG_DEF1        = (1<<4),
      RG_BYPASS_DHCP = (1<<5),
      RG_BYPASS_DNS  = (1<<6),
      RG_BLOCK_LOCAL = (1<<7),
    };

    RedirectGatewayFlags() : flags_(0) {}

    explicit RedirectGatewayFlags(const OptionList& opt)
    {
      init(opt);
    }

    void init(const OptionList& opt)
    {
      flags_ = 0;

      OptionList::IndexMap::const_iterator rg = opt.map().find("redirect-gateway");
      if (rg != opt.map().end())
	add_flags(opt, rg->second, true);
      else
	{
	  OptionList::IndexMap::const_iterator rp = opt.map().find("redirect-private");
	  if (rp != opt.map().end())
	    add_flags(opt, rp->second, false);
	}
    }

    unsigned int operator()() const { return flags_; }

    bool redirect_gateway_enabled() const
    {
      return (flags_ & (RG_ENABLE|RG_REROUTE_GW)) == (RG_ENABLE|RG_REROUTE_GW);
    }

  private:
    void add_flags(const OptionList& opt, const OptionList::IndexList& idx, const bool redirect_gateway)
    {
      flags_ |= RG_ENABLE;
      if (redirect_gateway)
	flags_ |= RG_REROUTE_GW;
      for (OptionList::IndexList::const_iterator i = idx.begin(); i != idx.end(); i++)
	{
	  const Option& o = opt[*i];
	  for (size_t j = 1; j < o.size(); ++j)
	    {
	      const std::string& f = o[j];
	      if (f == "local")
		flags_ |= RG_LOCAL;		
	      else if (f == "autolocal")
		flags_ |= RG_AUTO_LOCAL;		
	      else if (f == "def1")
		flags_ |= RG_DEF1;
	      else if (f == "bypass-dhcp")
		flags_ |= RG_BYPASS_DHCP;
	      else if (f == "bypass-dns")
		flags_ |= RG_BYPASS_DNS;
	      else if (f == "block_local")
		flags_ |= RG_BLOCK_LOCAL;
	    }
	}
    }

    unsigned int flags_;
  };
}

#endif
