//
//  tunutil.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

// tun interface utilities for Windows

#ifndef OPENVPN_TUN_WIN_TUNUTIL_H
#define OPENVPN_TUN_WIN_TUNUTIL_H

#include <windows.h>
#include <winsock2.h> // for IPv6
#include <winioctl.h>
#include <iphlpapi.h>
#include <ntddndis.h>
#include <wininet.h>
#include <ws2tcpip.h> // for IPv6

#include <string>
#include <vector>
#include <sstream>

#include <boost/cstdint.hpp> // for boost::uint32_t

#include <tap-windows.h>

#include <openvpn/common/format.hpp>
#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/socktypes.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/stringize.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/common/action.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/win/reg.hpp>
#include <openvpn/win/scoped_handle.hpp>
#include <openvpn/win/unicode.hpp>

namespace openvpn {
  namespace TunWin {
    namespace Util {
      OPENVPN_EXCEPTION(tun_win_util);

      // from tap-windows.h
      static const char ADAPTER[] = ADAPTER_KEY; // CONST GLOBAL
      static const char NETWORK_CONNECTIONS[] = NETWORK_CONNECTIONS_KEY; // CONST GLOBAL

      // generally defined on cl command line
      static const char COMPONENT_ID[] = OPENVPN_STRINGIZE(TAP_WIN_COMPONENT_ID); // CONST GLOBAL

      // Return a list of TAP device GUIDs installed on the system,
      // filtered by TAP_WIN_COMPONENT_ID.
      inline std::vector<std::string> tap_guids()
      {
	LONG status;
	DWORD len;
	DWORD data_type;

	std::vector<std::string> ret;

	Win::RegKey adapter_key;
	status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
			      ADAPTER,
			      0,
			      KEY_READ,
			      adapter_key.ref());
	if (status != ERROR_SUCCESS)
	  OPENVPN_THROW(tun_win_util, "tap_guids: error opening adapter registry key: " << ADAPTER);

	for (int i = 0;; ++i)
	  {
	    char strbuf[256];
	    Win::RegKey unit_key;

	    len = sizeof(strbuf);
	    status = RegEnumKeyEx(adapter_key(),
				  i,
				  strbuf,
				  &len,
				  NULL,
				  NULL,
				  NULL,
				  NULL);
	    if (status == ERROR_NO_MORE_ITEMS)
	      break;
	    else if (status != ERROR_SUCCESS)
	      OPENVPN_THROW(tun_win_util, "tap_guids: error enumerating registry subkeys of key: " << ADAPTER);
	    strbuf[len] = '\0';

	    const std::string unit_string = std::string(ADAPTER)
	                                  + std::string("\\")
	                                  + std::string(strbuf);

	    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
				  unit_string.c_str(),
				  0,
				  KEY_READ,
				  unit_key.ref());

	    if (status != ERROR_SUCCESS)
	      continue;

	    len = sizeof(strbuf);
	    status = RegQueryValueEx(unit_key(),
				     "ComponentId",
				     NULL,
				     &data_type,
				     (LPBYTE)strbuf,
				     &len);

	    if (status != ERROR_SUCCESS || data_type != REG_SZ)
	      continue;
	    strbuf[len] = '\0';
	    if (std::strcmp(strbuf, COMPONENT_ID))
	      continue;

	    len = sizeof(strbuf);
	    status = RegQueryValueEx(unit_key(),
				     "NetCfgInstanceId",
				     NULL,
				     &data_type,
				     (LPBYTE)strbuf,
				     &len);

	    if (status == ERROR_SUCCESS && data_type == REG_SZ)
	      {
		strbuf[len] = '\0';
		ret.push_back(std::string(strbuf));
	      }
	  }
	return ret;
      }

      struct TapNameGuidPair
      {
	TapNameGuidPair() : index(DWORD(-1)) {}

	bool index_defined() const { return index != DWORD(-1); }

	std::string index_or_name() const
	{
	  if (index_defined())
	    return to_string(index);
	  else if (!name.empty())
	    return '"' + name + '"';
	  else
	    OPENVPN_THROW(tun_win_util, "TapNameGuidPair: TAP interface " << guid << " has no name or interface index");
	}

	std::string name;
	std::string guid;
	DWORD index;
      };

      struct TapNameGuidPairList : public std::vector<TapNameGuidPair>
      {
	TapNameGuidPairList()
	{
	  // first get the TAP guids
	  {
	    std::vector<std::string> guids = tap_guids();
	    for (std::vector<std::string>::const_iterator i = guids.begin(); i != guids.end(); i++)
	      {
		TapNameGuidPair pair;
		pair.guid = *i;

		// lookup adapter index
		{
		  ULONG aindex;
		  const size_t len = 128;
		  wchar_t wbuf[len];
		  _snwprintf(wbuf, len, L"\\DEVICE\\TCPIP_%S", pair.guid.c_str());
		  wbuf[len-1] = 0;
		  if (GetAdapterIndex(wbuf, &aindex) == NO_ERROR)
		    pair.index = aindex;
		}

		push_back(pair);
	      }
	  }

	  // next, match up control panel interface names with GUIDs
	  {
	    LONG status;
	    DWORD len;
	    DWORD data_type;

	    Win::RegKey network_connections_key;
	    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
				  NETWORK_CONNECTIONS,
				  0,
				  KEY_READ,
				  network_connections_key.ref());
	    if (status != ERROR_SUCCESS)
	      OPENVPN_THROW(tun_win_util, "TapNameGuidPairList: error opening network connections registry key: " << NETWORK_CONNECTIONS);

	    for (int i = 0;; ++i)
	      {
		char strbuf[256];
		Win::RegKey connection_key;

		len = sizeof(strbuf);
		status = RegEnumKeyEx(network_connections_key(),
				      i,
				      strbuf,
				      &len,
				      NULL,
				      NULL,
				      NULL,
				      NULL);
		if (status == ERROR_NO_MORE_ITEMS)
		  break;
		else if (status != ERROR_SUCCESS)
		  OPENVPN_THROW(tun_win_util, "TapNameGuidPairList: error enumerating registry subkeys of key: " << NETWORK_CONNECTIONS);
		strbuf[len] = '\0';

		const std::string guid = std::string(strbuf);
		const std::string connection_string = std::string(NETWORK_CONNECTIONS) + std::string("\\") + guid + std::string("\\Connection");

		status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
				      connection_string.c_str(),
				      0,
				      KEY_READ,
				      connection_key.ref());
		if (status != ERROR_SUCCESS)
		  continue;

		len = sizeof(strbuf);
		status = RegQueryValueEx(connection_key(),
					 "Name",
					 NULL,
					 &data_type,
					 (LPBYTE)strbuf,
					 &len);
		if (status != ERROR_SUCCESS || data_type != REG_SZ)
		  continue;
		strbuf[len] = '\0';
		const std::string name = std::string(strbuf);

		// iterate through self and try to patch the name
		{
		  for (iterator j = begin(); j != end(); j++)
		    {
		      TapNameGuidPair& pair = *j;
		      if (pair.guid == guid)
			pair.name = name;
		    }
		}
	      }
	  }
	}

	std::string to_string() const
	{
	  std::ostringstream os;
	  for (const_iterator i = begin(); i != end(); i++)
	    {
	      const TapNameGuidPair& pair = *i;
	      os << "guid='" << pair.guid << '\'';
	      if (pair.index_defined())
		os << " index=" << pair.index;
	      if (!pair.name.empty())
		os << " name='" << pair.name << '\'';
	      os << std::endl;
	    }
	  return os.str();
	}

	std::string name_from_guid(const std::string& guid) const
	{
	  for (const_iterator i = begin(); i != end(); i++)
	    {
	      const TapNameGuidPair& pair = *i;
	      if (pair.guid == guid)
		return pair.name;
	    }
	}

	std::string guid_from_name(const std::string& name) const
	{
	  for (const_iterator i = begin(); i != end(); i++)
	    {
	      const TapNameGuidPair& pair = *i;
	      if (pair.name == name)
		return pair.guid;
	    }
	}
      };

      // given a TAP GUID, form the pathname of the TAP device node
      inline std::string tap_path(const std::string& tap_guid)
      {
	return std::string(USERMODEDEVICEDIR) + tap_guid + std::string(TAP_WIN_SUFFIX);
      }

      // open an available TAP adapter
      inline HANDLE tap_open(const TapNameGuidPairList& guids,
			     std::string& path_opened,
			     TapNameGuidPair& used)
      {
	Win::ScopedHANDLE hand;

	// iterate over list of TAP adapters on system
	for (TapNameGuidPairList::const_iterator i = guids.begin(); i != guids.end(); i++)
	  {
	    const TapNameGuidPair& tap = *i;
	    const std::string path = tap_path(tap.guid);
	    hand.reset(CreateFile(path.c_str(),
				  GENERIC_READ | GENERIC_WRITE,
				  0, /* was: FILE_SHARE_READ */
				  0,
				  OPEN_EXISTING,
				  FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
				  0));
	    if (hand.defined())
	      {
		used = tap;
		path_opened = path;
		break;
	      }
	  }
	return hand.release();
      }

      // set TAP adapter to topology subnet
      inline void tap_configure_topology_subnet(HANDLE th, const IP::Addr& local, const unsigned int prefix_len)
      {
	const IPv4::Addr netmask = IPv4::Addr::netmask_from_prefix_len(prefix_len);
	const IPv4::Addr network = local.to_ipv4() & netmask;

	boost::uint32_t ep[3];
	ep[0] = htonl(local.to_ipv4().to_uint32());
	ep[1] = htonl(network.to_uint32());
	ep[2] = htonl(netmask.to_uint32());

	DWORD len;
	if (!DeviceIoControl(th, TAP_WIN_IOCTL_CONFIG_TUN,
			     ep, sizeof (ep),
			     ep, sizeof (ep), &len, NULL))
	  throw tun_win_util("DeviceIoControl TAP_WIN_IOCTL_CONFIG_TUN failed");
      }

      // set TAP adapter to topology net30
      inline void tap_configure_topology_net30(HANDLE th, const IP::Addr& local, const unsigned int prefix_len)
      {
	const IPv4::Addr netmask = IPv4::Addr::netmask_from_prefix_len(prefix_len);

	boost::uint32_t ep[2];
	ep[0] = htonl(local.to_ipv4().to_uint32());
	ep[1] = htonl(netmask.to_uint32());

	DWORD len;
	if (!DeviceIoControl(th, TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT,
			     ep, sizeof (ep),
			     ep, sizeof (ep), &len, NULL))
	  throw tun_win_util("DeviceIoControl TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT failed");
      }

      // set driver media status to 'connected'
      inline void tap_set_media_status(HANDLE th, bool media_status)
      {
	DWORD len;
	ULONG status = media_status ? TRUE : FALSE;
	if (!DeviceIoControl(th, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
			     &status, sizeof (status),
			     &status, sizeof (status), &len, NULL))
	  throw tun_win_util("DeviceIoControl TAP_WIN_IOCTL_SET_MEDIA_STATUS failed");
      }

      // get debug logging from TAP driver (requires that
      // TAP driver was built with logging enabled)
      inline void tap_process_logging(HANDLE th)
      {
	const size_t size = 1024;
	ScopedPtr<char, PtrArrayFree> line(new char[size]);
	DWORD len;

	while (DeviceIoControl (th, TAP_WIN_IOCTL_GET_LOG_LINE,
				line(), size,
				line(), size,
				&len, NULL))
	  {
	    OPENVPN_LOG("TAP-Windows: " << line());
	  }
      }

      class TAPDriverVersion
      {
      public:
	TAPDriverVersion(HANDLE th)
	  : defined(false)
	{
	  DWORD len;
	  info[0] = info[1] = info[2] = 0;
	  if (DeviceIoControl(th, TAP_WIN_IOCTL_GET_VERSION,
			      &info, sizeof (info),
			      &info, sizeof (info), &len, NULL))
	    defined = true;
	}

	std::string to_string()
	{
	  std::ostringstream os;
	  os << "TAP-Windows Driver Version ";
	  if (defined)
	    {
	      os << info[0] << '.' << info[1];
	      if (info[2])
		os << " (DEBUG)";
	    }
	  else
	    os << "UNDEFINED";
	  return os.str();
	}

      private:
	bool defined;
	ULONG info[3];
      };

      // An action to set the DNS "Connection-specific DNS Suffix"
      class ActionSetSearchDomain : public Action
      {
      public:
	ActionSetSearchDomain(const std::string& search_domain_arg,
			      const std::string& tap_guid_arg)
	  : search_domain(search_domain_arg),
	    tap_guid(tap_guid_arg)
	{
	}

	virtual void execute()
	{
	  OPENVPN_LOG(to_string());

	  LONG status;
	  Win::RegKey key;
	  const std::string reg_key_name = "SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\\Interfaces\\" + tap_guid;
	  status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
				reg_key_name.c_str(),
				0,
				KEY_READ|KEY_WRITE,
				key.ref());
	  if (status != ERROR_SUCCESS)
	    OPENVPN_THROW(tun_win_util, "ActionSetSearchDomain: error opening registry key: " << reg_key_name);

	  Win::UTF16 dom(Win::utf16(search_domain));
	  status = RegSetValueExW(key(),
				  L"Domain",
				  0,
				  REG_SZ,
				  (const BYTE *)dom(),
				  (Win::utf16_strlen(dom())+1)*2);
	  if (status != ERROR_SUCCESS)
	    OPENVPN_THROW(tun_win_util, "ActionSetSearchDomain: error writing Domain registry key: " << reg_key_name);

	}

	virtual std::string to_string() const
	{
	  return "Set DNS search domain: '" + search_domain + "' " + tap_guid;
	}

      private:
	const std::string search_domain;
	const std::string tap_guid;
      };

      inline const MIB_IPFORWARDTABLE* windows_routing_table()
      {
	ULONG size = 0;
	DWORD status;
	ScopedPtr<MIB_IPFORWARDTABLE> rt;

	status = GetIpForwardTable (NULL, &size, TRUE);
	if (status == ERROR_INSUFFICIENT_BUFFER)
	  {
	    rt.reset((MIB_IPFORWARDTABLE*)new unsigned char[size]);
	    status = GetIpForwardTable(rt(), &size, TRUE);
	    if (status != NO_ERROR)
	      {
		OPENVPN_LOG("windows_routing_table: GetIpForwardTable failed");
		return NULL;
	      }
	  }
	return rt.release();
      }

      // Get the current default gateway
      class DefaultGateway
      {
      public:
	DefaultGateway()
	  : index(DWORD(-1))
	{
	  ScopedPtr<const MIB_IPFORWARDTABLE> rt(windows_routing_table());
	  if (rt.defined())
	    {
	      const MIB_IPFORWARDROW* gw = NULL;
	      for (size_t i = 0; i < rt()->dwNumEntries; ++i)
		{
		  const MIB_IPFORWARDROW* row = &rt()->table[i];
		  if (!row->dwForwardDest && !row->dwForwardMask
		      && (!gw || row->dwForwardMetric1 < gw->dwForwardMetric1))
		    gw = row;
		}
	      if (gw)
		{
		  index = gw->dwForwardIfIndex;
		  addr = IPv4::Addr::from_uint32(ntohl(gw->dwForwardNextHop)).to_string();
		}
	    }
	}

	bool defined() const
	{
	  return index != DWORD(-1) && !addr.empty();
	}

	DWORD interface_index() const
	{
	  return index;
	}

	const std::string& gateway_address() const
	{
	  return addr;
	}

      private:
	DWORD index;
	std::string addr;
      };

    }
  }
}

#endif
