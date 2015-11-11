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

#ifndef OPENVPN_TUN_WIN_WFP_H
#define OPENVPN_TUN_WIN_WFP_H

#include <ostream>

#include <openvpn/common/rc.hpp>
#include <openvpn/buffer/bufstr.hpp>
#include <openvpn/tun/win/tunutil.hpp>
#include <openvpn/win/winerr.hpp>

#include <fwpmu.h>
#include <fwpmtypes.h>
#include <iphlpapi.h>

namespace openvpn {
  namespace TunWin {

    class WFP : public RC<thread_unsafe_refcount>
    {
    public:
      typedef RCPtr<WFP> Ptr;

      OPENVPN_EXCEPTION(wfp_error);

      // Block DNS on all interfaces except the one given.
      // Derived from https://github.com/ValdikSS/openvpn-with-patches/commit/3bd4d503d21aa34636e4f97b3e32ae0acca407f0
      void block_dns(const NET_IFINDEX index, std::ostream& log)
      {
	// WFP filter/conditions
	FWPM_FILTER0 filter = {0};
	FWPM_FILTER_CONDITION0 condition[2] = {0};
	UINT64 filterid = 0;

	// Get NET_LUID object for adapter
	NET_LUID tap_luid = adapter_index_to_luid(index);

	// Get app ID for svchost.exe
	unique_ptr_del<FWP_BYTE_BLOB> svchost_app_id = get_app_id_blob(get_svchost_path());

	// Populate packet filter layer information
	{
	  FWPM_SUBLAYER0 subLayer = {0};
	  subLayer.subLayerKey = subLayerGUID;
	  subLayer.displayData.name = L"OpenVPN";
	  subLayer.displayData.description = L"OpenVPN";
	  subLayer.flags = 0;
	  subLayer.weight = 0x100;

	  // Add packet filter to interface
	  const DWORD status = ::FwpmSubLayerAdd0(engineHandle(), &subLayer, NULL);
	  if (status != ERROR_SUCCESS)
	    OPENVPN_THROW(wfp_error, "FwpmSubLayerAdd0 failed with status=0x" << std::hex << status);
	}

	// Prepare filter
	filter.subLayerKey = subLayerGUID;
	filter.displayData.name = L"OpenVPN";
	filter.weight.type = FWP_EMPTY;
	filter.filterCondition = condition;
	filter.numFilterConditions = 2;

	// Filter #1 -- block IPv4 DNS requests from svchost.exe
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	filter.action.type = FWP_ACTION_BLOCK;

	condition[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
	condition[0].matchType = FWP_MATCH_EQUAL;
	condition[0].conditionValue.type = FWP_UINT16;
	condition[0].conditionValue.uint16 = 53;

	condition[1].fieldKey = FWPM_CONDITION_ALE_APP_ID;
	condition[1].matchType = FWP_MATCH_EQUAL;
	condition[1].conditionValue.type = FWP_BYTE_BLOB_TYPE;
	condition[1].conditionValue.byteBlob = svchost_app_id.get();

	add_filter(&filter, NULL, &filterid);
	log << "block IPv4 DNS requests from svchost.exe" << std::endl;

	// Filter #2 -- block IPv6 DNS requests from svchost.exe
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
	add_filter(&filter, NULL, &filterid);
	log << "block IPv6 DNS requests from svchost.exe" << std::endl;

	// Filter #3 -- allow IPv4 traffic from TAP
	filter.action.type = FWP_ACTION_PERMIT;

	condition[0].fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
	condition[0].matchType = FWP_MATCH_EQUAL;
	condition[0].conditionValue.type = FWP_UINT64;

	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	condition[0].conditionValue.uint64 = &tap_luid.Value;

	add_filter(&filter, NULL, &filterid);
	log << "allow IPv4 traffic from TAP" << std::endl;

	// Filter #4 -- allow IPv6 traffic from TAP
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
	add_filter(&filter, NULL, &filterid);
	log << "allow IPv6 traffic from TAP" << std::endl;
      }

      void reset(std::ostream& log)
      {
	engineHandle.reset(&log);
      }

    private:
      class WFPEngine
      {
      public:
	WFPEngine()
	{
	  FWPM_SESSION0 session = {0};

	  // delete all filters when engine handle is closed
	  session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	  const DWORD status = ::FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &handle);
	  if (status != ERROR_SUCCESS)
	    OPENVPN_THROW(wfp_error, "FwpmEngineOpen0 failed with status=0x" << std::hex << status);
	}

	void reset(std::ostream* log)
	{
	  if (defined())
	    {
	      const DWORD status = ::FwpmEngineClose0(handle);
	      handle = NULL;
	      if (log)
		{
		  if (status != ERROR_SUCCESS)
		    *log << "FwpmEngineClose0 failed, status=" << status << std::endl;
		  else
		    *log << "WFPEngine closed" << std::endl;
		}
	    }
	}

	~WFPEngine()
	{
	  reset(nullptr);
	}

	bool defined() const
	{
	  return Win::Handle::defined(handle);
	}

	HANDLE operator()() const
	{
	  return handle;
	}

      private:
	WFPEngine(const WFPEngine&) = delete;
	WFPEngine& operator=(const WFPEngine&) = delete;

	HANDLE handle = NULL;
      };

      static GUID new_guid()
      {
	UUID ret;
	const RPC_STATUS status = ::UuidCreate(&ret);
	if (status != RPC_S_OK && status != RPC_S_UUID_LOCAL_ONLY)
	  throw wfp_error("UuidCreate failed");
	return ret;
      }

      static NET_LUID adapter_index_to_luid(const NET_IFINDEX index)
      {
	NET_LUID tap_luid;
	const NETIO_STATUS ret = ::ConvertInterfaceIndexToLuid(index, &tap_luid);
	if (ret != NO_ERROR)
	  throw wfp_error("ConvertInterfaceIndexToLuid failed");
	return tap_luid;
      }

      static std::wstring get_svchost_path()
      {
	wchar_t path[MAX_PATH];
	if (!::GetSystemDirectoryW(path, MAX_PATH))
	  {
	    const Win::LastError err;
	    OPENVPN_THROW(wfp_error, "GetSystemDirectoryW failed: " << err.message());
	  }
	return std::wstring(path) + L"\\svchost.exe";
      }

      static unique_ptr_del<FWP_BYTE_BLOB> get_app_id_blob(const std::wstring& app_path)
      {
	FWP_BYTE_BLOB *blob;
	const DWORD status = ::FwpmGetAppIdFromFileName0(app_path.c_str(), &blob);
	if (status != ERROR_SUCCESS)
	  OPENVPN_THROW(wfp_error, "FwpmGetAppIdFromFileName0 failed, status=0x" << std::hex << status);
	return unique_ptr_del<FWP_BYTE_BLOB>(blob, [](FWP_BYTE_BLOB* blob) {
	    ::FwpmFreeMemory0((void**)&blob);
	  });
      }

      bool add_filter(const FWPM_FILTER0 *filter,
		      PSECURITY_DESCRIPTOR sd,
		      UINT64 *id)
      {
	const DWORD status = ::FwpmFilterAdd0(engineHandle(), filter, sd, id);
	if (status != ERROR_SUCCESS)
	  OPENVPN_THROW(wfp_error, "FwpmFilterAdd0 failed, status=0x" << std::hex << status);
      }

      const GUID subLayerGUID{new_guid()};
      WFPEngine engineHandle;
    };

    class WFPContext : public RC<thread_unsafe_refcount>
    {
    public:
      typedef RCPtr<WFPContext> Ptr;

    private:
      friend class ActionWFP;

      void block(const DWORD iface_index, std::ostream& log)
      {
	unblock(log);
	wfp.reset(new WFP());
	wfp->block_dns(iface_index, log);
      }

      void unblock(std::ostream& log)
      {
	if (wfp)
	  {
	    wfp->reset(log);
	    wfp.reset();
	  }
      }

      WFP::Ptr wfp;
    };

    class ActionWFP : public Action
    {
    public:
      ActionWFP(const DWORD iface_index_arg,
		const bool enable_arg,
		const WFPContext::Ptr& wfp_arg)
	: iface_index(iface_index_arg),
	  enable(enable_arg),
	  wfp(wfp_arg)
      {
      }

      virtual void execute(std::ostream& log) override
      {
	log << to_string() << std::endl;
	if (enable)
	  wfp->block(iface_index, log);
	else
	  wfp->unblock(log);
      }

      virtual std::string to_string() const override
      {
	return "ActionWFP iface_index=" + std::to_string(iface_index) + " enable=" + std::to_string(enable);
      }

    private:
      const DWORD iface_index;
      bool enable;

      WFPContext::Ptr wfp;
    };
  }
}

#endif
