//
//  scdynstore.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_APPLE_SCDYNSTORE_H
#define OPENVPN_APPLE_SCDYNSTORE_H

#include <SystemConfiguration/SCDynamicStore.h>

#include <openvpn/applecrypto/cf/cf.hpp>

namespace openvpn {
  namespace CF {
    OPENVPN_CF_WRAP(DynamicStore, dynamic_store_cast, SCDynamicStoreRef, SCDynamicStoreGetTypeID)

    template <typename RET, typename KEY>
    inline RET DynamicStoreCopy(const DynamicStore& ds, const KEY& key)
    {
      String keystr = string(key);
      return RET(RET::cast(SCDynamicStoreCopyValue(ds(), keystr())));
    }

    template <typename KEY>
    inline Dict DynamicStoreCopyDict(const DynamicStore& ds, const KEY& key)
    {
      Dict dict = DynamicStoreCopy<Dict>(ds, key);
      if (dict.defined())
	return dict;
      else
	return CF::empty_dict();
    }
  }
}

#endif
