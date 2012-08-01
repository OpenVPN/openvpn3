#ifndef OPENVPN_APPLECRYPTO_CF_CFHELPER_H
#define OPENVPN_APPLECRYPTO_CF_CFHELPER_H

#include <openvpn/applecrypto/cf/cf.hpp>

namespace openvpn {
  namespace CF {

    inline CFTypeRef mutable_dict_new()
    {
      return CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    }

    inline CFTypeRef mutable_array_new()
    {
      return CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    }

    // Lookup or create (if absent) an item in a mutable dictionary.
    // Return the item, which will be owned by base.
    template <typename KEY>
    inline CFTypeRef dict_get_create(CFMutableDictionaryRef base,
				     const KEY& key,
				     CFTypeRef (*create_method)())
    {
      if (base)
	{
	  String keystr = string(key);
	  CFTypeRef ret = CFDictionaryGetValue(base, keystr()); // try lookup first
	  if (!ret)
	    {
	      // doesn't exist, must create
	      ret = (*create_method)();
	      CFDictionaryAddValue(base, keystr(), ret);
	      CFRelease(ret); // because ret is now owned by base
	    }
	  return ret;
	}
      return NULL;
    }

    // lookup a dict in another dict (base) and return or create if absent
    template <typename KEY>
    inline MutableDict dict_get_create_dict(MutableDict& base, const KEY& key)
    {
      String keystr = string(key);
      return mutable_dict_cast(dict_get_create(base(), keystr(), mutable_dict_new));
    }

    // lookup an array in a dict (base) and return or create if absent
    template <typename KEY>
    inline MutableArray dict_get_create_array(MutableDict& base, const KEY& key)
    {
      String keystr = string(key);
      return mutable_array_cast(dict_get_create(base(), keystr(), mutable_array_new));
    }

    // lookup an object in a dictionary (DICT should be a Dict or a MutableDict)
    template <typename DICT, typename KEY>
    inline CFTypeRef dict_get_obj(const DICT& dict, const KEY& key)
    {
      return dict_index(dict, key);
    }

    // lookup a string in a dictionary (DICT should be a Dict or a MutableDict)
    template <typename DICT, typename KEY>
    inline std::string dict_get_str(const DICT& dict, const KEY& key)
    {
      return cppstring(string_cast(dict_index(dict, key)));
    }

    // lookup an integer in a dictionary (DICT should be a Dict or a MutableDict)
    template <typename DICT, typename KEY>
    inline int dict_get_int(const DICT& dict, const KEY& key, const int default_value)
    {
      int ret;
      Number num = number_cast(dict_index(dict, key));
      if (num.defined() && CFNumberGetValue(num(), kCFNumberIntType, &ret))
	return ret;
      else
	return default_value;
    }

    // lookup a boolean in a dictionary (DICT should be a Dict or a MutableDict)
    template <typename DICT, typename KEY>
    inline bool dict_get_bool(const DICT& dict, const KEY& key, const bool default_value)
    {
      Bool b = bool_cast(dict_index(dict, key));
      if (b.defined())
	{
	  if (b() == kCFBooleanTrue)
	    return true;
	  else if (b() == kCFBooleanFalse)
	    return false;
	}
      return default_value;
    }

    // set a CFTypeRef in a mutable dictionary

    template <typename KEY>
    inline void dict_set_obj(MutableDict& dict, const KEY& key, CFTypeRef value)
    {
      String keystr = string(key);
      CFDictionarySetValue(dict(), keystr(), value);
    }

    // set a string in a mutable dictionary

    template <typename KEY, typename VALUE>
    inline void dict_set_str(MutableDict& dict, const KEY& key, const VALUE& value)
    {
      String keystr = string(key);
      String valstr = string(value);
      CFDictionarySetValue(dict(), keystr(), valstr());
    }

    // set a number in a mutable dictionary

    template <typename KEY>
    inline void dict_set_int(MutableDict& dict, const KEY& key, int value)
    {
      String keystr = string(key);
      Number num = number_from_int(value);
      CFDictionarySetValue(dict(), keystr(), num());
    }

    template <typename KEY>
    inline void dict_set_int32(MutableDict& dict, const KEY& key, SInt32 value)
    {
      String keystr = string(key);
      Number num = number_from_int32(value);
      CFDictionarySetValue(dict(), keystr(), num());
    }

    template <typename KEY>
    inline void dict_set_long_long(MutableDict& dict, const KEY& key, long long value)
    {
      String keystr = string(key);
      Number num = number_from_long_long(value);
      CFDictionarySetValue(dict(), keystr(), num());
    }

    template <typename KEY>
    inline void dict_set_index(MutableDict& dict, const KEY& key, CFIndex value)
    {
      String keystr = string(key);
      Number num = number_from_index(value);
      CFDictionarySetValue((CFMutableDictionaryRef)dict(), keystr(), num());
    }

    // set a boolean in a mutable dictionary

    template <typename KEY>
    inline void dict_set_bool(MutableDict& dict, const KEY& key, bool value)
    {
      String keystr = string(key);
      CFBooleanRef boolref = value ? kCFBooleanTrue : kCFBooleanFalse;
      CFDictionarySetValue(dict(), keystr(), boolref);
    }

    // append string to a mutable array

    template <typename VALUE>
    inline void array_append_str(MutableArray& array, const VALUE& value)
    {
      String valstr = string(value);
      CFArrayAppendValue(array(), valstr());
    }

    // append a number to a mutable array

    inline void array_append_int(MutableArray& array, int value)
    {
      Number num = number_from_int(value);
      CFArrayAppendValue(array(), num());
    }

    inline void array_append_int32(MutableArray& array, SInt32 value)
    {
      Number num = number_from_int32(value);
      CFArrayAppendValue(array(), num());
    }

    inline void array_append_long_long(MutableArray& array, long long value)
    {
      Number num = number_from_long_long(value);
      CFArrayAppendValue(array(), num());
    }

    inline void array_append_index(MutableArray& array, CFIndex value)
    {
      Number num = number_from_index(value);
      CFArrayAppendValue(array(), num());
    }
  }
}
#endif
