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
    inline CFTypeRef dict_get_create(CFMutableDictionaryRef base,
				     CFStringRef key,
				     CFTypeRef (*create_method)())
    {
      if (base)
	{
	  CFTypeRef ret = CFDictionaryGetValue(base, key); // try lookup first
	  if (!ret)
	    {
	      // doesn't exist, must create
	      ret = (*create_method)();
	      CFDictionaryAddValue(base, key, ret);
	      CFRelease(ret); // because ret is now owned by base
	    }
	  return ret;
	}
      return NULL;
    }

    // variation on above function that accepts a char * key
    inline CFTypeRef dict_get_create(CFMutableDictionaryRef base,
				     const char *key,
				     CFTypeRef (*create_method)())
    {
      String keystr = string(key);
      return dict_get_create(base, keystr(), create_method);
    }

    // lookup a dict in another dict (base) and return or create if absent

    inline MutableDict dict_get_create_dict(MutableDict& base, CFStringRef key)
    {
      return CF::mutable_dict_cast(CF::dict_get_create(base(), key, CF::mutable_dict_new));
    }

    inline MutableDict dict_get_create_dict(MutableDict& base, const char *key)
    {
      String keystr = string(key);
      return CF::mutable_dict_cast(CF::dict_get_create(base(), keystr(), CF::mutable_dict_new));
    }

    // lookup an array in a dict (base) and return or create if absent

    inline MutableArray dict_get_create_array(MutableDict& base, CFStringRef key)
    {
      return CF::mutable_array_cast(CF::dict_get_create(base(), key, CF::mutable_array_new));
    }

    inline MutableArray dict_get_create_array(MutableDict& base, const char *key)
    {
      String keystr = string(key);
      return CF::mutable_array_cast(CF::dict_get_create(base(), keystr(), CF::mutable_array_new));
    }


    // lookup a string in a dictionary (DICT should be a Dict or a MutableDict)
    template <typename DICT>
    inline std::string dict_get_str(const DICT& dict, CFStringRef key)
    {
      return cppstring(string_cast(dict_index(dict, key)));
    }

    // lookup a string in a dictionary (DICT should be a Dict or a MutableDict)
    template <typename DICT>
    inline std::string dict_get_str(const DICT& dict, const char *key)
    {
      return cppstring(string_cast(dict_index(dict, key)));
    }

    // lookup an integer in a dictionary (DICT should be a Dict or a MutableDict)
    template <typename DICT>
    inline int dict_get_int(const DICT& dict, const char *key, const int default_value)
    {
      int ret;
      Number num = number_cast(dict_index(dict, key));
      if (num.defined() && CFNumberGetValue(num(), kCFNumberIntType, &ret))
	return ret;
      else
	return default_value;
    }

    // set a string in a mutable dictionary

    inline void dict_set_str(MutableDict& dict, CFStringRef key, CFStringRef value)
    {
      CFDictionarySetValue(dict(), key, value);
    }

    inline void dict_set_str(MutableDict& dict, const char *key, CFStringRef value)
    {
      String keystr = string(key);
      CFDictionarySetValue(dict(), keystr(), value);
    }

    inline void dict_set_str(MutableDict& dict, CFStringRef key, const std::string& value)
    {
      String valstr = string(value);
      CFDictionarySetValue(dict(), key, valstr());
    }

    inline void dict_set_str(MutableDict& dict, const char* key, const std::string& value)
    {
      String keystr = string(key);
      String valstr = string(value);
      CFDictionarySetValue(dict(), keystr(), valstr());
    }

    // append string to a mutable array

    inline void array_append_str(MutableArray& array, const std::string& value)
    {
      String valstr = string(value);
      CFArrayAppendValue(array(), valstr());
    }

    // set a number in a mutable dictionary

    inline void dict_set_int(MutableDict& dict, CFStringRef key, int value)
    {
      Number num = number_from_int(value);
      CFDictionarySetValue(dict(), key, num());
    }

    inline void dict_set_int(MutableDict& dict, const char *key, int value)
    {
      String keystr = string(key);
      Number num = number_from_int(value);
      CFDictionarySetValue(dict(), keystr(), num());
    }

    inline void dict_set_int32(MutableDict& dict, CFStringRef key, SInt32 value)
    {
      Number num = number_from_int32(value);
      CFDictionarySetValue(dict(), key, num());
    }

    inline void dict_set_int32(MutableDict& dict, const char *key, SInt32 value)
    {
      String keystr = string(key);
      Number num = number_from_int32(value);
      CFDictionarySetValue(dict(), keystr(), num());
    }

    inline void dict_set_long_long(MutableDict& dict, CFStringRef key, long long value)
    {
      Number num = number_from_long_long(value);
      CFDictionarySetValue(dict(), key, num());
    }

    inline void dict_set_long_long(MutableDict& dict, const char *key, long long value)
    {
      String keystr = string(key);
      Number num = number_from_long_long(value);
      CFDictionarySetValue(dict(), keystr(), num());
    }

    inline void dict_set_index(MutableDict& dict, CFStringRef key, CFIndex value)
    {
      Number num = number_from_index(value);
      CFDictionarySetValue(dict(), key, num());
    }

    inline void dict_set_index(MutableDict& dict, const char *key, CFIndex value)
    {
      String keystr = string(key);
      Number num = number_from_index(value);
      CFDictionarySetValue((CFMutableDictionaryRef)dict(), keystr(), num());
    }

    // append number to a mutable array

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

    inline void array_append_index(MutableArray& array, CFIndex value)
    {
      Number num = number_from_index(value);
      CFArrayAppendValue(array(), num());
    }

    // set a boolean in a mutable dictionary

    inline void dict_set_bool(MutableDict& dict, CFStringRef key, bool value)
    {
      CFBooleanRef boolref = value ? kCFBooleanTrue : kCFBooleanFalse;
      CFDictionarySetValue(dict(), key, boolref);
    }

    inline void dict_set_bool(MutableDict& dict, const char *key, bool value)
    {
      String keystr = string(key);
      CFBooleanRef boolref = value ? kCFBooleanTrue : kCFBooleanFalse;
      CFDictionarySetValue(dict(), keystr(), boolref);
    }
  }
}
#endif
