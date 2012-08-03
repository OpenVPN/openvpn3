#ifndef OPENVPN_APPLECRYPTO_CF_CF_H
#define OPENVPN_APPLECRYPTO_CF_CF_H

#include <iostream>
#include <string>
#include <algorithm>

#include <CoreFoundation/CoreFoundation.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/buffer/buffer.hpp>

#define OPENVPN_CF_WRAP(cls, fname, cftype, idmeth) \
    typedef Wrap<cftype> cls; \
    inline cls fname(CFTypeRef obj) \
    { \
      if (obj && CFGetTypeID(obj) == idmeth()) \
	return cls((cftype)obj, BORROW); \
      else \
	return cls(); \
    }

namespace openvpn {
  namespace CF
  {
    enum Own {
      OWN,
      BORROW
    };

    template <typename T>
    class Wrap
    {
    public:
      Wrap() : obj_(NULL) {}

      // Set own=BORROW if we don't currently own the object
      explicit Wrap(T obj, const Own own=OWN)
      {
	if (own == BORROW && obj)
	  CFRetain(obj);
	obj_ = obj;
      }

      Wrap(const Wrap& other)
      {
	obj_ = other.obj_;
	if (obj_)
	  CFRetain(obj_);
      }

      Wrap& operator=(const Wrap& other)
      {
	if (other.obj_)
	  CFRetain(other.obj_);
	if (obj_)
	  CFRelease(obj_);
	obj_ = other.obj_;
	return *this;
      }

      void swap(Wrap& other)
      {
	std::swap(obj_, other.obj_);
      }

      void reset(T obj=NULL, const Own own=OWN)
      {
	if (own == BORROW && obj)
	  CFRetain(obj);
	if (obj_)
	  CFRelease(obj_);
	obj_ = obj;
      }

      bool defined() const { return obj_ != NULL; }

      T operator()() const { return obj_; }

      CFTypeRef generic() const { return (CFTypeRef)obj_; }

      T release()
      {
	T ret = obj_;
	obj_ = NULL;
	return ret;
      }

      CFTypeRef generic_release()
      {
	T ret = obj_;
	obj_ = NULL;
	return (CFTypeRef)ret;
      }

      // Intended for use with Core Foundation methods that require
      // a T* for saving a (non-borrowed) return value
      T* mod_ref()
      {
	if (obj_)
	  {
	    CFRelease(obj_);
	    obj_ = NULL;
	  }
	return &obj_;
      }

      void show() const
      {
	if (obj_)
	  CFShow(obj_);
	else
	  std::cerr << "CF_UNDEFINED" << std::endl;
      }

      virtual ~Wrap()
      {
	if (obj_)
	  CFRelease(obj_);
      }

    private:
      Wrap& operator=(T obj); // prevent use because no way to pass ownership parameter

      T obj_;
    };

    // essentially a vector of void *, used as source for array and dictionary constructors
    typedef BufferAllocatedType<CFTypeRef> SrcList;

    // common CF types

    OPENVPN_CF_WRAP(String, string_cast, CFStringRef, CFStringGetTypeID)
    OPENVPN_CF_WRAP(Number, number_cast, CFNumberRef, CFNumberGetTypeID)
    OPENVPN_CF_WRAP(Bool, bool_cast, CFBooleanRef, CFBooleanGetTypeID)
    OPENVPN_CF_WRAP(Data, data_cast, CFDataRef, CFDataGetTypeID)
    OPENVPN_CF_WRAP(Array, array_cast, CFArrayRef, CFArrayGetTypeID)
    OPENVPN_CF_WRAP(MutableArray, mutable_array_cast, CFMutableArrayRef, CFArrayGetTypeID)
    OPENVPN_CF_WRAP(Dict, dict_cast, CFDictionaryRef, CFDictionaryGetTypeID)
    OPENVPN_CF_WRAP(MutableDict, mutable_dict_cast, CFMutableDictionaryRef, CFDictionaryGetTypeID)
    OPENVPN_CF_WRAP(Error, error_cast, CFErrorRef, CFErrorGetTypeID);

    // generic CFTypeRef wrapper

    typedef Wrap<CFTypeRef> Generic;

    inline Generic generic_cast(CFTypeRef obj)
    {
      return Generic(obj, BORROW);
    }

    // constructors

    inline String string(const char *str)
    {
      return String(CFStringCreateWithCString(kCFAllocatorDefault, str, kCFStringEncodingUTF8));
    }

    inline String string(CFStringRef str)
    {
      return String(str, BORROW);
    }

    inline String string(const String& str)
    {
      return String(str);
    }

    inline String string(const std::string& str)
    {
      return String(CFStringCreateWithCString(kCFAllocatorDefault, str.c_str(), kCFStringEncodingUTF8));
    }

    inline String string(const std::string* str)
    {
      return String(CFStringCreateWithCString(kCFAllocatorDefault, str->c_str(), kCFStringEncodingUTF8));
    }

    inline Number number_from_int(const int n)
    {
      return Number(CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &n));
    }

    inline Number number_from_int32(const SInt32 n)
    {
      return Number(CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &n));
    }

    inline Number number_from_long_long(const long long n)
    {
      return Number(CFNumberCreate(kCFAllocatorDefault, kCFNumberLongLongType, &n));
    }

    inline Number number_from_index(const CFIndex n)
    {
      return Number(CFNumberCreate(kCFAllocatorDefault, kCFNumberCFIndexType, &n));
    }

    inline Data data(const void *bytes, CFIndex length)
    {
      return Data(CFDataCreate(kCFAllocatorDefault, (const UInt8 *)bytes, length));
    }

    inline Array array(const void **values, CFIndex numValues)
    {
      return Array(CFArrayCreate(kCFAllocatorDefault, values, numValues, &kCFTypeArrayCallBacks));
    }

    inline Array array(const SrcList& values)
    {
      return array((const void **)values.c_data(), values.size());
    }

    inline Dict dict(const void **keys, const void **values, CFIndex numValues)
    {
      return Dict(CFDictionaryCreate(kCFAllocatorDefault,
				     keys,
				     values,
				     numValues,
				     &kCFTypeDictionaryKeyCallBacks,
				     &kCFTypeDictionaryValueCallBacks));
    }

    inline Dict dict(const SrcList& keys, const SrcList& values)
    {
      return dict((const void **)keys.c_data(), (const void **)values.c_data(), std::min(keys.size(), values.size()));
    }

    inline Dict const_dict(MutableDict& mdict)
    {
      return Dict(mdict(), CF::BORROW);
    }

    inline MutableArray mutable_array(const CFIndex capacity=0)
    {
      return MutableArray(CFArrayCreateMutable(kCFAllocatorDefault, capacity, &kCFTypeArrayCallBacks));
    }

    inline MutableDict mutable_dict(const CFIndex capacity=0)
    {
      return MutableDict(CFDictionaryCreateMutable(kCFAllocatorDefault, capacity, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    }

    inline Error error(CFStringRef domain, CFIndex code, CFDictionaryRef userInfo)
    {
      return Error(CFErrorCreate(kCFAllocatorDefault, domain, code, userInfo));
    }

    // accessors

    template <typename ARRAY>
    inline CFIndex array_len(const ARRAY& array)
    {
      if (array.defined())
	return CFArrayGetCount(array());
      else
	return 0;
    }

    template <typename ARRAY>
    inline CFTypeRef array_index(const ARRAY& array, const CFIndex idx)
    {
      if (array.defined() && CFArrayGetCount(array()) > idx)
	return CFArrayGetValueAtIndex(array(), idx);
      else
	return NULL;
    }

    template <typename DICT, typename KEY>
    inline CFTypeRef dict_index(const DICT& dict, const KEY& key)
    {
      if (dict.defined())
	{
	  String keystr = string(key);
	  if (keystr.defined())
	    return CFDictionaryGetValue(dict(), keystr());
	}
      return NULL;
    }

    // string methods

    OPENVPN_SIMPLE_EXCEPTION(cppstring_error);

    inline std::string cppstring(CFStringRef str)
    {
      const CFStringEncoding encoding = kCFStringEncodingUTF8;
      if (str)
	{
	  const CFIndex len = CFStringGetLength(str);
	  if (len > 0)
	    {
	      const CFIndex maxsize = CFStringGetMaximumSizeForEncoding(len, encoding);
	      char *buf = new char[maxsize];
	      const Boolean status = CFStringGetCString(str, buf, maxsize, encoding);
	      if (status)
		{
		  std::string ret(buf);
		  delete [] buf;
		  return ret;
		}
	      else
		{
		  delete [] buf;
		  throw cppstring_error();
		}
	    }
	}
      return "";
    }

    inline std::string cppstring(const String& str)
    {
      return cppstring(str());
    }

    inline std::string description(CFTypeRef obj)
    {
      if (obj)
	{
	  String s(CFCopyDescription(obj));
	  return cppstring(s);
	}
      else
	return "UNDEF";
    }

    inline bool string_equal(const String& s1, const String& s2, const CFStringCompareFlags compareOptions = 0)
    {
      return s1.defined() && s2.defined() && CFStringCompare(s1(), s2(), compareOptions) == kCFCompareEqualTo;
    }

    // property lists
    inline Data plist(CFTypeRef obj)
    {
      return Data(CFPropertyListCreateData(kCFAllocatorDefault,
					   obj,
					   kCFPropertyListBinaryFormat_v1_0,
					   0,
					   NULL));
    }

  } // namespace CF
} // namespace openvpn

#endif // OPENVPN_APPLECRYPTO_CF_CF_H
