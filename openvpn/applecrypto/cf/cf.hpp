#ifndef OPENVPN_APPLECRYPTO_CF_CF_H
#define OPENVPN_APPLECRYPTO_CF_CF_H

#include <iostream>
#include <algorithm>

#include <CoreFoundation/CFBase.h>
#include <CoreFoundation/CFString.h>
#include <CoreFoundation/CFArray.h>
#include <CoreFoundation/CFDictionary.h>
#include <CoreFoundation/CFData.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/buffer/buffer.hpp>

namespace openvpn {

  namespace CF
  {
    enum Own {
      OWN,
      BORROW
    };
  }

  template <typename T>
  class CFWrap
  {
  public:
    CFWrap() : obj_(NULL) {}

    // Set own=CF::BORROW if we don't currently own the object
    explicit CFWrap(T obj, const CF::Own own=CF::OWN)
       : obj_(NULL)
    {
      if (own == CF::BORROW && obj)
	CFRetain(obj);
      obj_ = obj;
    }

    CFWrap(const CFWrap& other)
    {
      obj_ = other.obj_;
      if (obj_)
	CFRetain(obj_);
    }

    CFWrap& operator=(const CFWrap& other)
    {
      if (other.obj_)
	CFRetain(other.obj_);
      if (obj_)
	CFRelease(obj_);
      obj_ = other.obj_;
      return *this;
    }

    void reset(T obj, const CF::Own own=CF::OWN)
    {
      if (own == CF::BORROW && obj)
	CFRetain(obj);
      if (obj_)
	CFRelease(obj_);
      obj_ = obj;
    }

    bool defined() const { return obj_ != NULL; }

    T operator()() const { return obj_; }

    // Intended for use with Apple methods that require
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

    virtual ~CFWrap()
    {
      if (obj_)
	CFRelease(obj_);
    }

  private:
    CFWrap& operator=(T obj); // prevent use because no way to pass ownership parameter

    T obj_;
  };

  namespace CF
  {
    // common CF types

    typedef CFWrap<CFStringRef> String;
    typedef CFWrap<CFArrayRef> Array;
    typedef CFWrap<CFDictionaryRef> Dict;
    typedef CFWrap<CFDataRef> Data;
    typedef CFWrap<CFTypeRef> Generic;

    // essentially a vector of void *, used as source for array and dictionary constructors
    typedef BufferAllocatedType<CFTypeRef> SrcList;

    // casts

    inline String string_cast(CFTypeRef obj)
    {
      if (obj && CFGetTypeID(obj) == CFStringGetTypeID())
	return String((CFStringRef)obj, BORROW);
      else
	return String();
    }

    inline Array array_cast(CFTypeRef obj)
    {
      if (obj && CFGetTypeID(obj) == CFArrayGetTypeID())
	return Array((CFArrayRef)obj, BORROW);
      else
	return Array();
    }

    inline Dict dict_cast(CFTypeRef obj)
    {
      if (obj && CFGetTypeID(obj) == CFDictionaryGetTypeID())
	return Dict((CFDictionaryRef)obj, BORROW);
      else
	return Dict();
    }

    inline Generic generic_cast(CFTypeRef obj)
    {
      return Generic(obj, BORROW);
    }

    // constructors

    inline String string(const char *str)
    {
      return String(CFStringCreateWithCString(kCFAllocatorDefault, str, kCFStringEncodingUTF8));
    }

    inline Data data(const UInt8 *bytes, CFIndex length)
    {
      return Data(CFDataCreate(kCFAllocatorDefault, bytes, length));
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

    // accessors

    inline CFIndex array_len(const Array& array)
    {
      if (array.defined())
	return CFArrayGetCount(array());
      else
	return 0;
    }

    inline CFTypeRef array_index(const Array& array, const CFIndex idx)
    {
      if (array.defined() && CFArrayGetCount(array()) > idx)
	return CFArrayGetValueAtIndex(array(), idx);
      else
	return NULL;
    }

    inline CFTypeRef dict_index(const Dict& dict, const char *key)
    {
      if (dict.defined())
	{
	  String keystr = string(key);
	  return CFDictionaryGetValue(dict(), keystr());
	}
      else
	return NULL;
    }

    inline CFTypeRef dict_index(const Dict& dict, CFStringRef key)
    {
      if (dict.defined())
	return CFDictionaryGetValue(dict(), key);
      else
	return NULL;
    }

    // comparison

    bool string_equal(const String& s1, const String& s2, const CFStringCompareFlags compareOptions = 0)
    {
      return CFStringCompare(s1(), s2(), compareOptions) == kCFCompareEqualTo;
    }

  } // namespace CF
} // namespace openvpn

#endif // OPENVPN_APPLECRYPTO_CF_CF_H
