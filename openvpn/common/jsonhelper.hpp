//
//  jsonhelper.hpp
//  OpenVPN
//
//  Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
//  All rights reserved.
//

#ifndef OPENVPN_COMMON_JSONHELPER_H
#define OPENVPN_COMMON_JSONHELPER_H

#include <string>
#include <cstring>
#include <cstdint>

#include "json/json.h"

#include <openvpn/common/exception.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/stringtempl.hpp>
#include <openvpn/buffer/bufstr.hpp>
#include <openvpn/buffer/bufstream.hpp>

namespace openvpn {

  class json {
  public:
    OPENVPN_EXCEPTION(json_parse);

    template <typename TITLE>
    static Json::Value parse(const std::string& str, const TITLE& title)
    {
      Json::Value root;
      Json::Reader reader;
      if (!reader.parse(str, root, false))
	throw json_parse(StringTempl::to_string(title) + " : " + reader.getFormattedErrorMessages());
      return root;
    }

    static Json::Value parse_from_file(const std::string& fn)
    {
      return parse(read_text_utf8(fn), fn);
    }

    template <typename TITLE>
    static Json::Value parse_from_buffer(const Buffer& buf, const TITLE& title)
    {
      Json::Value root;
      Json::Reader reader;
      if (!reader.parse(reinterpret_cast<const char *>(buf.c_data()), reinterpret_cast<const char *>(buf.c_data()) + buf.size(), root, false))
	throw json_parse(StringTempl::to_string(title) + " : " + reader.getFormattedErrorMessages());
      return root;
    }

    template <typename T, typename NAME>
    static void from_vector(Json::Value& root, const T& vec, const NAME& name)
    {
      Json::Value array(Json::arrayValue);
      for (auto &e : vec)
	array.append(e.to_json());
      if (array.size())
	root[name] = array;
    }

    template <typename TITLE>
    static void assert_dict(const Json::Value& obj, const TITLE& title)
    {
      if (!obj.isObject())
	throw json_parse(StringTempl::to_string(title) + " is not a JSON dictionary");
    }

    template <typename TITLE>
    static bool is_dict(const Json::Value& obj, const TITLE& title)
    {
      if (obj.isNull())
	return false;
      assert_dict(obj, title);
      return true;
    }

    template <typename NAME>
    static bool exists(const Json::Value& root, const NAME& name)
    {
      const Json::Value& value = root[name];
      return !value.isNull();
    }

    template <typename NAME, typename TITLE>
    static void to_string(const Json::Value& root, std::string& dest, const NAME& name, const TITLE& title)
    {
      dest = get_string(root, name, title);
    }

    template <typename NAME, typename TITLE>
    static void to_string_optional(const Json::Value& root,
				   std::string& dest,
				   const NAME& name,
				   const std::string& default_value,
				   const TITLE& title)
    {
      dest = get_string_optional(root, name, default_value, title);
    }

    template <typename NAME, typename TITLE>
    static void to_int(const Json::Value& root, int& dest, const NAME& name, const TITLE& title)
    {
      dest = get_int(root, name, title);
    }

    template <typename NAME, typename TITLE>
    static void to_uint(const Json::Value& root, unsigned int& dest, const NAME& name, const TITLE& title)
    {
      dest = get_uint(root, name, title);
    }

    template <typename NAME, typename TITLE>
    static void to_uint_optional(const Json::Value& root,
				 unsigned int& dest,
				 const NAME& name,
				 const unsigned int default_value,
				 const TITLE& title)
    {
      dest = get_uint_optional(root, name, default_value, title);
    }

    template <typename NAME, typename TITLE>
    static void to_uint64(const Json::Value& root, std::uint64_t& dest, const NAME& name, const TITLE& title)
    {
      dest = get_uint64(root, name, title);
    }

    template <typename NAME, typename TITLE>
    static void to_bool(const Json::Value& root, bool& dest, const NAME& name, const TITLE& title)
    {
      dest = get_bool(root, name, title);
    }

    template <typename T, typename NAME, typename TITLE>
    static void to_vector(const Json::Value& root, T& vec, const NAME& name, const TITLE& title)
    {
      const Json::Value& array = root[name];
      if (array.isNull())
	return;
      if (!array.isArray())
	throw json_parse("array " + fmt_name(name, title) + " is of incorrect type");
      for (unsigned int i = 0; i < array.size(); ++i)
	{
	  vec.emplace_back();
	  vec.back().from_json(array[i], fmt_name(name, title));
	}
    }

    template <typename NAME, typename TITLE>
    static std::string get_string(const Json::Value& root, const NAME& name, const TITLE& title)
    {
      const Json::Value& value = root[name];
      if (value.isNull())
	throw json_parse("string " + fmt_name(name, title) + " is missing");
      if (!value.isString())
	throw json_parse("string " + fmt_name(name, title) + " is of incorrect type");
      return value.asString();
    }

    template <typename NAME, typename TITLE>
    static std::string get_string_optional(const Json::Value& root,
					   const NAME& name,
					   const std::string& default_value,
					   const TITLE& title)
    {
      const Json::Value& value = root[name];
      if (value.isNull())
	return default_value;
      if (!value.isString())
	throw json_parse("string " + fmt_name(name, title) + " is of incorrect type");
      return value.asString();
    }

    template <typename NAME>
    static std::string get_string(const Json::Value& root, const NAME& name)
    {
      return get_string(root, name, nullptr);
    }

    template <typename NAME, typename TITLE>
    static int get_int(const Json::Value& root, const NAME& name, const TITLE& title)
    {
      const Json::Value& value = root[name];
      if (value.isNull())
	throw json_parse("int " + fmt_name(name, title) + " is missing");
      if (!value.isInt())
	throw json_parse("int " + fmt_name(name, title) + " is of incorrect type");
      return value.asInt();
    }

    template <typename NAME>
    static int get_int(const Json::Value& root, const NAME& name)
    {
      return get_int(root, name, nullptr);
    }

    template <typename NAME, typename TITLE>
    static unsigned int get_uint(const Json::Value& root, const NAME& name, const TITLE& title)
    {
      const Json::Value& value = root[name];
      if (value.isNull())
	throw json_parse("uint " + fmt_name(name, title) + " is missing");
      if (!value.isUInt())
	throw json_parse("uint " + fmt_name(name, title) + " is of incorrect type");
      return value.asUInt();
    }

    template <typename NAME>
    static unsigned int get_uint(const Json::Value& root, const NAME& name)
    {
      return get_uint(root, name, nullptr);
    }

    template <typename NAME, typename TITLE>
    static unsigned int get_uint_optional(const Json::Value& root, const NAME& name, const unsigned int default_value, const TITLE& title)
    {
      const Json::Value& value = root[name];
      if (value.isNull())
	return default_value;
      if (!value.isUInt())
	throw json_parse("uint " + fmt_name(name, title) + " is of incorrect type");
      return value.asUInt();
    }

    template <typename NAME>
    static unsigned int get_uint_optional(const Json::Value& root, const NAME& name, const unsigned int default_value)
    {
      return get_uint_optional(root, name, default_value, nullptr);
    }

    template <typename NAME, typename TITLE>
    static std::uint64_t get_uint64(const Json::Value& root, const NAME& name, const TITLE& title)
    {
      const Json::Value& value = root[name];
      if (value.isNull())
	throw json_parse("uint64 " + fmt_name(name, title) + " is missing");
      if (!value.isUInt64())
	throw json_parse("uint64 " + fmt_name(name, title) + " is of incorrect type");
      return value.asUInt64();
    }

    template <typename NAME, typename TITLE>
    static bool get_bool(const Json::Value& root, const NAME& name, const TITLE& title)
    {
      const Json::Value& value = root[name];
      if (value.isNull())
	throw json_parse("bool " + fmt_name(name, title) + " is missing");
      if (!value.isBool())
	throw json_parse("bool " + fmt_name(name, title) + " is of incorrect type");
      return value.asBool();
    }

    template <typename NAME>
    static bool get_bool(const Json::Value& root, const NAME& name)
    {
      return get_bool(root, name, nullptr);
    }

    template <typename NAME>
    static bool get_bool_optional(const Json::Value& root, const NAME& name, const bool default_value=false)
    {
      const Json::Value& jv = root[name];
      if (jv.isConvertibleTo(Json::booleanValue))
	return jv.asBool();
      else if (jv.isString())
	{
	  const std::string bs = string::to_lower_copy(jv.asString());
	  return bs == "true" || bs == "1";
	}
      else
	return default_value;
    }

    template <typename NAME, typename TITLE>
    static const Json::Value& get_dict(const Json::Value& root, const NAME& name, const bool optional, const TITLE& title)
    {
      const Json::Value& value = root[name];
      if (value.isNull())
	{
	  if (optional)
	    return value;
	  throw json_parse("dictionary " + fmt_name(name, title) + " is missing");
	}
      if (!value.isObject())
	throw json_parse("dictionary " + fmt_name(name, title) + " is of incorrect type");
      return value;
    }

    template <typename TITLE>
    static const Json::Value& cast_dict(const Json::Value& value, const bool optional, const TITLE& title)
    {
      if (value.isNull())
	{
	  if (optional)
	    return value;
	  throw json_parse("dictionary cast " + StringTempl::to_string(title) + " is null");
	}
      if (!value.isObject())
	throw json_parse("dictionary cast " + StringTempl::to_string(title) + " is of incorrect type");
      return value;
    }

    template <typename NAME, typename TITLE>
    static const Json::Value& get_array(const Json::Value& root, const NAME& name, const bool optional, const TITLE& title)
    {
      const Json::Value& value = root[name];
      if (value.isNull())
	{
	  if (optional)
	    return value;
	  throw json_parse("array " + fmt_name(name, title) + " is missing");
	}
      if (!value.isArray())
	throw json_parse("array " + fmt_name(name, title) + " is of incorrect type");
      return value;
    }

    template <typename TITLE>
    static const Json::Value& cast_array(const Json::Value& value, const bool optional, const TITLE& title)
    {
      if (value.isNull())
	{
	  if (optional)
	    return value;
	  throw json_parse("array cast " + StringTempl::to_string(title) + " is null");
	}
      if (!value.isArray())
	throw json_parse("array cast " + StringTempl::to_string(title) + " is of incorrect type");
      return value;
    }

    template <typename NAME>
    static const Json::Value& get_dict(const Json::Value& root, const NAME& name, const bool optional)
    {
      return get_dict(root, name, optional, "");
    }

    static void format_compact(const Json::Value& root, Buffer& buf)
    {
      Json::StreamWriterBuilder json_builder;
      json_builder.settings_["indentation"] = "";
      BufferStreamOut os(buf);
      std::unique_ptr<Json::StreamWriter> sw(json_builder.newStreamWriter());
      sw->write(root, &os);
    }

    static std::string format_compact(const Json::Value& root, const size_t size_hint=256)
    {
      BufferPtr bp = new BufferAllocated(size_hint, BufferAllocated::GROW);
      format_compact(root, *bp);
      return buf_to_string(*bp);
    }

    static std::string format(const Json::Value& root)
    {
      return root.toStyledString();
    }

  private:
    template <typename NAME, typename TITLE>
    static std::string fmt_name(const NAME& name, const TITLE& title)
    {
      if (!StringTempl::empty(title))
	return StringTempl::to_string(title) + '.' + name;
      else
	return name;
    }
  };
}

#endif
