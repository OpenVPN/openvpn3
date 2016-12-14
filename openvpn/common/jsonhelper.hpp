//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
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

#ifndef OPENVPN_COMMON_JSONHELPER_H
#define OPENVPN_COMMON_JSONHELPER_H

#include "json/json.h"

#include <openvpn/common/exception.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/buffer/bufstr.hpp>
#include <openvpn/buffer/bufstream.hpp>

namespace openvpn {

  class json {
  public:
    OPENVPN_EXCEPTION(json_parse);

    static Json::Value parse(const std::string& str, const std::string& title)
    {
      Json::Value root;
      Json::Reader reader;
      if (!reader.parse(str, root, false))
	OPENVPN_THROW(json_parse, title << " : " << reader.getFormattedErrorMessages());
      return root;
    }

    static Json::Value parse_from_file(const std::string& fn)
    {
      return parse(read_text_utf8(fn), fn);
    }

    static Json::Value parse_from_buffer(const Buffer& buf, const std::string& title)
    {
      Json::Value root;
      Json::Reader reader;
      if (!reader.parse(reinterpret_cast<const char *>(buf.c_data()), reinterpret_cast<const char *>(buf.c_data()) + buf.size(), root, false))
	OPENVPN_THROW(json_parse, title << " : " << reader.getFormattedErrorMessages());
      return root;
    }

    template <typename T>
    static void from_vector(Json::Value& root, const T& vec, const std::string& name)
    {
      Json::Value array(Json::arrayValue);
      for (auto &e : vec)
	array.append(e.to_json());
      if (array.size())
	root[name] = array;
    }

    static void assert_dict(const Json::Value& obj, const std::string& title)
    {
      if (!obj.isObject())
	OPENVPN_THROW(json_parse, title << " is not a JSON dictionary");
    }

    static bool is_dict(const Json::Value& obj, const std::string& title)
    {
      if (obj.isNull())
	return false;
      assert_dict(obj, title);
      return true;
    }

    static bool exists(const Json::Value& root, const std::string& name)
    {
      const Json::Value& value = root[name];
      return !value.isNull();
    }

    static void to_string(const Json::Value& root, std::string& dest, const std::string& name, const std::string& title)
    {
      const Json::Value& value = root[name];
      if (value.isNull())
	OPENVPN_THROW(json_parse, "string " << fmt_name(name, title) << " is missing");
      if (!value.isString())
	OPENVPN_THROW(json_parse, "string " << fmt_name(name, title) << " is of incorrect type");
      dest = value.asString();
    }

    static void to_string_optional(const Json::Value& root,
				   std::string& dest,
				   const std::string& name,
				   const std::string& default_value,
				   const std::string& title)
    {
      const Json::Value& value = root[name];
      if (value.isNull())
	{
	  dest = default_value;
	  return;
	}
      if (!value.isString())
	OPENVPN_THROW(json_parse, "string " << fmt_name(name, title) << " is of incorrect type");
      dest = value.asString();
    }

    static void to_int(const Json::Value& root, int& dest, const std::string& name, const std::string& title)
    {
      const Json::Value& value = root[name];
      if (value.isNull())
	OPENVPN_THROW(json_parse, "int " << fmt_name(name, title) << " is missing");
      if (!value.isInt())
	OPENVPN_THROW(json_parse, "int " << fmt_name(name, title) << " is of incorrect type");
      dest = value.asInt();
    }

    static void to_uint(const Json::Value& root, unsigned int& dest, const std::string& name, const std::string& title)
    {
      const Json::Value& value = root[name];
      if (value.isNull())
	OPENVPN_THROW(json_parse, "uint " << fmt_name(name, title) << " is missing");
      if (!value.isUInt())
	OPENVPN_THROW(json_parse, "uint " << fmt_name(name, title) << " is of incorrect type");
      dest = value.asUInt();
    }

    static void to_uint_optional(const Json::Value& root,
				 unsigned int& dest,
				 const std::string& name,
				 const unsigned int default_value,
				 const std::string& title)
    {
      const Json::Value& value = root[name];
      if (value.isNull())
	{
	  dest = default_value;
	  return;
	}
      if (!value.isUInt())
	OPENVPN_THROW(json_parse, "uint " << fmt_name(name, title) << " is of incorrect type");
      dest = value.asUInt();
    }

    static void to_bool(const Json::Value& root, bool& dest, const std::string& name, const std::string& title)
    {
      const Json::Value& value = root[name];
      if (value.isNull())
	OPENVPN_THROW(json_parse, "bool " << fmt_name(name, title) << " is missing");
      if (!value.isBool())
	OPENVPN_THROW(json_parse, "bool " << fmt_name(name, title) << " is of incorrect type");
      dest = value.asBool();
    }

    template <typename T>
    static void to_vector(const Json::Value& root, T& vec, const std::string& name, const std::string& title)
    {
      const Json::Value& array = root[name];
      if (array.isNull())
	return;
      if (!array.isArray())
	OPENVPN_THROW(json_parse, "array " << fmt_name(name, title) << " is of incorrect type");
      for (unsigned int i = 0; i < array.size(); ++i)
	{
	  vec.emplace_back();
	  vec.back().from_json(array[i], fmt_name(name, title));
	}
    }

    static std::string get_string(const Json::Value& root, const std::string& name, const std::string& title)
    {
      std::string ret;
      to_string(root, ret, name, title);
      return ret;
    }

    static std::string get_string_optional(const Json::Value& root,
					   const std::string& name,
					   const std::string& default_value,
					   const std::string& title)
    {
      std::string ret;
      to_string_optional(root, ret, name, default_value, title);
      return ret;
    }

    static std::string get_string(const Json::Value& root, const std::string& name)
    {
      return get_string(root, name, "");
    }

    static int get_int(const Json::Value& root, const std::string& name, const std::string& title)
    {
      int ret;
      to_int(root, ret, name, title);
      return ret;
    }

    static int get_int(const Json::Value& root, const std::string& name)
    {
      return get_int(root, name, "");
    }

    static unsigned int get_uint(const Json::Value& root, const std::string& name, const std::string& title)
    {
      unsigned int ret;
      to_uint(root, ret, name, title);
      return ret;
    }

    static unsigned int get_uint(const Json::Value& root, const std::string& name)
    {
      return get_uint(root, name, "");
    }

    static unsigned int get_uint_optional(const Json::Value& root, const std::string& name, const unsigned int default_value, const std::string& title)
    {
      unsigned int ret;
      to_uint_optional(root, ret, name, default_value, title);
      return ret;
    }

    static unsigned int get_uint_optional(const Json::Value& root, const std::string& name, const unsigned int default_value)
    {
      return get_uint_optional(root, name, default_value, "");
    }

    static bool get_bool(const Json::Value& root, const std::string& name, const std::string& title)
    {
      bool ret;
      to_bool(root, ret, name, title);
      return ret;
    }

    static bool get_bool(const Json::Value& root, const std::string& name)
    {
      return get_bool(root, name, "");
    }

    static bool get_bool_optional(const Json::Value& root, const std::string& name)
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
	return false;
    }

    static const Json::Value& get_dict(const Json::Value& root, const std::string& name, const bool optional, const std::string& title)
    {
      const Json::Value& value = root[name];
      if (value.isNull())
	{
	  if (optional)
	    return value;
	  OPENVPN_THROW(json_parse, "dictionary " << fmt_name(name, title) << " is missing");
	}
      if (!value.isObject())
	OPENVPN_THROW(json_parse, "dictionary " << fmt_name(name, title) << " is of incorrect type");
      return value;
    }

    static const Json::Value& cast_dict(const Json::Value& value, const bool optional, const std::string& title)
    {
      if (value.isNull())
	{
	  if (optional)
	    return value;
	  OPENVPN_THROW(json_parse, "dictionary cast " << title << " is null");
	}
      if (!value.isObject())
	OPENVPN_THROW(json_parse, "dictionary cast " << title << " is of incorrect type");
      return value;
    }

    static const Json::Value& get_array(const Json::Value& root, const std::string& name, const bool optional, const std::string& title)
    {
      const Json::Value& value = root[name];
      if (value.isNull())
	{
	  if (optional)
	    return value;
	  OPENVPN_THROW(json_parse, "array " << fmt_name(name, title) << " is missing");
	}
      if (!value.isArray())
	OPENVPN_THROW(json_parse, "array " << fmt_name(name, title) << " is of incorrect type");
      return value;
    }

    static const Json::Value& get_dict(const Json::Value& root, const std::string& name, const bool optional)
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

  private:
    static std::string fmt_name(const std::string& name, const std::string& title)
    {
      if (!title.empty())
	return title + '.' + name;
      else
	return name;
    }
  };
}

#endif
