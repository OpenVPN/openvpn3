//
//  options.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_OPTIONS_H
#define OPENVPN_COMMON_OPTIONS_H

#include <string>
#include <sstream>
#include <vector>
#include <algorithm> // for std::sort

#include <boost/cstdint.hpp> // for boost::uint64_t
#include <boost/algorithm/string.hpp> // for boost::algorithm::starts_with, ends_with
#include <boost/unordered_map.hpp>

#include <openvpn/common/rc.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/types.hpp>
#include <openvpn/common/typeinfo.hpp>
#include <openvpn/common/number.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/split.hpp>
#include <openvpn/common/splitlines.hpp>
#include <openvpn/common/unicode.hpp>

namespace openvpn {

  OPENVPN_EXCEPTION(option_error);

  class Option
  {
  public:
    enum {
      MULTILINE = 0x8000000,
    };

    // Validate string by size and multiline status.
    // OR max_len with MULTILINE to allow multiline string.
    // Return values:
    enum validate_status {
      STATUS_GOOD,
      STATUS_MULTILINE,
      STATUS_LENGTH,
    };

    static validate_status validate(const std::string& str, const size_t max_len)
    {
      const size_t pos = str.find_first_of("\r\n");
      const size_t len = max_len & ((size_t)MULTILINE-1); // NOTE -- use smallest flag value here
      if (pos != std::string::npos && !(max_len & MULTILINE))
	return STATUS_MULTILINE;
      else if (len > 0 && Unicode::utf8_length(str) > len)
	return STATUS_LENGTH;
      else
	return STATUS_GOOD;
    }

    static const char *validate_status_description(const validate_status status)
    {
      switch (status)
	{
	case STATUS_GOOD:
	  return "good";
	case STATUS_MULTILINE:
	  return "multiline";
	case STATUS_LENGTH:
	  return "too long";
	default:
	  return "unknown";
	}
    }

    void min_args(const size_t n) const
    {
      const size_t s = data.size();
      if (s < n)
	OPENVPN_THROW(option_error, err_ref() << " must have at least " << n << " arguments");
    }

    void exact_args(const size_t n) const
    {
      const size_t s = data.size();
      if (s != n)
	OPENVPN_THROW(option_error, err_ref() << " must have exactly " << n << " arguments");
    }

    void validate_arg(const size_t index, const size_t max_len) const
    {
      if (max_len > 0 && index < data.size())
	{
	  const validate_status status = validate(data[index], max_len);
	  if (status != STATUS_GOOD)
	    OPENVPN_THROW(option_error, err_ref() << " is " << validate_status_description(status));
	}
    }

    static void validate_string(const std::string& name, const std::string& str, const size_t max_len)
    {
      const validate_status status = validate(str, max_len);
      if (status != STATUS_GOOD)
	OPENVPN_THROW(option_error, name << " is " << validate_status_description(status));
    }

    std::string printable_directive() const
    {
      if (data.size() > 0)
	return Unicode::utf8_printable(data[0], 32);
      else
	return "";
    }

    const std::string& get(const size_t index, const size_t max_len) const
    {
      min_args(index+1);
      validate_arg(index, max_len);
      return data[index];
    }

    std::string get_optional(const size_t index, const size_t max_len) const
    {
      validate_arg(index, max_len);
      if (index < data.size())
	return data[index];
      else
	return "";
    }

    const std::string* get_ptr(const size_t index, const size_t max_len) const
    {
      validate_arg(index, max_len);
      if (index < data.size())
	return &data[index];
      else
	return NULL;
    }

    std::string render() const
    {
      std::ostringstream out;
      for (std::vector<std::string>::const_iterator i = data.begin(); i != data.end(); ++i)
	out << '[' << Unicode::utf8_printable(*i, 0 | Unicode::UTF8_PASS_FMT) << "] ";
      return out.str();
    }

    // delegate to data
    size_t size() const { return data.size(); }
    bool empty() const { return data.empty(); }
    void push_back(const std::string& item) { data.push_back(item); }
    void clear() { data.clear(); }
    void reserve(const size_t n) { data.reserve(n); }

    // raw references to data
    const std::string& ref(const size_t i) const { return data[i]; }
    std::string& ref(const size_t i) { return data[i]; }

  private:
    std::string err_ref() const
    {
      std::string ret = "option";
      if (data.size())
	{
	  ret += " '";
	  ret += printable_directive();
	  ret += '\'';
	}
      return ret;
    }

    std::vector<std::string> data;
  };

  class OptionList : public std::vector<Option>
  {
  public:
    typedef std::vector<unsigned int> IndexList;
    typedef boost::unordered_map<std::string, IndexList> IndexMap;
    typedef std::pair<std::string, IndexList> IndexPair;

    static bool is_comment(const char c)
    {
      return c == '#' || c == ';';
    }

    // standard lex filter that doesn't understand end-of-line comments
    typedef StandardLex Lex;

    // special lex filter that recognizes end-of-line comments
    class LexComment
    {
    public:
      LexComment() : in_quote_(false), in_comment(false), backslash(false), ch(-1) {}

      void put(char c)
      {
	if (in_comment)
	  {
	    ch = -1;
	  }
	else if (backslash)
	  {
	    ch = c;
	    backslash = false;
	  }
	else if (c == '\\')
	  {
	    backslash = true;
	    ch = -1;
	  }
	else if (c == '\"')
	  {
	    in_quote_ = !in_quote_;
	    ch = -1;
	  }
	else if (is_comment(c) && !in_quote_)
	  {
	    in_comment = true;
	    ch = -1;
	  }
	else
	  {
	    ch = c;
	  }
      }

      bool available() const { return ch != -1; }
      int get() const { return ch; }
      void reset() { ch = -1; }

      bool in_quote() const { return in_quote_; }

    private:
      bool in_quote_;
      bool in_comment;
      bool backslash;
      int ch;
    };

    class Limits
    {
    public:
      Limits(const std::string& error_message,
	     const boost::uint64_t max_bytes_arg,
	     const size_t extra_bytes_per_opt_arg,
	     const size_t extra_bytes_per_term_arg,
	     const size_t max_line_len_arg,
	     const size_t max_directive_len_arg)
	: bytes(0),
	  max_bytes(max_bytes_arg),
	  extra_bytes_per_opt(extra_bytes_per_opt_arg),
	  extra_bytes_per_term(extra_bytes_per_term_arg),
	  max_line_len(max_line_len_arg),
	  max_directive_len(max_directive_len_arg),
	  err(error_message) {}

      void add_bytes(const size_t n)
      {
	bytes += n;
	check_overflow();
      }

      void add_string(const std::string& str)
      {
	bytes += str.length();
	check_overflow();
      }

      void add_term()
      {
	bytes += extra_bytes_per_term;
	check_overflow();
      }

      void add_opt()
      {
	bytes += extra_bytes_per_opt;
	check_overflow();
      }

      size_t get_max_line_len() const
      {
	return max_line_len;
      }

      boost::uint64_t get_bytes() const
      {
	return bytes;
      }

      void validate_directive(const Option& opt)
      {
	opt.validate_arg(0, max_directive_len);
      }

    private:
      void check_overflow()
      {
	if (bytes >= max_bytes)
	  error();
      }

      void error()
      {
	throw option_error(err);
      }

      boost::uint64_t bytes;
      const boost::uint64_t max_bytes;
      const size_t extra_bytes_per_opt;
      const size_t extra_bytes_per_term;
      const size_t max_line_len;
      const size_t max_directive_len;
      const std::string err;
    };

    class KeyValue : public RC<thread_unsafe_refcount>
    {
    public:
      typedef boost::intrusive_ptr<KeyValue> Ptr;

      KeyValue() : key_priority(0) {}
      KeyValue(const std::string& key_arg, const std::string& value_arg, const int key_priority_arg=0)
	: key(key_arg), value(value_arg), key_priority(key_priority_arg) {}

      size_t combined_length() const
      {
	return key.length() + value.length();
      }

      Option convert_to_option(Limits* lim) const
      {
	bool newline_present = false;
	Option opt;
	const std::string unesc_value = unescape(value, newline_present);
	opt.push_back(key);
	if (newline_present || singular_arg(key))
	  opt.push_back(unesc_value);
	else if (unesc_value != "NOARGS")
	  Split::by_space_void<Option, Lex, SpaceMatch, Limits>(opt, unesc_value, lim);
	return opt;
      }

      void split_priority()
      {
	// look for usage such as: remote.7
	const size_t dp = key.find_last_of(".");
	if (dp != std::string::npos)
	  {
	    const size_t tp = dp + 1;
	    if (tp < key.length())
	      {
		const char *tail = key.c_str() + tp;
		try {
		  key_priority = parse_number<int>(tail);
		  key = key.substr(0, dp);
		}
		catch (const number_parse_exception& e)
		  {
		    ;
		  }
	      }
	  }
      }

      static bool compare(const Ptr& a, const Ptr& b)
      {
	const int cmp = a->key.compare(b->key);
	if (cmp < 0)
	  return true;
	else if (cmp > 0)
	  return false;
	else
	  return a->key_priority < b->key_priority;
      }

      std::string key;
      std::string value;
      int key_priority;

    private:
      static std::string unescape(const std::string& value, bool& newline_present)
      {
	std::string ret;
	ret.reserve(value.length());

	bool bs = false;
	for (size_t i = 0; i < value.length(); ++i)
	  {
	    const char c = value[i];
	    if (bs)
	      {
		if (c == 'n')
		  {
		    ret += '\n';
		    newline_present = true;
		  }
		else if (c == '\\')
		  ret += '\\';
		else
		  {
		    ret += '\\';
		    ret += c;
		  }
		bs = false;
	      }
	    else
	      {
		if (c == '\\')
		  bs = true;
		else
		  ret += c;
	      }
	  }
	if (bs)
	  ret += '\\';
	return ret;
      }

      static bool singular_arg(const std::string& key)
      {
	bool upper = false;
	bool lower = false;
	for (size_t i = 0; i < key.length(); ++i)
	  {
	    const char c = key[i];
	    if (c >= 'a' && c <= 'z')
	      lower = true;
	    else if (c >= 'A' && c <= 'Z')
	      upper = true;
	  }
	return upper && !lower;
      }
    };

    struct KeyValueList : public std::vector<KeyValue::Ptr>
    {
      void preprocess()
      {
	split_priority();
	sort();
      }

      void split_priority()
      {
	for (iterator i = begin(); i != end(); ++i)
	  {
	    KeyValue& kv = **i;
	    kv.split_priority();
	  }
      }

      void sort()
      {
	std::sort(begin(), end(), KeyValue::compare);
      }
    };

    static OptionList parse_from_csv_static(const std::string& str, Limits* lim)
    {
      OptionList ret;
      ret.parse_from_csv(str, lim);
      ret.update_map();
      return ret;
    }

    static OptionList parse_from_config_static(const std::string& str, Limits* lim)
    {
      OptionList ret;
      ret.parse_from_config(str, lim);
      ret.update_map();
      return ret;
    }

    void clear()
    {
      std::vector<Option>::clear();
      map_.clear();
    }

    // caller should call update_map() after this function
    void parse_from_csv(const std::string& str, Limits* lim)
    {
      if (lim)
	lim->add_string(str);
      std::vector<std::string> list = Split::by_char<std::vector<std::string>, Lex, Limits>(str, ',', 0, ~0, lim);
      for (std::vector<std::string>::const_iterator i = list.begin(); i != list.end(); ++i)
	{
	  const Option opt = Split::by_space<Option, Lex, SpaceMatch, Limits>(*i, lim);
	  if (opt.size())
	    {
	      if (lim)
		{
		  lim->add_opt();
		  lim->validate_directive(opt);
		}
	      push_back(opt);
	    }
	}
    }

    // caller may want to call list.preprocess() before this function
    // caller should call update_map() after this function
    void parse_from_key_value_list(const KeyValueList& list, Limits* lim)
    {
      for (KeyValueList::const_iterator i = list.begin(); i != list.end(); ++i)
	{
	  const KeyValue& kv = **i;
	  if (lim)
	    lim->add_bytes(kv.combined_length());
	  const Option opt = kv.convert_to_option(lim);
	  if (lim)
	    {
	      lim->add_opt();
	      lim->validate_directive(opt);
	    }
	  push_back(opt);
	}
    }

    // caller should call update_map() after this function
    void parse_from_config(const std::string& str, Limits* lim)
    {
      if (lim)
	lim->add_string(str);

      SplitLines in(str, lim ? lim->get_max_line_len() : 0);
      int line_num = 0;
      bool in_multiline = false;
      Option multiline;
      while (in(true))
	{
	  ++line_num;
	  if (in.line_overflow())
	    line_too_long(line_num);
	  const std::string& line = in.line_ref();
	  if (in_multiline)
	    {
	      if (is_close_tag(line, multiline.ref(0)))
		{
		  if (lim)
		    {
		      lim->add_opt();
		      lim->validate_directive(multiline);
		    }
		  push_back(multiline);
		  multiline.clear();
		  in_multiline = false;
		}
	      else
		{
		  std::string& mref = multiline.ref(1);
		  mref += line;
		  mref += '\n';
		}
	    }
	  else if (!ignore_line(line))
	    {
	      Option opt = Split::by_space<Option, LexComment, SpaceMatch, Limits>(line, lim);
	      if (opt.size())
		{
		  if (is_open_tag(opt.ref(0)))
		    {
		      if (opt.size() > 1)
			extraneous_err(line_num, "option", opt);
		      untag_open_tag(opt.ref(0));
		      opt.push_back("");
		      multiline = opt;
		      in_multiline = true;
		    }
		  else
		    {
		      if (lim)
			{
			  lim->add_opt();
			  lim->validate_directive(opt);
			}
		      push_back(opt);
		    }
		}
	    }
	}
      if (in_multiline)
	not_closed_out_err("option", multiline);
    }
    
    // caller should call update_map() after this function
    void parse_meta_from_config(const std::string& str, const std::string& tag, Limits* lim)
    {
      SplitLines in(str, lim ? lim->get_max_line_len() : 0);
      int line_num = 0;
      bool in_multiline = false;
      Option multiline;
      const std::string prefix = tag + "_";
      while (in(true))
	{
	  ++line_num;
	  if (in.line_overflow())
	    line_too_long(line_num);
	  std::string& line = in.line_ref();
	  if (boost::algorithm::starts_with(line, "# "))
	    {
	      line = std::string(line, 2);
	      if (in_multiline)
		{
		  if (is_close_meta_tag(line, prefix, multiline.ref(0)))
		    {
		      if (lim)
			{
			  lim->add_opt();
			  lim->validate_directive(multiline);
			}
		      push_back(multiline);
		      multiline.clear();
		      in_multiline = false;
		    }
		  else
		    {
		      std::string& mref = multiline.ref(1);
		      mref += line;
		      mref += '\n';
		    }
		}
	      else if (boost::algorithm::starts_with(line, prefix))
		{
		  Option opt = Split::by_char<Option, NullLex, Limits>(std::string(line, prefix.length()), '=', 0, 1, lim);
		  if (opt.size())
		    {
		      if (is_open_meta_tag(opt.ref(0)))
			{
			  if (opt.size() > 1)
			    extraneous_err(line_num, "meta option", opt);
			  untag_open_meta_tag(opt.ref(0));
			  opt.push_back("");
			  multiline = opt;
			  in_multiline = true;
			}
		      else
			{
			  if (lim)
			    {
			      lim->add_opt();
			      lim->validate_directive(opt);
			    }
			  push_back(opt);
			}
		    }
		}
	    }
	}
      if (in_multiline)
	not_closed_out_err("meta option", multiline);
    }

    // Append elements in other to self,
    // caller should call update_map() after this function.
    void extend(const OptionList& other)
    {
      reserve(size() + other.size());
      for (std::vector<Option>::const_iterator i = other.begin(); i != other.end(); ++i)
	push_back(*i);
    }

    // Append elements in other having given name to self,
    // caller should call update_map() after this function.
    void extend(const OptionList& other, const std::string& name)
    {
      IndexMap::const_iterator oi = other.map().find(name);
      if (oi != other.map().end())
	for (IndexList::const_iterator i = oi->second.begin(); i != oi->second.end(); ++i)
	  push_back(other[*i]);
    }

    // Append to self only those elements in other that do not exist
    // in self, caller should call update_map() after this function.
    void extend_nonexistent(const OptionList& other)
    {
      for (std::vector<Option>::const_iterator i = other.begin(); i != other.end(); ++i)
	{
	  const Option& opt = *i;
	  if (map().find(opt.ref(0)) == map().end())
	      push_back(*i);
	}
    }

    const Option& get_first(const std::string& name) const
    {
      IndexMap::const_iterator e = map_.find(name);
      if (e != map_.end() && !e->second.empty())
	return (*this)[e->second[0]];
      else
	OPENVPN_THROW(option_error, "option '" << name << "' not found");
    }

    const Option* get_ptr(const std::string& name) const
    {
      IndexMap::const_iterator e = map_.find(name);
      if (e != map_.end() && !e->second.empty())
	{
	  if (e->second.size() == 1)
	    return &((*this)[e->second[0]]);
	  else
	    OPENVPN_THROW(option_error, "more than one instance of option '" << name << '\'');
	}
      else
	return NULL;
    }

    const Option& get(const std::string& name) const
    {
      const Option* o = get_ptr(name);
      if (o)
	return *o;
      else
	OPENVPN_THROW(option_error, "option '" << name << "' not found");
    }

    const IndexList& get_index(const std::string& name) const
    {
      IndexMap::const_iterator e = map_.find(name);
      if (e != map_.end() && !e->second.empty())
	return e->second;
      else
	OPENVPN_THROW(option_error, "option '" << name << "' not found");
    }

    const IndexList* get_index_ptr(const std::string& name) const
    {
      IndexMap::const_iterator e = map_.find(name);
      if (e != map_.end() && !e->second.empty())
	return &e->second;
      else
	return NULL;
    }

    // concatenate all one-arg directives of a given name, in index order
    std::string cat(const std::string& name) const
    {
      std::string ret;
      const OptionList::IndexList* il = get_index_ptr(name);
      if (il)
	{
	  size_t size = 0;
	  OptionList::IndexList::const_iterator i;
	  for (i = il->begin(); i != il->end(); ++i)
	    {
	      const Option& o = (*this)[*i];
	      if (o.size() == 2)
		size += o.ref(1).length() + 1;
	      else
		OPENVPN_THROW(option_error, "option '" << name << "' (" << o.size() << ") must have exactly one parameter");
	    }
	  ret.reserve(size);
	  for (i = il->begin(); i != il->end(); ++i)
	    {
	      const Option& o = (*this)[*i];
	      if (o.size() >= 2)
		{
		  ret += o.ref(1);
		  string::add_trailing_in_place(ret, '\n');
		}
	    }
	}
      return ret;
    }

    bool exists_unique(const std::string& name) const
    {
      const Option* o = get_ptr(name);
      return o != NULL;
    }

    bool exists(const std::string& name) const
    {
      const OptionList::IndexList* il = get_index_ptr(name);
      return il != NULL;
    }

    const std::string& get(const std::string& name, size_t index, const size_t max_len) const
    {
      const Option& o = get(name);
      return o.get(index, max_len);
    }

    const std::string get_optional(const std::string& name, size_t index, const size_t max_len) const
    {
      const Option* o = get_ptr(name);
      if (o)
	return o->get(index, max_len);
      else
	return "";
    }

    std::string render() const
    {
      std::ostringstream out;
      for (size_t i = 0; i < size(); ++i)
	out << i << ' ' << (*this)[i].render() << std::endl;
      return out.str();
    }

    std::string render_map() const
    {
      std::ostringstream out;
      for (IndexMap::const_iterator i = map_.begin(); i != map_.end(); ++i)
	{
	  out << i->first << " [";
	  for (IndexList::const_iterator j = i->second.begin(); j != i->second.end(); ++j)
	    out << ' ' << *j;
	  out << " ]" << std::endl;
	}
      return out.str();
    }

    void add_item(const Option& opt) // updates map as well
    {
      if (!opt.empty())
	{
	  const size_t i = size();
	  push_back(opt);
	  map_[opt.ref(0)].push_back(i);
	}
    }

    const IndexMap& map() const { return map_; }

    void update_map()
    {
      map_.clear();
      for (size_t i = 0; i < size(); ++i)
	{
	  const Option& opt = (*this)[i];
	  if (!opt.empty())
	    map_[opt.ref(0)].push_back(i);
	}
    }

    // return true if line is blank or a comment
    static bool ignore_line(const std::string& line)
    {
      for (std::string::const_iterator i = line.begin(); i != line.end(); ++i)
	{
	  const char c = *i;
	  if (!SpaceMatch::is_space(c))
	    return is_comment(c);
	}
      return true;
    }

    // multiline tagging

    // return true if string is a tag, e.g. "<ca>"
    static bool is_open_tag(const std::string& str)
    {
      const size_t n = str.length();
      return n >= 3 && str[0] == '<' && str[1] != '/' && str[n-1] == '>';
    }

    // return true if string is a tag, e.g. "<ca>"
    static bool is_close_tag(const std::string& str, const std::string& tag)
    {
      const size_t n = str.length();
      return n >= 4 && str[0] == '<' && str[1] == '/' && str.substr(2, n-3) == tag && str[n-1] == '>';
    }

    // remove <> chars from open tag
    static void untag_open_tag(std::string& str)
    {
      const size_t n = str.length();
      if (n >= 3)
	str = str.substr(1, n-2);
    }

  private:
    // multiline tagging (meta)

    // return true if string is a meta tag, e.g. WEB_CA_BUNDLE_START
    static bool is_open_meta_tag(const std::string& str)
    {
      return boost::algorithm::ends_with(str, "_START");
    }

    // return true if string is a tag, e.g. WEB_CA_BUNDLE_STOP
    static bool is_close_meta_tag(const std::string& str, const std::string& prefix, const std::string& tag)
    {
      return prefix + tag + "_STOP" == str;
    }

    // remove trailing "_START" from open tag
    static void untag_open_meta_tag(std::string& str)
    {
      const size_t n = str.length();
      if (n >= 6)
	str = std::string(str, 0, n - 6);
    }

    static void extraneous_err(const int line_num, const char *type, const Option& opt)
    {
      OPENVPN_THROW(option_error, "line " << line_num << ": " << type << " <" << opt.printable_directive() << "> is followed by extraneous text");
    }

    static void not_closed_out_err(const char *type, const Option& opt)
    {
      OPENVPN_THROW(option_error, type << " <" << opt.printable_directive() << "> was not properly closed out");
    }

    static void line_too_long(const int line_num)
    {
      OPENVPN_THROW(option_error, "line " << line_num << " is too long");
    }

    IndexMap map_;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_OPTIONS_H
