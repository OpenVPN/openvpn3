#ifndef OPENVPN_COMMON_OPTIONS_H
#define OPENVPN_COMMON_OPTIONS_H

#include <string>
#include <sstream>
#include <vector>

#include <boost/unordered_map.hpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/types.hpp>
#include <openvpn/common/typeinfo.hpp>
#include <openvpn/common/split.hpp>

namespace openvpn {

  OPENVPN_EXCEPTION(option_error);

  class Option : public std::vector<std::string>
  {
  public:
    void min_args(const size_t n) const
    {
      const size_t s = size();
      if (s < n)
	{
	  std::ostringstream out;
	  out << err_ref() << " must have at least " << n << " arguments";
	  throw option_error(out.str());
	}
    }

    void exact_args(const size_t n) const
    {
      const size_t s = size();
      if (s != n)
	{
	  std::ostringstream out;
	  out << err_ref() << " must have exactly " << n << " arguments";
	  throw option_error(out.str());
	}
    }

    template <typename T>
    T get_type(const size_t index) const
    {
      min_args(index+1);
      try {
	return types<T>::parse((*this)[index]);
      }
      catch (std::exception& e)
	{
	  throw option_error(type_error<T>(e, index));
	}
    }

    template <typename T>
    void get_type(const size_t index, T& ret) const
    {
      min_args(index+1);
      try {
	types<T>::parse((*this)[index], ret);
      }
      catch (std::exception& e)
	{
	  throw option_error(type_error<T>(e, index));
	}
    }

    const std::string& get(const size_t index) const
    {
      min_args(index+1);
      return (*this)[index];
    }

#ifdef OPENVPN_DEBUG
    std::string debug_render() const
    {
      std::ostringstream out;
      for (const_iterator i = begin(); i != end(); i++)
	out << '[' << *i << "] ";
      return out.str();
    }
#endif

  private:
    std::string err_ref() const
    {
      std::string ret = "option";
      if (size())
	{
	  ret += " '";
	  ret += (*this)[0];
	  ret += '\'';
	}
      return ret;
    }

    template <typename T>
    std::string type_error(std::exception& e, const size_t index) const
    {
      std::ostringstream out;
      out << "in " << err_ref() << ": unable to parse '" << (*this)[index]
	  << "' as type " << types<T>::name() << ": " << e.what();
      return out.str();
    }
  };

  class OptionList : public std::vector<Option>
  {
  public:
    typedef StandardLex Lex;
    typedef std::vector<unsigned int> IndexList;
    typedef boost::unordered_map<std::string, IndexList> IndexMap;
    typedef std::pair<std::string, IndexList> IndexPair;

    static OptionList parse_from_csv(const std::string& str)
    {
      OptionList ret;
      std::vector<std::string> list = split_by_char<std::vector<std::string>, Lex>(str, ',');
      for (std::vector<std::string>::const_iterator i = list.begin(); i != list.end(); i++)
	{
	  const Option opt = split_by_space<Option, Lex, SpaceMatch>(*i);
	  if (opt.size())
	    ret.push_back(opt);
	}
      ret.build_map();
      return ret;
    }

    static OptionList parse_from_config(const std::string& str)
    {
      OptionList ret;
      std::stringstream in(str);
      std::string line;
      int line_num = 0;
      bool in_multiline = false;
      Option multiline;
      while (std::getline(in, line))
	{
	  ++line_num;
	  if (in_multiline)
	    {
	      if (is_close_tag(line, multiline[0]))
		{
		  ret.push_back(multiline);
		  multiline.clear();
		  in_multiline = false;
		}
	      else
		{
		  multiline[1] += line;
		  multiline[1] += '\n';
		}
	    }
	  else if (!ignore_line(line))
	    {
	      Option opt = split_by_space<Option, Lex, SpaceMatch>(line);
	      if (opt.size())
		{
		  if (is_open_tag(opt[0]))
		    {
		      if (opt.size() > 1)
			OPENVPN_THROW(option_error, "line " << line_num << ": option <" << opt[0] << "> is followed by extraneous text");
		      untag_open_tag(opt[0]);
		      opt.push_back("");
		      multiline = opt;
		      in_multiline = true;
		    }
		  else
		    ret.push_back(opt);
		}
	    }
	}
      if (in_multiline)
	OPENVPN_THROW(option_error, "option <" << multiline[0] << "> was not properly closed out");
      ret.build_map();
      return ret;
    }

    const Option& get_first(const std::string& name) const
    {
      OptionList::IndexMap::const_iterator e = map_.find(name);
      if (e != map_.end() && !e->second.empty())
	return (*this)[e->second[0]];
      else
	OPENVPN_THROW(option_error, "option '" << name << "' not found");
    }

    const Option* get_ptr(const std::string& name) const
    {
      OptionList::IndexMap::const_iterator e = map_.find(name);
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

    bool exists(const std::string& name) const
    {
      const Option* o = get_ptr(name);
      return o != NULL;
    }

    const std::string& get(const std::string& name, size_t index) const
    {
      const Option& o = get(name);
      return o.get(index);
    }

    const std::string get_optional(const std::string& name, size_t index) const
    {
      const Option* o = get_ptr(name);
      if (o)
	return o->get(index);
      else
	return "";
    }

    template <typename T>
    T get_type(const std::string& name, size_t index) const
    {
      const Option& o = get(name);
      return o.get_type<T>(index);
    }

    template <typename T>
    void get_type(const std::string& name, size_t index, T& ret) const
    {
      const Option& o = get(name);
      o.get_type<T>(index, ret);
    }

#ifdef OPENVPN_DEBUG
    std::string debug_render() const
    {
      std::ostringstream out;
      for (size_t i = 0; i < size(); i++)
	out << i << ' ' << (*this)[i].debug_render() << std::endl;
      return out.str();
    }

    std::string debug_render_map() const
    {
      std::ostringstream out;
      for (IndexMap::const_iterator i = map_.begin(); i != map_.end(); i++)
	{
	  out << i->first << " [";
	  for (IndexList::const_iterator j = i->second.begin(); j != i->second.end(); j++)
	    out << ' ' << *j;
	  out << " ]" << std::endl;
	}
      return out.str();
    }
#endif

    const IndexMap& map() const { return map_; }

  private:
    void build_map()
    {
      for (size_t i = 0; i < size(); i++)
	{
	  const Option& opt = (*this)[i];
	  if (!opt.empty())
	    map_[opt[0]].push_back(i);
	}
    }

    // return true if line is blank or a comment
    static bool ignore_line(const std::string& line)
    {
      for (std::string::const_iterator i = line.begin(); i != line.end(); i++)
	{
	  const char c = *i;
	  if (!SpaceMatch::is_space(c))
	    return c == '#' || c == ';';
	}
      return true;
    }

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

    IndexMap map_;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_OPTIONS_H
