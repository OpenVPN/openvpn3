#ifndef OPENVPN_COMMON_PARSEOPT_H
#define OPENVPN_COMMON_PARSEOPT_H

#include <string>
#include <sstream>
#include <vector>

#include <boost/unordered_map.hpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/types.hpp>
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
	  out << "option";
	  if (n)
	    out << " '" << (*this)[0] << '\'';
	  out << " must have at least " << n << " arguments";
	  throw option_error(out.str());
	}
    }

    void exact_args(const size_t n) const
    {
      const size_t s = size();
      if (s != n)
	{
	  std::ostringstream out;
	  out << "option";
	  if (n)
	    out << " '" << (*this)[0] << '\'';
	  out << " must have exactly " << n << " arguments";
	  throw option_error(out.str());
	}
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
	  Option opt = split_by_space<Option, Lex, SpaceMatch>(*i);
	  if (opt.size())
	    ret.push_back(opt);
	}
      ret.build_map();
      return ret;
    }

    bool exists(const std::string& name) const
    {
      OptionList::IndexMap::const_iterator e = map_.find(name);
      return e != map_.end() && !e->second.empty();
    }

    const Option& get(const std::string& name) const
    {
      OptionList::IndexMap::const_iterator e = map_.find(name);
      if (e != map_.end() && !e->second.empty())
	{
	  if (e->second.size() == 1)
	    return (*this)[e->second[0]];
	  else
	    OPENVPN_THROW(option_error, "more than one instance of option '" << name << '\'');
	}
      else
	OPENVPN_THROW(option_error, "option '" << name << "' not found");
    }

    const Option* get_ptr(const std::string& name) const
    {
      OptionList::IndexMap::const_iterator e = map_.find(name);
      if (e != map_.end() && e->second.size() == 1)
	return &((*this)[e->second[0]]);
      else
	return NULL;
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

    IndexMap map_;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_PARSEOPT_H
