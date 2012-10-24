//
//  split.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_SPLIT_H
#define OPENVPN_COMMON_SPLIT_H

#include <string>
#include <vector>

#include <openvpn/common/lex.hpp>

namespace openvpn {
  namespace Split {
    enum {
      TRIM_LEADING_SPACES=(1<<0),
      TRIM_SPECIAL=(1<<1), // trims quotes (but respects their content)
    };

    template <typename V, typename LEX>
    inline void by_char_void(V& ret, const std::string& input, const char split_by, const unsigned int flags=0, const unsigned int max_terms=~0)
    {
      LEX lex;
      unsigned int nterms = 0;
      std::string term;
      for (std::string::const_iterator i = input.begin(); i != input.end(); ++i)
	{
	  const char c = *i;
	  lex.put(c);
	  if (!lex.in_quote() && c == split_by && nterms < max_terms)
	    {
	      ret.push_back(term);
	      ++nterms;
	      term = "";
	    }
	  else if ((!(flags & TRIM_SPECIAL) || lex.available())
		   && (!(flags & TRIM_LEADING_SPACES) || !term.empty() || !SpaceMatch::is_space(c)))
	    term += c;
	}
      ret.push_back(term);
    }

    template <typename V, typename LEX>
    inline V by_char(const std::string& input, const char split_by, const unsigned int flags=0, const unsigned int max_terms=~0)
    {
      V ret;
      by_char_void<V, LEX>(ret, input, split_by, flags, max_terms);
      return ret;
    }

    template <typename V, typename LEX, typename SPACE>
    inline void by_space_void(V& ret, const std::string& input)
    {
      LEX lex;

      std::string term;
      bool defined = false;
      for (std::string::const_iterator i = input.begin(); i != input.end(); ++i)
	{
	  const char c = *i;
	  lex.put(c);
	  if (lex.in_quote())
	    defined = true;
	  if (lex.available())
	    {
	      const char tc = lex.get();
	      if (!SPACE::is_space(tc) || lex.in_quote())
		{
		  defined = true;
		  term += tc;
		}
	      else if (defined)
		{
		  ret.push_back(term);
		  term = "";
		  defined = false;
		}
	    }
	}
      if (defined)
	ret.push_back(term);
    }

    template <typename V, typename LEX, typename SPACE>
    inline V by_space(const std::string& input)
    {
      V ret;
      by_space_void<V, LEX, SPACE>(ret, input);
      return ret;
    }
  }
} // namespace openvpn

#endif // OPENVPN_COMMON_SPLIT_H
