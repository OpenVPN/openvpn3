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

#include <openvpn/common/types.hpp>
#include <openvpn/common/lex.hpp>

namespace openvpn {
  namespace Split {
    enum {
      TRIM_LEADING_SPACES=(1<<0),
      TRIM_SPECIAL=(1<<1), // trims quotes (but respects their content)
    };

    struct NullLimit
    {
      void add_term() {}
    };

    template <typename V, typename LEX, typename LIM>
    inline void by_char_void(V& ret, const std::string& input, const char split_by, const unsigned int flags=0, const unsigned int max_terms=~0, LIM* lim=NULL)
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
	      if (lim)
		lim->add_term();
	      ret.push_back(term);
	      ++nterms;
	      term = "";
	    }
	  else if ((!(flags & TRIM_SPECIAL) || lex.available())
		   && (!(flags & TRIM_LEADING_SPACES) || !term.empty() || !SpaceMatch::is_space(c)))
	    term += c;
	}
      if (lim)
	lim->add_term();
      ret.push_back(term);
    }

    template <typename V, typename LEX, typename LIM>
    inline V by_char(const std::string& input, const char split_by, const unsigned int flags=0, const unsigned int max_terms=~0, LIM* lim=NULL)
    {
      V ret;
      by_char_void<V, LEX, LIM>(ret, input, split_by, flags, max_terms, lim);
      return ret;
    }

    template <typename V, typename LEX, typename SPACE, typename LIM>
    inline void by_space_void(V& ret, const std::string& input, LIM* lim=NULL)
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
		  if (lim)
		    lim->add_term();
		  ret.push_back(term);
		  term = "";
		  defined = false;
		}
	    }
	}
      if (defined)
	{
	  if (lim)
	    lim->add_term();
	  ret.push_back(term);
	}
    }

    template <typename V, typename LEX, typename SPACE, typename LIM>
    inline V by_space(const std::string& input, LIM* lim=NULL)
    {
      V ret;
      by_space_void<V, LEX, SPACE, LIM>(ret, input, lim);
      return ret;
    }
  }
} // namespace openvpn

#endif // OPENVPN_COMMON_SPLIT_H
