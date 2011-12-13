#ifndef OPENVPN_COMMON_PARSE_H
#define OPENVPN_COMMON_PARSE_H

#include <string>
#include <vector>

namespace openvpn {

  struct SpaceMatch
  {
    static bool is_space(char c)
    {
      return (c == ' ' ||
	      c == '\t' ||
	      c == '\n' ||
	      c == '\r');
    }
  };

  class StandardLex
  {
  public:
    StandardLex() : in_quote_(false), backslash(false), ch(-1) {}

    void put(char c)
    {
      if (backslash)
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
      else
	{
	  ch = c;
	}
    }

    int get() const { return ch; }
    void reset() { ch = -1; }

    bool in_quote() const { return in_quote_; }

  private:
    bool in_quote_;
    bool backslash;
    int ch;
  };

  class NullLex
  {
  public:
    NullLex() : ch(-1) {}

    void put(char c) { ch = c; }
    int get() const { return ch; }
    void reset() { ch = -1; }
    bool in_quote() const { return false; }

  private:
    int ch;
  };

  template <typename V, typename LEX>
  inline V split_by_char(const std::string& input, const char split_by)
  {
    LEX lex;
    V ret;

    std::string term;
    for (std::string::const_iterator i = input.begin(); i != input.end(); i++)
      {
	const char c = *i;
	lex.put(c);
	if (!lex.in_quote() && c == split_by)
	  {
	    ret.push_back(term);
	    term = "";
	  }
	else
	  term += c;
      }
    ret.push_back(term);
    return ret;
  }

  template <typename V, typename LEX, typename SPACE>
  inline V split_by_space(const std::string& input)
  {
    LEX lex;
    V ret;

    std::string term;
    bool defined = false;
    for (std::string::const_iterator i = input.begin(); i != input.end(); i++)
      {
	const char c = *i;
	lex.put(c);
	const char tc = lex.get();
	if (lex.in_quote())
	  defined = true;
	if (tc >= 0)
	  {
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
    return ret;
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_PARSE_H
