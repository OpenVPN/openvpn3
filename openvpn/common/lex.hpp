#ifndef OPENVPN_COMMON_LEX_H
#define OPENVPN_COMMON_LEX_H

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

} // namespace openvpn

#endif // OPENVPN_COMMON_LEX_H
