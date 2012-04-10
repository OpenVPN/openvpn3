#ifndef OPENVPN_ADDR_RANGE_H
#define OPENVPN_ADDR_RANGE_H

#include <string>
#include <sstream>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>

namespace openvpn {
  namespace IP {
    template <typename A>
    class Range
    {
    public:
      class Iterator
      {
	friend class Range;
      public:
	bool more() const { return remaining_ > 0; }

	const A& addr() const { return addr_; }

	void next()
	{
	  if (more())
	    {
	      ++addr_;
	      --remaining_;
	    }
	}

      private:
	Iterator(const Range& range)
	  : addr_(range.start_), remaining_(range.extent_) {}

	A addr_;
	size_t remaining_;
      };

      Range() : extent_(0) {}

      Range(const A& start, const size_t extent)
	: start_(start), extent_(extent) {}

      Iterator iterator() const { return Iterator(*this); }

      std::string to_string() const
      {
	std::ostringstream os;
	os << start_.to_string() << '[' << extent_ << ']';
	return os.str();
      }

    private:
      A start_;
      size_t extent_;
    };
  }
}

#endif
