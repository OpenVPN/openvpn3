#ifndef OPENVPN_COMMON_MEMCMP_H
#define OPENVPN_COMMON_MEMCMP_H

#include <cstddef> // defines size_t and NULL

namespace openvpn {

  // Is value of type T aligned on A boundary?
  // NOTE: requires that sizeof(A) is a power of 2
  template <typename T, typename A>
  inline bool is_aligned(const T value)
  {
    return (size_t(value) & (sizeof(A)-1)) == 0;
  }

  // constant-time memcmp
  inline bool memcmp_secure(const unsigned char *p1, const unsigned char *p2, size_t size)
  {
    typedef unsigned int altword;
    if (is_aligned<const unsigned char *, altword>(p1) && is_aligned<const unsigned char *, altword>(p2) && is_aligned<size_t, altword>(size))
      {
	//std::cout << "*** MEMCMP ALT" << std::endl; // fixme
	altword *u1 = (altword *)p1;
	altword *u2 = (altword *)p2;
	altword a = 0;
	size /= sizeof(altword);
	while (size--)
	  a |= (*u1++ ^ *u2++);
	return bool(a);
      }
    else
      {
	//std::cout << "*** MEMCMP CHAR " << (size_t(p1) & (sizeof(altword)-1)) << ' ' << (size_t(p2) & (sizeof(altword)-1)) << ' ' << size << std::endl; // fixme
	unsigned char a = 0;
	while (size--)
	  a |= (*p1++ ^ *p2++);
	return bool(a);
      }
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_MEMCMP_H
