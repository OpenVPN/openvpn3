//
//  lzoasym_impl.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMPRESS_LZOASYM_IMPL_H
#define OPENVPN_COMPRESS_LZOASYM_IMPL_H

#include <boost/cstdint.hpp> // for boost::uint32_t, etc.

// Implementation of asymmetrical LZO compression (only uncompress, don't compress)

#define LZOASYM_UNALIGNED_OK_2
#define LZOASYM_UNALIGNED_OK_4
#define LZOASYM_ALIGNED_OK_4
//#define LZOASYM_UNALIGNED_OK_8

#define LZOASYM_LITTLE_ENDIAN

#define LZOASYM_NEED_IP(x)  if ((size_t)(ip_end - ip) < (size_t)(x))  goto input_overrun
#define LZOASYM_NEED_OP(x)  if ((size_t)(op_end - op) < (size_t)(x))  goto output_overrun
#define LZOASYM_TEST_LB(m_pos)        if (m_pos < out || m_pos >= op) goto lookbehind_overrun
#define LZOASYM_ASSERT(cond)                             if (!(cond)) goto assertion_failed

namespace openvpn {
  namespace lzo_asym_impl {
    typedef boost::uint16_t lzo_uint16;
    typedef boost::uint32_t lzo_uint32;
    typedef boost::uint64_t lzo_uint64;

    template <typename T>
    inline T get_mem(const void *p)
    {
      typedef volatile const T* cptr;
      return *cptr(p);
    }

    template <typename T>
    inline T set_mem(void *p, const T value)
    {
      typedef volatile T* ptr;
      *ptr(p) = value;
    }

    template <typename T>
    inline void copy_mem(void *dest, const void *src)
    {
      typedef volatile T* ptr;
      typedef volatile const T* cptr;
      *ptr(dest) = *cptr(src);
    }

    template <typename T>
    inline bool ptr_aligned_4(const T* a, const T* b)
    {
      return ((size_t(a) | size_t(b)) & 3) == 0;
    }

    template <typename T>
    inline size_t ptr_diff(const T* a, const T* b)
    {
      return a - b;
    }

    enum {
      LZOASYM_E_OK=0,
      LZOASYM_E_EOF_NOT_FOUND=-7,
      LZOASYM_E_INPUT_NOT_CONSUMED=-8,
      LZOASYM_E_INPUT_OVERRUN=-4,
      LZOASYM_E_OUTPUT_OVERRUN=-5,
      LZOASYM_E_LOOKBEHIND_OVERRUN=-6,
      LZOASYM_E_ASSERT_FAILED=-9,
    };

    enum {
      LZOASYM_EOF_CODE=1,
      LZOASYM_M2_MAX_OFFSET=0x0800,
    };

    int lzo1x_decompress_safe(const unsigned char *in, size_t in_len, unsigned char *out, size_t *out_len)
    {
      unsigned char *op;
      const unsigned char *ip;
      size_t t;
      const unsigned char *m_pos;
      const unsigned char *const ip_end = in + in_len;
      unsigned char *const op_end = out + *out_len;

      *out_len = 0;

      ip = in;
      op = out;

      if (*ip > 17)
	{
	  t = *ip++ - 17;
	  if (t < 4)
	    goto match_next;
	  LZOASYM_ASSERT(t > 0);
	  LZOASYM_NEED_OP(t);
	  LZOASYM_NEED_IP(t+1);
	  do *op++ = *ip++; while (--t > 0);
	  goto first_literal_run;
	}

      while ((ip < ip_end) && (op <= op_end))
	{
	  t = *ip++;
	  if (t >= 16)
	    goto match;

	  // a literal run
	  if (t == 0)
	    {
	      LZOASYM_NEED_IP(1);
	      while (*ip == 0)
		{
		  t += 255;
		  ip++;
		  LZOASYM_NEED_IP(1);
		}
	      t += 15 + *ip++;
	    }

	  // copy literals
	  LZOASYM_ASSERT(t > 0);
	  LZOASYM_NEED_OP(t+3);
	  LZOASYM_NEED_IP(t+4);
#if defined(LZOASYM_UNALIGNED_OK_8) && defined(LZOASYM_UNALIGNED_OK_4)
	  t += 3;
	  if (t >= 8)
	    do {
	      copy_mem<lzo_uint64>(op,ip);
	      op += 8; ip += 8; t -= 8;
	    } while (t >= 8);
	  if (t >= 4)
	    {
	      copy_mem<lzo_uint32>(op,ip);
	      op += 4; ip += 4; t -= 4;
	    }
	  if (t > 0)
	    {
	      *op++ = *ip++;
	      if (t > 1) { *op++ = *ip++; if (t > 2) { *op++ = *ip++; } }
	    }
#elif defined(LZOASYM_UNALIGNED_OK_4) || defined(LZOASYM_ALIGNED_OK_4)
#if !defined(LZOASYM_UNALIGNED_OK_4)
	  if (ptr_aligned_4(op,ip))
	    {
#endif
	      copy_mem<lzo_uint32>(op,ip);
	      op += 4; ip += 4;
	      if (--t > 0)
		{
		  if (t >= 4)
		    {
		      do {
			copy_mem<lzo_uint32>(op,ip);
			op += 4; ip += 4; t -= 4;
		      } while (t >= 4);
		      if (t > 0) do *op++ = *ip++; while (--t > 0);
		    }
		  else
		    do *op++ = *ip++; while (--t > 0);
		}
#if !defined(LZOASYM_UNALIGNED_OK_4)
	    }
	  else
#endif
#endif
#if !defined(LZOASYM_UNALIGNED_OK_4) && !defined(LZOASYM_UNALIGNED_OK_8)
	    {
	      *op++ = *ip++; *op++ = *ip++; *op++ = *ip++;
	      do *op++ = *ip++; while (--t > 0);
	    }
#endif

	first_literal_run:
	  t = *ip++;
	  if (t >= 16)
	    goto match;

	  m_pos = op - (1 + LZOASYM_M2_MAX_OFFSET);
	  m_pos -= t >> 2;
	  m_pos -= *ip++ << 2;

	  LZOASYM_TEST_LB(m_pos);
	  LZOASYM_NEED_OP(3);
	  *op++ = *m_pos++; *op++ = *m_pos++; *op++ = *m_pos;
	  goto match_done;

	  // handle matches
	  do {
	  match:
	    if (t >= 64)            // M2 match
	      {
		m_pos = op - 1;
		m_pos -= (t >> 2) & 7;
		m_pos -= *ip++ << 3;
		t = (t >> 5) - 1;
		LZOASYM_TEST_LB(m_pos);
		LZOASYM_ASSERT(t > 0);
		LZOASYM_NEED_OP(t+3-1);
		goto copy_match;
	      }
	    else if (t >= 32)       // M3 match
	      {
		t &= 31;
		if (t == 0)
		  {
		    LZOASYM_NEED_IP(1);
		    while (*ip == 0)
		      {
			t += 255;
			ip++;
			LZOASYM_NEED_IP(1);
		      }
		    t += 31 + *ip++;
		  }

		m_pos = op - 1;
#if defined(LZOASYM_UNALIGNED_OK_2) && defined(LZOASYM_LITTLE_ENDIAN)
		m_pos -= get_mem<lzo_uint16>(ip) >> 2;
#else
		m_pos -= (ip[0] >> 2) + (ip[1] << 6);
#endif
		ip += 2;
	      }
	    else if (t >= 16)       // M4 match
	      {
		m_pos = op;
		m_pos -= (t & 8) << 11;
		t &= 7;
		if (t == 0)
		  {
		    LZOASYM_NEED_IP(1);
		    while (*ip == 0)
		      {
			t += 255;
			ip++;
			LZOASYM_NEED_IP(1);
		      }
		    t += 7 + *ip++;
		  }

#if defined(LZOASYM_UNALIGNED_OK_2) && defined(LZOASYM_LITTLE_ENDIAN)
		m_pos -= get_mem<lzo_uint16>(ip) >> 2;
#else
		m_pos -= (ip[0] >> 2) + (ip[1] << 6);
#endif
		ip += 2;
		if (m_pos == op)
		  goto eof_found;
		m_pos -= 0x4000;
	      }
	    else                    // M1 match
	      {
		m_pos = op - 1;
		m_pos -= t >> 2;
		m_pos -= *ip++ << 2;

		LZOASYM_TEST_LB(m_pos); LZOASYM_NEED_OP(2);
		*op++ = *m_pos++; *op++ = *m_pos;
		goto match_done;
	      }

	    // copy match
	    LZOASYM_TEST_LB(m_pos);
	    LZOASYM_ASSERT(t > 0);
	    LZOASYM_NEED_OP(t+3-1);
#if defined(LZOASYM_UNALIGNED_OK_8) && defined(LZOASYM_UNALIGNED_OK_4)
	    if (op - m_pos >= 8)
	      {
		t += (3 - 1);
		if (t >= 8)
		  do {
		    copy_mem<lzo_uint64>(op,m_pos);
		    op += 8; m_pos += 8; t -= 8;
		  } while (t >= 8);
		if (t >= 4)
		  {
		    copy_mem<lzo_uint32>(op,m_pos);
		    op += 4; m_pos += 4; t -= 4;
		  }
		if (t > 0)
		  {
		    *op++ = m_pos[0];
		    if (t > 1) { *op++ = m_pos[1]; if (t > 2) { *op++ = m_pos[2]; } }
		  }
	      }
	    else
#elif defined(LZOASYM_UNALIGNED_OK_4) || defined(LZOASYM_ALIGNED_OK_4)
#if !defined(LZOASYM_UNALIGNED_OK_4)
	      if (t >= 2 * 4 - (3 - 1) && ptr_aligned_4(op,m_pos))
		{
		  LZOASYM_ASSERT((op - m_pos) >= 4);
#else
		  if (t >= 2 * 4 - (3 - 1) && (op - m_pos) >= 4)
		    {
#endif
		      copy_mem<lzo_uint32>(op,m_pos);
		      op += 4; m_pos += 4; t -= 4 - (3 - 1);
		      do {
			copy_mem<lzo_uint32>(op,m_pos);
			op += 4; m_pos += 4; t -= 4;
		      } while (t >= 4);
		      if (t > 0) do *op++ = *m_pos++; while (--t > 0);
		    }
		  else
#endif
		    {
		    copy_match:
		      *op++ = *m_pos++; *op++ = *m_pos++;
		      do *op++ = *m_pos++; while (--t > 0);
		    }

		match_done:
		  t = ip[-2] & 3;
		  if (t == 0)
		    break;

		match_next:
		  // copy literals
		  LZOASYM_ASSERT(t > 0);
		  LZOASYM_ASSERT(t < 4);
		  LZOASYM_NEED_OP(t);
		  LZOASYM_NEED_IP(t+1);
		  *op++ = *ip++;
		  if (t > 1) { *op++ = *ip++; if (t > 2) { *op++ = *ip++; } }
		  t = *ip++;
		} while ((ip < ip_end) && (op <= op_end));
	  }

	  // no EOF code was found
	  *out_len = ptr_diff(op, out);
	  return LZOASYM_E_EOF_NOT_FOUND;

	eof_found:
	  LZOASYM_ASSERT(t == 1);
	  *out_len = ptr_diff(op, out);
	  return (ip == ip_end ? LZOASYM_E_OK :
		  (ip < ip_end  ? LZOASYM_E_INPUT_NOT_CONSUMED : LZOASYM_E_INPUT_OVERRUN));

	input_overrun:
	  *out_len = ptr_diff(op, out);
	  return LZOASYM_E_INPUT_OVERRUN;

	output_overrun:
	  *out_len = ptr_diff(op, out);
	  return LZOASYM_E_OUTPUT_OVERRUN;

	lookbehind_overrun:
	  *out_len = ptr_diff(op, out);
	  return LZOASYM_E_LOOKBEHIND_OVERRUN;

	assertion_failed:
	  return LZOASYM_E_ASSERT_FAILED;
	}

    }
  }

#undef LZOASYM_NEED_IP
#undef LZOASYM_NEED_OP
#undef LZOASYM_TEST_LB
#undef LZOASYM_ASSERT

#undef LZOASYM_UNALIGNED_OK_2
#undef LZOASYM_UNALIGNED_OK_4
#undef LZOASYM_ALIGNED_OK_4
#undef LZOASYM_UNALIGNED_OK_8

#undef LZOASYM_LITTLE_ENDIAN

#endif
