#ifndef OPENVPN_CRYPTO_DECRYPT
#define OPENVPN_CRYPTO_DECRYPT

#include <cstring>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/openssl/prng.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/crypto/cipher.hpp>
#include <openvpn/crypto/digest.hpp>
#include <openvpn/crypto/static_key.hpp>
#include <openvpn/crypto/packet_id.hpp>

namespace openvpn {

  class Decrypt {
  public:
    OPENVPN_SIMPLE_EXCEPTION(unsupported_cipher_mode);
    OPENVPN_SIMPLE_EXCEPTION(decrypt_hmac_verify_failed);
    OPENVPN_SIMPLE_EXCEPTION(decrypt_packet_id_verify_failed);

    void decrypt(BufferAllocated& buf)
    {
      // verify the HMAC
      if (hmac.defined())
	{
	  unsigned char local_hmac[HMACContext::MAX_HMAC_SIZE];
	  const size_t hmac_size = hmac.output_size();
	  const unsigned char *packet_hmac = buf.read_alloc(hmac_size);
	  hmac.hmac(local_hmac, hmac_size, buf.c_data(), buf.size());
	  if (std::memcmp(local_hmac, packet_hmac, hmac_size))
	    throw decrypt_hmac_verify_failed();
	}

      // decrypt packet ID + payload
      if (cipher.defined())
	{
	  unsigned char iv_buf[CipherContext::MAX_IV_SIZE];
	  const size_t iv_size = cipher.iv_size();

	  // extract IV from head of packet
	  buf.read(iv_buf, iv_size);

	  // initialize work buffer
	  frame->prepare(Frame::DECRYPT_WORK, work);

	  // decrypt from buf -> work
	  const size_t decrypt_bytes = cipher.decrypt(iv_buf, work.data(), work.max_size(), buf.c_data(), buf.size());
	  work.set_size(decrypt_bytes);

	  // handle different cipher modes
	  const int cipher_mode = cipher.cipher_mode();
	  if (cipher_mode == CipherContext::CIPH_CBC_MODE)
	    {
	      verify_packet_id(work);
	    }
	  else
	    {
	      throw unsupported_cipher_mode();
	    }
	}
      else // no encryption
	{
	  verify_packet_id(buf);
	}

      // return cleartext result in buf
      buf.swap(work);
    }

    FramePtr frame;
    CipherContext cipher;
    HMACContext hmac;
    PacketIDReceive pid_recv;

  private:
    void verify_packet_id(BufferAllocated& buf)
    {
      // ignore packet ID if pid_recv is not initialized
      if (pid_recv.initialized())
	{
	  const PacketID pid = pid_recv.read_next(buf);
	  if (pid_recv.test(pid)) // verify packet ID
	    pid_recv.add(pid);    // remember packet ID
	  else
	    throw decrypt_packet_id_verify_failed();
	}
    }

    BufferAllocated work;
  };

} // namespace openvpn

#endif // OPENVPN_CRYPTO_DECRYPT
