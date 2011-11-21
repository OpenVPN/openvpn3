#ifndef OPENVPN_CRYPTO_ENCRYPT
#define OPENVPN_CRYPTO_ENCRYPT

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
  class Encrypt {
  public:
    OPENVPN_SIMPLE_EXCEPTION(unsupported_cipher_mode);

    void encrypt(BufferAllocated& buf, const PacketID::time_t now)
    {
      if (cipher.defined())
	{
	  // workspace for generating IV
	  unsigned char iv_buf[CipherContext::MAX_IV_SIZE];
	  const size_t iv_size = cipher.iv_size();

	  // IV and packet ID are generated differently depending on cipher mode
	  const int cipher_mode = cipher.cipher_mode();
	  if (cipher_mode == CipherContext::CIPH_CBC_MODE)
	    {
	      // in CBC mode, use an explicit, random IV
	      prng->bytes(iv_buf, iv_size);

	      // generate fresh outgoing packet ID and prepend to cleartext buffer
	      pid_send.write_next(buf, true, now);
	    }
	  else
	    {
	      throw unsupported_cipher_mode();
	    }

	  // initialize work buffer
	  frame->prepare(Frame::ENCRYPT_WORK, work);

	  // encrypt from buf -> work
	  const size_t encrypt_bytes = cipher.encrypt(iv_buf, work.data(), work.max_size(), buf.c_data(), buf.size());
	  work.set_size(encrypt_bytes);

	  // prepend the IV to the ciphertext
	  work.prepend(iv_buf, iv_size);

	  // HMAC the ciphertext
	  prepend_hmac(work);
	}
      else // no encryption
	{
	  // generate fresh outgoing packet ID and prepend to cleartext buffer
	  pid_send.write_next(buf, true, now);

	  // HMAC the cleartext
	  prepend_hmac(work);
	}

      // return ciphertext result in buf
      buf.swap(work);
    }

    FramePtr frame;
    CipherContext cipher;
    HMACContext hmac;
    PacketIDSend pid_send;
    PRNGPtr prng;

  private:
    // compute HMAC signature of data buffer,
    // then prepend the signature to the buffer.
    void prepend_hmac(BufferAllocated& buf)
    {
      if (hmac.defined())
	{
	  const unsigned char *content = buf.data();
	  const size_t content_size = buf.size();
	  const size_t hmac_size = hmac.output_size();
	  unsigned char *hmac_buf = buf.prepend_alloc(hmac_size);
	  hmac.hmac(hmac_buf, hmac_size, content, content_size);
	}
    }

    BufferAllocated work;
  };

} // namespace openvpn

#endif // OPENVPN_CRYPTO_ENCRYPT
