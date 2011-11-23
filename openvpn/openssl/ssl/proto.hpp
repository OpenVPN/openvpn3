#ifndef OPENVPN_SSL_PROTO_H
#define OPENVPN_SSL_PROTO_H

#include <openssl/ssl.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/openssl/util/error.hpp>
#include <openvpn/openssl/bio/bio_memq_stream.hpp>
#include <openvpn/random/prng.hpp>
#include <openvpn/crypto/static_key.hpp>
#include <openvpn/crypto/packet_id.hpp>
#include <openvpn/reliable/relrecv.hpp>
#include <openvpn/reliable/relsend.hpp>
#include <openvpn/reliable/relack.hpp>
#include <openvpn/ssl/psid.hpp>
#include <openvpn/openssl/ssl/sslctx.hpp>
#include <openvpn/ssl/tlsprf.hpp>

namespace openvpn {

  class ProtoContext : public RC<thread_unsafe_refcount>
  {
  public:
    OPENVPN_EXCEPTION(proto_context_error);

    // client/server designation
    enum ClientServer {
      CLIENT=0,
      SERVER=1,
    };

    // configuration info passed to ProtoContext constructor
    struct Config : public RC<thread_unsafe_refcount>
    {
      ClientServer cli_serv;
      FramePtr frame;
      SSLContextPtr ssl_ctx;
      OpenVPNStaticKey tls_auth;
      PRNGPtr prng;
    };

    typedef boost::intrusive_ptr<Config> ConfigPtr;

  private:
    enum {
      // packet opcode (high 5 bits) and key-id (low 3 bits) are combined in one byte
      KEY_ID_MASK =             0x07,
      OPCODE_SHIFT =            3,

      // packet opcodes -- the V1 is intended to allow protocol changes in the future
      CONTROL_HARD_RESET_CLIENT_V1 = 1,   // (obsolete) initial key from client, forget previous state
      CONTROL_HARD_RESET_SERVER_V1 = 2,   // (obsolete) initial key from server, forget previous state
      CONTROL_SOFT_RESET_V1 =        3,   // new key, graceful transition from old to new key
      CONTROL_V1 =                   4,   // control channel packet (usually TLS ciphertext)
      ACK_V1 =                       5,   // acknowledgement for packets received
      DATA_V1 =                      6,   // data channel packet

      // indicates key_method >= 2
      CONTROL_HARD_RESET_CLIENT_V2 = 7,   // initial key from client, forget previous state
      CONTROL_HARD_RESET_SERVER_V2 = 8,   // initial key from server, forget previous state

      // define the range of legal opcodes
      FIRST_OPCODE =                1,
      LAST_OPCODE =                 8,

      // key negotiation states
      S_ERROR =         -1,
      S_UNDEF =          0,
      S_INITIAL =        1,	// tls_init() was called
      S_PRE_START =      2,	// waiting for initial reset & acknowledgement
      S_START =          3,	// ready to exchange keys
      S_SENT_KEY =       4,	// client does S_SENT_KEY -> S_GOT_KEY
      S_GOT_KEY =        5,	// server does S_GOT_KEY -> S_SENT_KEY
      S_ACTIVE =         6,	// ready to exchange data channel packets
      S_NORMAL_OP =      7,	// normal operations
    };

    friend class KeyContext;

    class KeyContext : public RC<thread_unsafe_refcount>
    {
    public:
      KeyContext(const Config& config, ProtoContext& proto)
      {
	ssl_clear();
	try {
	  state = S_INITIAL;

	  // init SSL objects
	  ssl = SSL_new(config.ssl_ctx->raw_ctx());
	  if (!ssl)
	    throw OpenSSLException("KeyContext: SSL_new failed");
	  ssl_bio = BIO_new(BIO_f_ssl());
	  if (!ssl_bio)
	    throw OpenSSLException("KeyContext: BIO_new BIO_f_ssl failed");
	  ct_in = mem_bio(config);
	  ct_out = mem_bio(config);

	  // set client/server mode
	  if (config.cli_serv == SERVER)
	    SSL_set_connect_state(ssl);
	  else if (config.cli_serv == CLIENT)
	    SSL_set_accept_state(ssl);
	  else
	    OPENVPN_THROW(proto_context_error, "KeyContext: unknown client/server mode");

	  // effect SSL/BIO linkage
	  SSL_set_bio (ssl, ct_in, ct_out);
	  BIO_set_ssl (ssl_bio, ssl, BIO_NOCLOSE);

	  // get key_id from parent
	  key_id = proto.next_key_id();
	}
	catch (...)
	  {
	    ssl_erase();
	    throw;
	  }
      }

    private:
      void ssl_clear()
      {
	ssl = NULL;
	ssl_bio = NULL;
	ct_in = NULL;
	ct_out = NULL;
      }

      void ssl_erase()
      {
	if (ssl_bio)
	  BIO_free_all(ssl_bio);
	if (ssl)
	  SSL_free(ssl);
	ssl_clear();
      }

      static BIO* mem_bio(const Config& config)
      {
	BIO *bio = BIO_new(bmq_stream::BIO_s_memq());
	if (!bio)
	  throw OpenSSLException("KeyContext: BIO_new failed on bmq_stream");
	bmq_stream::memq_from_bio(bio)->set_frame(config.frame);
	return bio;
      }

      SSL *ssl;		   // OpenSSL SSL object
      BIO *ssl_bio;        // read/write cleartext from here
      BIO *ct_in;          // write ciphertext to here
      BIO *ct_out;         // read ciphertext from here

      unsigned int state;
      unsigned int key_id;

      ReliableRecv rel_recv;
      ReliableSend rel_send;
      ReliableAck rel_ack;
    };

    typedef boost::intrusive_ptr<KeyContext> KeyContextPtr;

    // key_id starts at 0, increments to KEY_ID_MASK, then recycles back to 1.
    // Therefore, if key_id is 0, it is the first key.
    unsigned int next_key_id()
    {
      unsigned int ret = key_id;
      if ((key_id = (key_id + 1) & KEY_ID_MASK) == 0)
	key_id = 1;
      return ret;
    }

  public:
    ProtoContext(const ConfigPtr& config_p)
      : key_id(0),
	config(config_p)
    {
      primary.reset(new KeyContext(*config, *this));
      psid.init(*config->prng);
    }

  private:
    unsigned int key_id;
    ConfigPtr config;

    ProtoSessionID psid;
    KeyContextPtr primary;
    KeyContextPtr expiring;
  };

  typedef boost::intrusive_ptr<ProtoContext> ProtoContextPtr;

} // namespace openvpn

#endif // OPENVPN_SSL_PROTO_H
