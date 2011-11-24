#include <iostream>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/openssl/ssl/sslctx.hpp>
#include <openvpn/gencrypto/cryptoinit.hpp>

using namespace openvpn;

const char message[] =
  "It was a bright cold day in April, and the clocks\n"
  "were striking thirteen. Winston Smith, his chin nuzzled\n"
  "into his breast in an effort to escape the vile wind,\n"
  "slipped quickly through the glass doors of Victory\n"
  "Mansions, though not quickly enough to prevent a\n"
  "swirl of gritty dust from entering along with him.\n";

#ifndef ITER
#define ITER 10
#endif

inline void xfer(OpenSSLContext::SSL& cli, OpenSSLContext::SSL& serv)
{
  while (true)
    {
      bool did_work = false;
      if (cli.read_ciphertext_ready())
	{
	  BufferPtr buf = cli.read_ciphertext();
	  serv.write_ciphertext(buf);
#if ITER <= 10
	  std::cout << "CLIENT -> SERVER " << buf->size() << " bytes" << std::endl;
#endif
	  did_work = true;
	}
      if (serv.read_ciphertext_ready())
	{
	  BufferPtr buf = serv.read_ciphertext();
	  cli.write_ciphertext(buf);
#if ITER <= 10
	  std::cout << "SERVER -> CLIENT " << buf->size() << " bytes" << std::endl;
#endif
	  did_work = true;
	}
      if (!did_work)
	break;
    }
}

int main(int /*argc*/, char* /*argv*/[])
{
  try {
    // initialize crypto lib
    openvpn::crypto_init ci;

    std::string ca1_crt = read_text("ca1.crt");
    std::string ca2_crt = read_text("ca2.crt");

    std::string client_crt = read_text("client.crt");
    std::string client_key = read_text("client.key");

    std::string server_crt = read_text("server.crt");
    std::string server_key = read_text("server.key");

    std::string dh_pem = read_text("dh.pem");
    std::string tls_auth_key = read_text("tls-auth.key");

    FramePtr frame(new Frame(Frame::Context(128, 256, 128, 0, sizeof(size_t), 0)));

    // client config
    SSLConfig cc;
    cc.mode = SSLConfig::CLIENT;
#if ITER <= 10
    cc.flags = SSLConfig::DEBUG;
#endif
    cc.ca = ca1_crt + ca2_crt;
    cc.cert = client_crt;
    cc.pkey = client_key;
    cc.frame = frame;
    OpenSSLContext cli_ctx(cc);

    // server config
    SSLConfig sc;
    sc.mode = SSLConfig::SERVER;
#if ITER <= 10
    sc.flags = SSLConfig::DEBUG;
#endif
    sc.ca = ca1_crt + ca2_crt;
    sc.cert = server_crt;
    sc.pkey = server_key;
    sc.dh = dh_pem;
    sc.frame = frame;
    OpenSSLContext serv_ctx(sc);

    // start client/server SSL sessions
    OpenSSLContext::SSLPtr cli = cli_ctx.ssl();
    OpenSSLContext::SSLPtr serv = serv_ctx.ssl();

    char rcvbuf[1024];
    long count = 0;

    std::string msg(message); // fixme

#if 0
    msg += message;
    msg += message;
    msg += message;
    msg += message;
    msg += message;
    msg += message;
    msg += message;
    msg += message;
    msg += message;
    msg += message;
#endif

    for (int i = 1; i <= ITER; ++i)
      {
	if (i < ITER-2)
	  {
	    const ssize_t status = cli->write_cleartext_unbuffered(msg.c_str(), msg.length());
	    if (status > 0)
	      count += status;
#if ITER <= 10
	    std::cout << "WRITE #" << i << " returned " << status << std::endl;
#endif
	  }

	// transfer data between "client" and "server"
	xfer(*cli, *serv);

	{
	  const ssize_t status = serv->read_cleartext(rcvbuf, sizeof(rcvbuf));
	  if (status > 0)
	    count += status;
#if ITER <= 10
	  std::cout << "READ #" << i << " returned " << status << std::endl;
	  if (status >= 32)
	    {
	      std::string rstr(rcvbuf, 32);
	      std::cout << "GOT IT: " << rstr << std::endl;
	    }
#endif
	}
    }

    std::cout << count << " bytes" << std::endl;
  }
  catch (std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
