#include <iostream>
#include <string>
#include <sstream>
#include <deque>
#include <algorithm>
#include <cstring>
#include <limits>

#define OPENVPN_DEBUG

#include <openvpn/common/exception.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/random/rand.hpp>
#include <openvpn/crypto/packet_id.hpp>
#include <openvpn/crypto/static_key.hpp>
#include <openvpn/crypto/digest.hpp>
#include <openvpn/ssl/protostack.hpp>
#include <openvpn/ssl/psid.hpp>
#include <openvpn/openssl/ssl/sslctx.hpp>
#include <openvpn/openssl/util/init.hpp>

#ifdef USE_APPLE_SSL
#include <openvpn/applecrypto/ssl/sslctx.hpp>
#endif

using namespace openvpn;

#ifndef ITER1
#define ITER1 1000
#endif

#ifndef ITER2
#define ITER2 1000
#endif

#if !defined(VERBOSE) && (ITER1 * ITER2) <= 1000
#define VERBOSE
#endif

const char message[] =
  "Message _->_ 0000000000 It was a bright cold day in April, and the clocks\n"
  "were striking thirteen. Winston Smith, his chin nuzzled\n"
  "into his breast in an effort to escape the vile wind,\n"
  "slipped quickly through the glass doors of Victory\n"
  "Mansions, though not quickly enough to prevent a\n"
  "swirl of gritty dust from entering along with him.\n"
#ifdef LARGE_MESSAGE
  "It was a bright cold day in April, and the clocks\n"
  "were striking thirteen. Winston Smith, his chin nuzzled\n"
  "into his breast in an effort to escape the vile wind,\n"
  "slipped quickly through the glass doors of Victory\n"
  "Mansions, though not quickly enough to prevent a\n"
  "swirl of gritty dust from entering along with him.\n"
  "It was a bright cold day in April, and the clocks\n"
  "were striking thirteen. Winston Smith, his chin nuzzled\n"
  "into his breast in an effort to escape the vile wind,\n"
  "slipped quickly through the glass doors of Victory\n"
  "Mansions, though not quickly enough to prevent a\n"
  "swirl of gritty dust from entering along with him.\n"
  "It was a bright cold day in April, and the clocks\n"
  "were striking thirteen. Winston Smith, his chin nuzzled\n"
  "into his breast in an effort to escape the vile wind,\n"
  "slipped quickly through the glass doors of Victory\n"
  "Mansions, though not quickly enough to prevent a\n"
  "swirl of gritty dust from entering along with him.\n"
  "It was a bright cold day in April, and the clocks\n"
  "were striking thirteen. Winston Smith, his chin nuzzled\n"
  "into his breast in an effort to escape the vile wind,\n"
  "slipped quickly through the glass doors of Victory\n"
  "Mansions, though not quickly enough to prevent a\n"
  "swirl of gritty dust from entering along with him.\n"
#endif
  ;

struct Packet
{
  Packet() : flags(0) {}
  explicit Packet(const BufferPtr& buf_arg) : flags(0), buf(buf_arg) {}
  operator bool() const { return bool(buf); }
  void reset() { flags = 0; buf.reset(); }
  const BufferPtr& buffer_ptr() const { return buf; }
  bool is_raw() const { return false; }

  void frame_prepare(const Frame& frame, const unsigned int context)
  {
    if (!buf)
      buf.reset(new BufferAllocated());
    frame.prepare(context, *buf);
  }

  unsigned int flags;
  BufferPtr buf;
};

template <typename SSL_CONTEXT>
class TestProto : public ProtoStackBase<SSL_CONTEXT, Packet>
{
  typedef ProtoStackBase<SSL_CONTEXT, Packet> Base;
  typedef typename Base::ReliableSend ReliableSend;
  typedef typename Base::ReliableRecv ReliableRecv;

  // ProtoStackBase protected vars
  using Base::now;
  using Base::rel_recv;
  using Base::rel_send;
  using Base::xmit_acks;

  enum {
    CONTROL = 42, // magic number for normal packet
    ACK = 7       // magic number for standalone ACK list packet
  };

public:
  TestProto(SSL_CONTEXT& ctx, TimePtr now, const Frame::Ptr& frame, PRNG& prng,
	    const id_t reliable_window, const size_t max_ack_list,
	    const std::string tls_auth_key)
    : Base(ctx, now, frame, ProtoStats::Ptr(), reliable_window, max_ack_list),
      app_bytes_(0),
      net_bytes_(0),
      hmac_size(0),
      use_tls_auth(false)
  {
    // determine client/server status
    server = (ctx.mode() == SSLConfig::SERVER);

    // zero progress value
    std::memset(progress_, 0, 11);

    // generate proto session ID for self
    psid_self.randomize(prng);

    if (!tls_auth_key.empty())
      {
	use_tls_auth = true;

	// parse tls_auth key
	OpenVPNStaticKey key;
	key.parse(tls_auth_key);

	// select tls_auth digest
	const Digest digest("SHA1");
	hmac_size = digest.size();

	// init tls_auth hmac
	const unsigned int key_dir = server ? OpenVPNStaticKey::NORMAL : OpenVPNStaticKey::INVERSE;
	ta_hmac_send.init(digest, key.slice(OpenVPNStaticKey::HMAC | OpenVPNStaticKey::ENCRYPT | key_dir));
	ta_hmac_recv.init(digest, key.slice(OpenVPNStaticKey::HMAC | OpenVPNStaticKey::DECRYPT | key_dir));

	// init tls_auth packet ID
	ta_pid_send.init(PacketID::LONG_FORM);
	ta_pid_recv.init(PacketIDReceive::UDP_MODE,
			 PacketID::LONG_FORM,
			 64, 30,
			 "CC-UDP", 0,
#ifdef VERBOSE
			 PacketIDReceive::DEBUG_MEDIUM
#else
			 PacketIDReceive::DEBUG_QUIET
#endif
			 );
      }
  }

  void app_send(BufferPtr& buf)
  {
    app_bytes_ += buf->size();
    Base::app_send(buf);
  }

  void initial_app_send(const char *msg)
  {
    const size_t msglen = std::strlen(msg);
    BufferPtr buf(new BufferAllocated((unsigned char *)msg, msglen, 0));
    app_send(buf);
    this->flush();
  }

  std::string dump_packet(const Buffer& buf)
  {
    std::ostringstream out;
    try {
      Buffer b(buf);
      const size_t orig_size = b.size();
      const int op = b.pop_front();
      if (op == CONTROL)
	out << "CONTROL";
      else if (op == ACK)
	out << "ACK";
      else
	return "BAD_PACKET";

      ProtoSessionID psid(b);
      out << " PSID=" << psid.str();

      if (use_tls_auth)
	{
	  const unsigned char *hmac = b.read_alloc(hmac_size);
	  out << " HMAC=" << render_hex(hmac, hmac_size);

	  PacketID pid;
	  pid.read(b, PacketID::LONG_FORM);
	  out << " PID=" << pid.str();
	}

      ReliableAck ack(0);
      ack.read(b);
      out << " ACK=[";
      while (!ack.empty())
	{
	  out << " " << ack.front();
	  ack.pop_front();
	}
      out << " ]";

      if (op == CONTROL)
	{
	  out << " ID=" << ReliableAck::read_id(b);
	  out << " SIZE=" << b.size() << '/' << orig_size;
	}

    }
    catch (std::exception& e)
      {
	out << " EXCEPTION: " << e.what();
      }
    return out.str();
  }

  size_t net_bytes() const { return net_bytes_; }
  size_t app_bytes() const { return app_bytes_; }

  const char *progress() const { return progress_; }

  std::deque<BufferPtr> net_out;

private:
  // generate message head
  void gen_head(const int op, Buffer& buf)
  {
    if (use_tls_auth)
      {
	// write tls-auth packet ID
	ta_pid_send.write_next(buf, true, now->seconds_since_epoch());

	// make space for tls-auth HMAC
	unsigned char *hmac = buf.prepend_alloc(hmac_size);

	// write proto session ID
	psid_self.prepend(buf);

	// write opcode
	buf.push_front(op);

	// write hmac
	ta_hmac_send.hmac2_gen(hmac, hmac_size, buf.data(), buf.size());
      }
    else
      {
	// write proto session ID
	psid_self.prepend(buf);

	// write opcode
	buf.push_front(op);
      }
  }

  virtual void encapsulate(id_t id, Packet& pkt)
  {
    Buffer& buf = *pkt.buf;

    // write message sequence number
    ReliableAck::prepend_id(buf, id);

    // write ACKs for messages received from peer
    xmit_acks.prepend(buf);

    // generate message head
    gen_head(CONTROL, buf);
  }

  virtual bool decapsulate(Packet& pkt)
  {
    Buffer& recv = *pkt.buf;

    if (use_tls_auth)
      {
	const unsigned char *orig_data = recv.data();
	const size_t orig_size = recv.size();

	// get opcode
	const int op = recv.pop_front();

	// get proto session ID
	ProtoSessionID psid(recv);

	// verify HMAC
	{
	  const unsigned char *hmac = recv.read_alloc(hmac_size);
	  if (!ta_hmac_recv.hmac2_cmp(hmac, hmac_size, orig_data, orig_size))
	    {
#ifdef VERBOSE
	      std::cout << "*** HMAC verification failed" << std::endl;
#endif
	      return false;
	    }
      
	}

	// verify proto session ID
	if (psid_peer.defined())
	  {
	    if (!psid_peer.match(psid))
	      {
#ifdef VERBOSE
		std::cout << "*** Peer proto session ID verification failed" << std::endl;
#endif
		return false;
	      }
	  }
	else
	  {
	    psid_peer = psid;
	  }

	// read tls_auth packet ID
	const PacketID pid = ta_pid_recv.read_next(recv);

	// verify opcode
	if (op != CONTROL && op != ACK)
	  {
	    std::cout << "Error: Decapsulate: unknown string packet op " << op << std::endl;
	    return false;
	  }

	// get current time_t
	const PacketID::time_t t = now->seconds_since_epoch();

	// verify tls_auth packet ID
	const bool pid_ok = ta_pid_recv.test(pid, t);

	// process ACKs sent by peer (if packet ID check failed
	// read the ACK IDs, but don't modify the rel_send object).
	ReliableAck::ack(rel_send, recv, pid_ok);

	// for CONTROL packets only, not ACK
	if (op == CONTROL)
	  {
	    // get message sequence number
	    const id_t id = ReliableAck::read_id(recv);

	    if (pid_ok)
	      {
		// try to push message into reliable receive object
		const unsigned int rflags = rel_recv.receive(pkt, id);

		// should we ACK packet back to sender?
		if (rflags & ReliableRecv::ACK_TO_SENDER)
		  xmit_acks.push_back(id); // ACK packet to sender

		// was packet accepted by reliable receive object?
		if (rflags & ReliableRecv::IN_WINDOW)
		  {
		    ta_pid_recv.add(pid, t); // remember tls_auth packet ID so that it can't be replayed
		    return true;
		  }
	      }
	    else // treat as replay
	      {
#ifdef VERBOSE
		std::cout << "*** Packet ID verification failed" << std::endl;
#endif
		if (pid.is_valid())
		  xmit_acks.push_back(id); // even replayed packets must be ACKed or protocol could deadlock
	      }
	  }
      }
    else // non tls_auth mode
      {
	// get opcode
	const int op = recv.pop_front();

	// verify opcode
	if (op != CONTROL && op != ACK)
	  {
	    std::cout << "Error: Decapsulate: unknown string packet op " << op << std::endl;
	    return false;
	  }

	// verify proto session ID
	ProtoSessionID psid(recv);
	if (psid_peer.defined())
	  {
	    if (!psid_peer.match(psid))
	      {
#ifdef VERBOSE
		std::cout << "*** Peer proto session ID verification failed" << std::endl;
#endif
		return false;
	      }
	  }
	else
	  {
	    psid_peer = psid;
	  }

	// process ACKs sent by peer
	ReliableAck::ack(rel_send, recv, true);

	// for CONTROL packets only, not ACK
	if (op == CONTROL)
	  {
	    // get message sequence number
	    const id_t id = ReliableAck::read_id(recv);

	    // try to push message into reliable receive object
	    const unsigned int rflags = rel_recv.receive(pkt, id);

	    // should we ACK packet back to sender?
	    if (rflags & ReliableRecv::ACK_TO_SENDER)
	      xmit_acks.push_back(id); // ACK packet to sender

	    // was packet accepted by reliable receive object?
	    if (rflags & ReliableRecv::IN_WINDOW)
	      return true;
	  }
      }
    return false;
  }

  virtual void generate_ack(Packet& pkt)
  {
    Buffer& buf = *pkt.buf;
    xmit_acks.prepend(buf);

    // generate message head
    gen_head(ACK, buf);
  }

  virtual void net_send(const Packet& net_pkt)
  {
    const Buffer& buf = *net_pkt.buf;
    net_bytes_ += buf.size();
    net_out.push_back(BufferPtr(new BufferAllocated(buf, 0)));
  }

  virtual void app_recv(BufferPtr& to_app_buf)
  {
    BufferPtr work;
    work.swap(to_app_buf);
    if (work->size() >= 23)
      std::memcpy(progress_, work->data()+13, 10);

#ifdef VERBOSE
    {
      const ssize_t trunc = 64;
      std::string show((char *)work->data(), trunc);
      std::cout << now->raw() << " " << (server ? "SERVER" : "CLIENT") << " " << show << std::endl;
    }
#endif
    modmsg(work);
    this->app_send(work);
  }

  virtual void raw_recv(Packet& raw_pkt)
  {
  }

  void modmsg(BufferPtr& buf)
  {
    char *msg = (char *) buf->data();
    if (server)
      {
	msg[8] = 'S';
	msg[11] = 'C';
      }
    else
      {
	msg[8] = 'C';
	msg[11] = 'S';
      }

    // increment embedded number
    for (int i = 22; i >= 13; i--)
      {
	if (msg[i] != '9')
	  {
	    msg[i]++;
	    break;
	  }
	else
	  msg[i] = '0';
      }
  }

  bool server;
  size_t app_bytes_;
  size_t net_bytes_;
  char progress_[11];

  HMACContext ta_hmac_send;
  HMACContext ta_hmac_recv;
  PacketIDSend ta_pid_send;
  PacketIDReceive ta_pid_recv;
  size_t hmac_size;
  bool use_tls_auth;

  ProtoSessionID psid_self;
  ProtoSessionID psid_peer;
};

class NoisyWire
{
public:
  NoisyWire(const std::string title_arg,
	    TimePtr now_arg,
	    RandomIntBase& rand_arg,
	    const unsigned int reorder_prob_arg,
	    const unsigned int drop_prob_arg,
	    const unsigned int corrupt_prob_arg)
    : title(title_arg),
      now(now_arg),
      random(rand_arg),
      reorder_prob(reorder_prob_arg),
      drop_prob(drop_prob_arg),
      corrupt_prob(corrupt_prob_arg)
  {
  }

  template <typename T1, typename T2>
  void xfer(T1& a, T2& b)
  {
    //std::cout << "TEST RETRANS " << title << " now=" << now->raw() << " next=" << a.next_retransmit().raw() << std::endl; // fixme
    if (*now >= a.next_retransmit())
      {
#ifdef VERBOSE
	std::cout << now->raw() << " " << title << " Retransmitting" << std::endl;
#endif
	a.retransmit();
      }
    while (!a.net_out.empty())
      {
	BufferPtr buf = a.net_out.front();
#ifdef VERBOSE
	std::cout << now->raw() << " " << title << " " << a.dump_packet(*buf) <<  std::endl;
#endif
	a.net_out.pop_front();
	wire.push_back(buf);
      }
    while (true)
      {
	BufferPtr buf = recv();
	if (!buf)
	  break;
	Packet pkt(buf);
	b.net_recv(pkt);
      }
    b.flush();
    b.send_pending_acks();
  }

private:
  BufferPtr recv()
  {
    // simulate packets being received out of order
    if (wire.size() >= 2 && !rand(reorder_prob))
      {
	const size_t i = random.randrange(wire.size() - 1) + 1;
#ifdef VERBOSE
	std::cout << now->raw() << " " << title << " Simulating packet reordering " << i << " -> 0" <<  std::endl;
#endif
	std::swap(wire[0], wire[i]);
      }

    if (wire.size())
      {
	BufferPtr buf = wire.front();
	wire.pop_front();

#ifdef VERBOSE
	std::cout << now->raw() << " " << title << " Received packet, size=" << buf->size() << std::endl;
#endif

	// simulate dropped packet
	if (!rand(drop_prob))
	  {
#ifdef VERBOSE
	    std::cout << now->raw() << " " << title << " Simulating a dropped packet" << std::endl;
#endif
	    return BufferPtr();
	  }

	// simulate corrupted packet
	if (!rand(corrupt_prob))
	  {
#ifdef VERBOSE
	    std::cout << now->raw() << " " << title << " Simulating a corrupted packet" << std::endl;
#endif
	    const size_t pos = random.randrange(buf->size());
	    const unsigned char value = random.randrange(256);
	    (*buf)[pos] = value;
	  }
	return buf;
      }

    return BufferPtr();
  }

  unsigned int rand(const unsigned int prob)
  {
    if (prob)
      return random.randrange(prob);
    else
      return 1;
  }
  
  std::string title;
  TimePtr now;
  RandomIntBase& random;
  unsigned int reorder_prob;
  unsigned int drop_prob;
  unsigned int corrupt_prob;
  std::deque<BufferPtr> wire;
};

int main(int /*argc*/, char* /*argv*/[])
{
  try {
    Time::reset_base();
    openssl_init ossl_init;

    // frame
    Frame::Ptr frame(new Frame(Frame::Context(128, 256, 128, 0, 16, 0)));

    // RNG
    RandomInt rand;
    PRNG prng("sha1", 16);

    // server config files
    const std::string ca1_crt = read_text("../ssl/ca1.crt");
    const std::string ca2_crt = read_text("../ssl/ca2.crt");
    const std::string client_crt = read_text("../ssl/client.crt");
    const std::string client_key = read_text("../ssl/client.key");
    const std::string server_crt = read_text("../ssl/server.crt");
    const std::string server_key = read_text("../ssl/server.key");
    const std::string dh_pem = read_text("../ssl/dh.pem");
    const std::string tls_auth_key = read_text("../ssl/tls-auth.key");

    // server config
    SSLConfig sc;
    sc.mode = SSLConfig::SERVER;
#ifdef VERBOSE
    sc.flags = SSLConfig::DEBUG;
#endif
    sc.ca = ca1_crt + ca2_crt;
    sc.cert = server_crt;
    sc.pkey = server_key;
    sc.dh = dh_pem;
    sc.frame = frame;
    OpenSSLContext serv_ctx(sc);

    // client config
    SSLConfig cc;
#ifdef USE_APPLE_SSL
    typedef AppleSSLContext ClientSSLContext;
    cc.identity = "etest";
#else
    typedef OpenSSLContext ClientSSLContext;
    cc.ca = ca1_crt + ca2_crt;
    cc.cert = client_crt;
    cc.pkey = client_key;
#endif
    cc.mode = SSLConfig::CLIENT;
#ifdef VERBOSE
    cc.flags = SSLConfig::DEBUG;
#endif
    cc.frame = frame;
    ClientSSLContext cli_ctx(cc);

    // init simulated time
    Time time;
    const Time::Duration time_step = Time::Duration::binary_ms(100);

    // init stats
    size_t app_bytes = 0;
    size_t net_bytes = 0;
    size_t app_min = std::numeric_limits<size_t>::max();
    size_t net_min = std::numeric_limits<size_t>::max();

    for (int i = 0; i < ITER1; ++i)
      {
	TestProto<ClientSSLContext> cli_proto(cli_ctx, &time, frame, prng, 4, 4, tls_auth_key);
	TestProto<OpenSSLContext> serv_proto(serv_ctx, &time, frame, prng, 4, 4, tls_auth_key);
	NoisyWire client_to_server("Client -> Server", &time, rand, 8, 16, 32);
	NoisyWire server_to_client("Server -> Client", &time, rand, 8, 16, 32);

#ifdef VERBOSE
	std::cout << "*** ITER" << i << std::endl;
#endif

	// start feedback loop
	// fixme -- set time
	cli_proto.start_handshake();
	serv_proto.start_handshake();
	cli_proto.initial_app_send(message);

	// message loop
	for (int j = 0; j < ITER2; ++j)
	  {
	    client_to_server.xfer(cli_proto, serv_proto);
	    server_to_client.xfer(serv_proto, cli_proto);
	    time += time_step;
	  }

	const size_t ab = cli_proto.app_bytes() + serv_proto.app_bytes();
	const size_t nb = cli_proto.net_bytes() + serv_proto.net_bytes();
	app_bytes += ab;
	net_bytes += nb;
	if (ab < app_min)
	  app_min = ab;
	if (nb < net_min)
	  net_min = nb;

#if ITER1 <= 100
	std::cout << "*** PROGRESS " << cli_proto.progress() << '/' << serv_proto.progress() << std::endl;
#endif
      }
    std::cout << "i1=" << ITER1 << " i2=" << ITER2 << " app bytes=" << app_bytes << " net bytes=" << net_bytes << " app_min=" << app_min << " net_min=" << net_min << std::endl;
  }
  catch (std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
