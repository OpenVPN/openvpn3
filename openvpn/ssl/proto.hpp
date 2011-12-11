#ifndef OPENVPN_SSL_PROTO_H
#define OPENVPN_SSL_PROTO_H

#include <cstring>
#include <string>
#include <sstream>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/types.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/random/prng.hpp>
#include <openvpn/crypto/crypto.hpp>
#include <openvpn/crypto/packet_id.hpp>
#include <openvpn/crypto/static_key.hpp>
#include <openvpn/crypto/protostats.hpp>
#include <openvpn/ssl/protostack.hpp>
#include <openvpn/ssl/psid.hpp>
#include <openvpn/ssl/sslconf.hpp>
#include <openvpn/ssl/tlsprf.hpp>

// OpenVPN protocol implementation

namespace openvpn {

  template <typename SSL_CONTEXT>
  class ProtoContext : public RC<thread_unsafe_refcount>
  {
  protected:
    enum {
      // packet opcode (high 5 bits) and key-id (low 3 bits) are combined in one byte
      KEY_ID_MASK =             0x07,
      OPCODE_SHIFT =            3,

      // packet opcodes -- the V1 is intended to allow protocol changes in the future
      //CONTROL_HARD_RESET_CLIENT_V1 = 1,   // (obsolete) initial key from client, forget previous state
      //CONTROL_HARD_RESET_SERVER_V1 = 2,   // (obsolete) initial key from server, forget previous state
      CONTROL_SOFT_RESET_V1 =        3,   // new key, graceful transition from old to new key
      CONTROL_V1 =                   4,   // control channel packet (usually TLS ciphertext)
      ACK_V1 =                       5,   // acknowledgement for packets received
      DATA_V1 =                      6,   // data channel packet

      // indicates key_method >= 2
      CONTROL_HARD_RESET_CLIENT_V2 = 7,   // initial key from client, forget previous state
      CONTROL_HARD_RESET_SERVER_V2 = 8,   // initial key from server, forget previous state

      // define the range of legal opcodes
      FIRST_OPCODE =                3,
      LAST_OPCODE =                 8,
      INVALID_OPCODE =              0,

      // states
      // C_x : client states
      // S_x : server states

      // ACK states -- must be first before other states
      C_WAIT_RESET_ACK=0,
      C_WAIT_AUTH_ACK=1,
      S_WAIT_RESET_ACK=2,
      S_WAIT_AUTH_ACK=3,
      LAST_ACK_STATE=3, // all ACK states must be <= this value

      // key negotiation states (client)
      C_INITIAL=4,
      C_WAIT_RESET=5,
      C_WAIT_AUTH=6,

      // key negotiation states (server)
      S_WAIT_RESET=7,
      S_WAIT_AUTH=8,

      // key negotiation states (client and server)
      ACTIVE=9,
    };

    static unsigned int opcode_extract(const unsigned int op)
    {
      return op >> OPCODE_SHIFT;
    }

    static unsigned int key_id_extract(const unsigned int op)
    {
      return op & KEY_ID_MASK;
    }

    static unsigned char op_compose(const unsigned int opcode, const unsigned int key_id)
    {
      return (opcode << OPCODE_SHIFT) | key_id;
    }

  public:
    typedef SSL_CONTEXT SSLContext;

    // configuration data passed to ProtoContext constructor
    struct Config : public RC<thread_unsafe_refcount>
    {
      typedef boost::intrusive_ptr<Config> Ptr;

      Config()
      {
	reliable_window = 0;
	max_ack_list = 0;
	pid_mode = 0;
	pid_seq_backtrack = 0;
	pid_time_backtrack = 0;
	pid_debug_level = 0;
      }

      // master SSL context
      typename SSLContext::Ptr ssl_ctx;

      // master Frame object
      Frame::Ptr frame;

      // (non-smart) pointer to current time
      TimePtr now;

      // PRNG
      PRNG::Ptr prng;

      // data channel parms
      Cipher cipher;
      Digest digest;

      // tls_auth parms
      OpenVPNStaticKey tls_auth_key; // leave this undefined to disable tls_auth
      Digest tls_auth_digest;

      // reliability layer parms
      id_t reliable_window;
      size_t max_ack_list;

      // packet_id parms for both data and control channels
      int pid_mode;            // PacketIDReceive::UDP_MODE or PacketIDReceive::TCP_MODE
      int pid_seq_backtrack;
      int pid_time_backtrack;
      int pid_debug_level;     // PacketIDReceive::DEBUG_x levels
    };

    class PacketType
    {
      friend class ProtoContext;

      enum {
	DEFINED=1<<0,
	CONTROL=1<<1,
	SECONDARY=1<<2,
      };

    public:
      bool is_defined() const { return flags & DEFINED; }
      bool is_control() const { return (flags & (CONTROL|DEFINED)) == (CONTROL|DEFINED); }
      bool is_data()    const { return (flags & (CONTROL|DEFINED)) == DEFINED; }

    private:
      PacketType() : flags(0), opcode(INVALID_OPCODE) {}

      bool is_secondary() const { return flags & SECONDARY; }

      unsigned int flags;
      unsigned int opcode;
    };

    static const char *opcode_name(const unsigned int opcode)
    {
      switch (opcode)
	{
	case CONTROL_SOFT_RESET_V1:
	  return "CONTROL_SOFT_RESET_V1";
	case CONTROL_V1:
	  return "CONTROL_V1";
	case ACK_V1:
	  return "ACK_V1";
	case DATA_V1:
	  return "DATA_V1";
	case CONTROL_HARD_RESET_CLIENT_V2:
	  return "CONTROL_HARD_RESET_CLIENT_V2";
	case CONTROL_HARD_RESET_SERVER_V2:
	  return "CONTROL_HARD_RESET_SERVER_V2";
	}
      return NULL;
    }

    std::string dump_packet(const Buffer& buf)
    {
      std::ostringstream out;
      try {
	Buffer b(buf);
	const size_t orig_size = b.size();
	const unsigned int op = b.pop_front();

	const unsigned int opcode = opcode_extract(op);
	const char *op_name = opcode_name(opcode);
	if (op_name)
	  out << op_name << '/' << key_id_extract(op);
	else
	  return "BAD_PACKET";

	{
	  ProtoSessionID src_psid(b);
	  out << " SRC_PSID=" << src_psid.str();
	}

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
	const bool dest_psid_defined = !ack.empty();
	out << " ACK=[";
	while (!ack.empty())
	  {
	    out << " " << ack.front();
	    ack.pop_front();
	  }
	out << " ]";

	if (dest_psid_defined)
	  {
	    ProtoSessionID dest_psid(b);
	    out << " DEST_PSID=" << dest_psid.str();
	  }

	if (opcode != ACK_V1)
	  {
	    out << " MSG_ID=" << ReliableAck::read_id(b);
	    out << " SIZE=" << b.size() << '/' << orig_size;
	  }

      }
      catch (std::exception& e)
	{
	  out << " EXCEPTION: " << e.what();
	}
      return out.str();
    }

  protected:
    class Packet
    {
      friend class ProtoContext;

    public:
      Packet()
      {
	reset_non_buf();
      }

      explicit Packet(const BufferPtr& buf_arg, const unsigned int opcode_arg = CONTROL_V1)
	: opcode(opcode_arg), buf(buf_arg)
      {
      }

      void reset()
      {
	reset_non_buf();
	buf.reset();
      }

      void frame_prepare(const Frame& frame, const unsigned int context)
      {
	if (!buf)
	  buf.reset(new BufferAllocated());
	frame.prepare(context, *buf);
      }

      bool is_raw() const { return opcode != CONTROL_V1; }
      operator bool() const { return bool(buf); }
      const BufferPtr& buffer_ptr() { return buf; }
      const Buffer& buffer() const { return *buf; }

    private:
      void reset_non_buf()
      {
	opcode = INVALID_OPCODE;
      }

      unsigned int opcode;
      BufferPtr buf;
    };

    class KeyContext : ProtoStackBase<SSLContext, Packet>, public RC<thread_unsafe_refcount>
    {
      typedef ProtoStackBase<SSLContext, Packet> Base;
      typedef typename Base::ReliableSend ReliableSend;
      typedef typename Base::ReliableRecv ReliableRecv;

      // ProtoStackBase protected vars
      using Base::now;
      using Base::rel_recv;
      using Base::rel_send;
      using Base::xmit_acks;

      // ProtoStackBase member functions
      using Base::start_handshake;
      using Base::raw_send;
      using Base::send_pending_acks;

    public:
      OPENVPN_SIMPLE_EXCEPTION(peer_psid_undef);

      typedef boost::intrusive_ptr<KeyContext> Ptr;

      KeyContext(ProtoContext& p)
	: Base(*p.config->ssl_ctx, p.config->now, p.config->frame, p.stats,
	       p.config->reliable_window, p.config->max_ack_list),
	  proto(p),
	  dirty(0),
	  tlsprf_self(p.server_),
	  tlsprf_peer(!p.server_)
      {
	state = proto.server_ ? S_WAIT_RESET : C_INITIAL;

	// get key_id from parent
	key_id_ = proto.next_key_id();
      }

      void start()
      {
	if (state == C_INITIAL)
	  {
	    send_reset();
	    state = C_WAIT_RESET;
	    dirty = true;
	  }
      }

      void flush()
      {
	if (dirty)
	  {
	    post_ack_action();
	    Base::flush();
	    send_pending_acks();
	    dirty = false;
	  }
      }

      void retransmit()
      {
	Base::retransmit();
	dirty = true;
      }

      Time next_retransmit() const
      {
	return Base::next_retransmit();
      }

      void app_send(BufferPtr& bp)
      {
	if (state >= ACTIVE)
	  {
	    Base::app_send(bp);
	    dirty = true;
	  }
	else
	  app_pre_write_queue.push_back(bp);
      }

      void net_recv(Packet& pkt)
      {
	Base::net_recv(pkt);
	dirty = true;
      }

      void encrypt(BufferAllocated& buf)
      {
	if (state >= ACTIVE)
	  {
	    crypto.encrypt.encrypt(buf, now->seconds_since_epoch());
	    buf.push_front(op_compose(DATA_V1, key_id_));
	  }
	else
	  buf.reset_size(); // no crypto context available yet
      }

      void decrypt(BufferAllocated& buf)
      {
	if (state >= ACTIVE)
	  {
	    buf.advance(1); // knock off leading op from buffer
	    crypto.decrypt.decrypt(buf, now->seconds_since_epoch());
	  }
	else
	  buf.reset_size(); // no crypto context available yet
      }

      unsigned int key_id() const { return key_id_; }

      bool data_channel_ready() const { return state >= ACTIVE; }

      bool is_dirty() const { return dirty; }

    private:
      unsigned int initial_op(const bool sender) const
      {
	if (key_id_)
	  return CONTROL_SOFT_RESET_V1;
	else
	  return (proto.server_ == sender) ? CONTROL_HARD_RESET_SERVER_V2 : CONTROL_HARD_RESET_CLIENT_V2;
      }

      void send_reset()
      {
	Packet pkt;
	pkt.opcode = initial_op(true);
	pkt.frame_prepare(*proto.config->frame, Frame::WRITE_SSL_INIT);
	raw_send(pkt);
      }

      virtual void raw_recv(Packet& raw_pkt)
      {
	if (raw_pkt.buf->empty() && raw_pkt.opcode == initial_op(false))
	  {
	    switch (state)
	      {
	      case C_WAIT_RESET:
		state = C_WAIT_RESET_ACK;
		break;
	      case S_WAIT_RESET:
		send_reset();
		state = S_WAIT_RESET_ACK;
		break;
	      }
	  }
      }

      virtual void app_recv(BufferPtr& to_app_buf)
      {
	switch (state)
	  {
	  case C_WAIT_AUTH:
	    recv_auth(*to_app_buf);
	    state = C_WAIT_AUTH_ACK;
	    break;
	  case S_WAIT_AUTH:
	    recv_auth(*to_app_buf);
	    send_auth();	
	    state = S_WAIT_AUTH_ACK;
	    break;
	  case ACTIVE:
	    proto.app_recv(key_id_, to_app_buf);
	    break;
	  }
      }

      virtual void net_send(const Packet& net_pkt)
      {
	proto.net_send(key_id_, net_pkt);
      }

      void post_ack_action()
      {
	if (state <= LAST_ACK_STATE && !rel_send.n_unacked())
	  {
	    switch (state)
	      {
	      case C_WAIT_RESET_ACK:
		start_handshake();
		send_auth();
		state = C_WAIT_AUTH;
		break;
	      case S_WAIT_RESET_ACK:
		start_handshake();
		state = S_WAIT_AUTH;
		break;
	      case C_WAIT_AUTH_ACK:
		generate_session_keys();
		active();
		state = ACTIVE;
		break;
	      case S_WAIT_AUTH_ACK:
		generate_session_keys();
		active();
		state = ACTIVE;
		break;
	      }
	  }
      }

      void send_auth()
      {
	BufferPtr buf = new BufferAllocated();
	proto.config->frame->prepare(Frame::WRITE_SSL_CLEARTEXT, *buf);
	tlsprf_self.randomize();
	tlsprf_self.write(*buf);
	Base::app_send(buf);
      }

      void recv_auth(Buffer& buf)
      {
	tlsprf_peer.read(buf);
      }

      void active()
      {
	while (!app_pre_write_queue.empty())
	  {
	    Base::app_send(app_pre_write_queue.front());
	    app_pre_write_queue.pop_front();
	  }
      }

      void generate_session_keys()
      {
	OpenVPNStaticKey key;
	tlsprf_self.generate_key_expansion(key, tlsprf_peer, proto.psid_self, proto.psid_peer);
	//std::cout << "KEY " << proto.server_ << ' ' << key.render();
	init_data_channel_crypto_context(key);
	tlsprf_self.erase();
	tlsprf_peer.erase();
      }

      void init_data_channel_crypto_context(const OpenVPNStaticKey& key)
      {
	const Config& c = *proto.config;
	const unsigned int key_dir = proto.server_ ? OpenVPNStaticKey::NORMAL : OpenVPNStaticKey::INVERSE;

	// initialize CryptoContext encrypt
	crypto.encrypt.frame = c.frame;
	crypto.encrypt.cipher.init(c.cipher,
				   key.slice(OpenVPNStaticKey::CIPHER | OpenVPNStaticKey::ENCRYPT | key_dir),
				   CipherContext::ENCRYPT,
				   ProtoStats::Ptr());
	crypto.encrypt.hmac.init(c.digest,
				 key.slice(OpenVPNStaticKey::HMAC | OpenVPNStaticKey::ENCRYPT | key_dir));
	crypto.encrypt.pid_send.init(PacketID::SHORT_FORM);
	crypto.encrypt.prng = c.prng;

	// initialize CryptoContext decrypt
	crypto.decrypt.frame = c.frame;
	crypto.decrypt.stats = proto.stats;
	crypto.decrypt.cipher.init(c.cipher,
				   key.slice(OpenVPNStaticKey::CIPHER | OpenVPNStaticKey::DECRYPT | key_dir),
				   CipherContext::DECRYPT,
				   proto.stats);
	crypto.decrypt.hmac.init(c.digest,
				 key.slice(OpenVPNStaticKey::HMAC | OpenVPNStaticKey::DECRYPT | key_dir));
	crypto.decrypt.pid_recv.init(c.pid_mode,
				     PacketID::SHORT_FORM,
				     c.pid_seq_backtrack, c.pid_time_backtrack,
				     "DC", int(key_id_),
				     c.pid_debug_level);
      }

      // generate message head
      void gen_head(const unsigned int opcode, Buffer& buf)
      {
	if (proto.use_tls_auth)
	  {
	    // write tls-auth packet ID
	    proto.ta_pid_send.write_next(buf, true, now->seconds_since_epoch());

	    // make space for tls-auth HMAC
	    unsigned char *hmac = buf.prepend_alloc(proto.hmac_size);

	    // write source PSID
	    proto.psid_self.prepend(buf);

	    // write opcode
	    buf.push_front(op_compose(opcode, key_id_));

	    // write hmac
	    proto.ta_hmac_send.hmac2_gen(hmac, proto.hmac_size, buf.data(), buf.size());
	  }
	else
	  {
	    // write source PSID
	    proto.psid_self.prepend(buf);

	    // write opcode
	    buf.push_front(op_compose(opcode, key_id_));
	  }
      }

      void prepend_dest_psid_and_acks(Buffer& buf)
      {
	// if sending ACKs, prepend dest PSID
	if (!xmit_acks.empty())
	  {
	    if (proto.psid_peer.defined())
	      proto.psid_peer.prepend(buf);
	    else
	      {
		proto.stats->error(ProtoStats::CC_ERRORS);
		throw peer_psid_undef();
	      }
	  }

	// prepend ACKs for messages received from peer
	xmit_acks.prepend(buf);
      }

      bool verify_src_psid(const ProtoSessionID& src_psid)
      {
	if (proto.psid_peer.defined())
	  {
	    if (!proto.psid_peer.match(src_psid))
	      {
		proto.stats->error(ProtoStats::CC_ERRORS);
		return false;
	      }
	  }
	else
	  {
	    proto.psid_peer = src_psid;
	  }
	return true;
      }

      bool verify_dest_psid(Buffer& buf)
      {
	ProtoSessionID dest_psid(buf);
	if (!proto.psid_self.match(dest_psid))
	  {
	    proto.stats->error(ProtoStats::CC_ERRORS);
	    return false;
	  }
	return true;
      }

      virtual void encapsulate(id_t id, Packet& pkt)
      {
	Buffer& buf = *pkt.buf;

	// prepend message sequence number
	ReliableAck::prepend_id(buf, id);

	// prepend dest PSID and ACKs to reply to peer
	prepend_dest_psid_and_acks(buf);

	// generate message head
	gen_head(pkt.opcode, buf);
      }

      virtual bool decapsulate(Packet& pkt)
      {
	Buffer& recv = *pkt.buf;

	if (proto.use_tls_auth)
	  {
	    const unsigned char *orig_data = recv.data();
	    const size_t orig_size = recv.size();

	    // advance buffer past initial op byte
	    recv.advance(1);

	    // get source PSID
	    ProtoSessionID src_psid(recv);

	    // verify HMAC
	    {
	      const unsigned char *hmac = recv.read_alloc(proto.hmac_size);
	      if (!proto.ta_hmac_recv.hmac2_cmp(hmac, proto.hmac_size, orig_data, orig_size))
		{
		  proto.stats->error(ProtoStats::HMAC_ERRORS);
		  return false;
		}      
	    }

	    // verify source PSID
	    if (!verify_src_psid(src_psid))
	      return false;

	    // read tls_auth packet ID
	    const PacketID pid = proto.ta_pid_recv.read_next(recv);

	    // get current time_t
	    const PacketID::time_t t = now->seconds_since_epoch();

	    // verify tls_auth packet ID
	    const bool pid_ok = proto.ta_pid_recv.test(pid, t);

	    // process ACKs sent by peer (if packet ID check failed,
	    // read the ACK IDs, but don't modify the rel_send object).
	    if (ReliableAck::ack(rel_send, recv, pid_ok))
	      {
		// make sure that our own PSID is contained in packet received from peer
		if (!verify_dest_psid(recv))
		  return false;
	      }

	    // for CONTROL packets only, not ACK
	    if (pkt.opcode != ACK_V1)
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
			proto.ta_pid_recv.add(pid, t); // remember tls_auth packet ID so that it can't be replayed
			return true;
		      }
		  }
		else // treat as replay
		  {
		    proto.stats->error(ProtoStats::REPLAY_ERRORS);
		    if (pid.is_valid())
		      xmit_acks.push_back(id); // even replayed packets must be ACKed or protocol could deadlock
		  }
	      }
	  }
	else // non tls_auth mode
	  {
	    // advance buffer past initial op byte
	    recv.advance(1);

	    // verify source PSID
	    ProtoSessionID src_psid(recv);
	    if (!verify_src_psid(src_psid))
	      return false;

	    // process ACKs sent by peer
	    if (ReliableAck::ack(rel_send, recv, true))
	      {
		// make sure that our own PSID is in packet received from peer
		if (!verify_dest_psid(recv))
		  return false;
	      }

	    // for CONTROL packets only, not ACK
	    if (pkt.opcode != ACK_V1)
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

	// prepend dest PSID and ACKs to reply to peer
	prepend_dest_psid_and_acks(buf);

	// generate message head
	gen_head(ACK_V1, buf);
      }

      // BEGIN KeyContext data members

      ProtoContext& proto; // parent
      unsigned int state;
      unsigned int key_id_;
      bool dirty;
      std::deque<BufferPtr> app_pre_write_queue;
      CryptoContext crypto;
      TLSPRF tlsprf_self;
      TLSPRF tlsprf_peer;
    };

  public:
    OPENVPN_SIMPLE_EXCEPTION(select_key_context_error);

    ProtoContext(const typename Config::Ptr& config_arg,
		 const ProtoStats::Ptr& stats_arg)
      : config(config_arg),
	stats(stats_arg),
	hmac_size(0),
	use_tls_auth(false),
	key_id(0)
    {
      const Config& c = *config;

      // determine client/server status
      server_ = (c.ssl_ctx->mode() == SSLConfig::SERVER);

      // tls-auth setup
      if (c.tls_auth_key.defined())
	{
	  use_tls_auth = true;

	  // get HMAC size from Digest object
	  hmac_size = c.tls_auth_digest.size();

	  // init tls_auth hmac
	  const unsigned int key_dir = server_ ? OpenVPNStaticKey::NORMAL : OpenVPNStaticKey::INVERSE;
	  ta_hmac_send.init(c.tls_auth_digest, c.tls_auth_key.slice(OpenVPNStaticKey::HMAC | OpenVPNStaticKey::ENCRYPT | key_dir));
	  ta_hmac_recv.init(c.tls_auth_digest, c.tls_auth_key.slice(OpenVPNStaticKey::HMAC | OpenVPNStaticKey::DECRYPT | key_dir));

	  // init tls_auth packet ID
	  ta_pid_send.init(PacketID::LONG_FORM);
	  ta_pid_recv.init(c.pid_mode,
			   PacketID::LONG_FORM,
			   c.pid_seq_backtrack, c.pid_time_backtrack,
			   "SSL-CC", int(key_id),
			   c.pid_debug_level
			   );
	}

      // initialize proto session ID
      psid_self.randomize(*c.prng);

      // initialize primary key context
      primary.reset(new KeyContext(*this));
    }

    virtual ~ProtoContext() {}

    PacketType packet_type(Buffer& buf)
    {
      PacketType pt;
      const unsigned int op = buf[0];
      pt.opcode = validate_opcode(op);
      if (pt.opcode != INVALID_OPCODE)
	{
	  if (pt.opcode != DATA_V1)
	    pt.flags |= PacketType::CONTROL;
	  const unsigned int kid = key_id_extract(op);
	  if (kid == primary->key_id())
	    pt.flags |= PacketType::DEFINED;
	  else if (secondary && kid == secondary->key_id())
	    pt.flags |= (PacketType::DEFINED | PacketType::SECONDARY);
	}
      return pt;
    }

    void start()
    {
      primary->start();
    }

    void flush()
    {
      primary->flush();
      if (secondary)
	secondary->flush();
    }

    void retransmit()
    {
      primary->retransmit();
      if (secondary)
	secondary->retransmit();
    }

    Time next_retransmit() const
    {
      const Time p = primary->next_retransmit();
      if (secondary)
	{
	  const Time s = secondary->next_retransmit();
	  if (s < p)
	    return s;
	}
      return p;
    }

    void control_send(BufferPtr& app_bp)
    {
      primary->app_send(app_bp);
    }

    void control_send(BufferAllocated& app_buf)
    {
      BufferPtr bp = new BufferAllocated();
      bp->move(app_buf);
      primary->app_send(bp);      
    }

    void control_net_recv(const PacketType& type, BufferAllocated& net_buf)
    {
      KeyContext& kc = select_key_context(type, true);
      BufferPtr bp = new BufferAllocated();
      bp->move(net_buf);
      Packet pkt(bp, type.opcode);
      kc.net_recv(pkt);
    }

    void control_net_recv(const PacketType& type, BufferPtr& net_bp)
    {
      KeyContext& kc = select_key_context(type, true);
      Packet pkt(net_bp, type.opcode);
      kc.net_recv(pkt);
    }

    void data_encrypt(BufferAllocated& in_out)
    {
      primary->encrypt(in_out);
    }

    void data_decrypt(const PacketType& type, BufferAllocated& in_out)
    {
      select_key_context(type, false).decrypt(in_out);
    }

    // was primary context invalidated by an exception?
    bool invalidated() const { return primary->invalidated(); }

    // current time
    const Time& now() const { return *config->now; }

    // client or server?
    bool server() const { return server_; }

    // can we call data_encrypt or data_decrypt yet?
    bool data_channel_ready() const { return primary->data_channel_ready(); }

  private:
    virtual void control_net_send(const Buffer& net_buf) = 0;

    virtual void control_recv(BufferPtr& app_bp) = 0;

    void net_send(const unsigned int key_id, const Packet& net_pkt)
    {
      control_net_send(net_pkt.buffer());
    }

    void app_recv(const unsigned int key_id, BufferPtr& to_app_buf)
    {
      control_recv(to_app_buf);
    }

    KeyContext& select_key_context(const PacketType& type, const bool control)
    {
      if (!control)
	{
	  if (type.flags == (PacketType::DEFINED))
	    return *primary;
	  else if (type.flags == (PacketType::DEFINED|PacketType::SECONDARY) && secondary)
	    return *secondary;
	}
      else
	{
	  if (type.flags == (PacketType::DEFINED|PacketType::CONTROL))
	    return *primary;
	  else if (type.flags == (PacketType::DEFINED|PacketType::SECONDARY|PacketType::CONTROL) && secondary)
	    return *secondary;
	}
      throw select_key_context_error();
    }

    unsigned int validate_opcode(const unsigned int op)
    {
      // get opcode
      const unsigned int opcode = opcode_extract(op);

      // validate opcode
      if (opcode >= CONTROL_SOFT_RESET_V1 && opcode <= DATA_V1)
	return opcode;
      if (server_)
	  {
	    if (opcode == CONTROL_HARD_RESET_CLIENT_V2)
	      return opcode;
	  }
      else
	{
	  if (opcode == CONTROL_HARD_RESET_SERVER_V2)
	    return opcode;
	}

      stats->error(ProtoStats::CC_ERRORS);
      return INVALID_OPCODE;
    }

    // key_id starts at 0, increments to KEY_ID_MASK, then recycles back to 1.
    // Therefore, if key_id is 0, it is the first key.
    unsigned int next_key_id()
    {
      unsigned int ret = key_id;
      if ((key_id = (key_id + 1) & KEY_ID_MASK) == 0)
	key_id = 1;
      return ret;
    }

    // BEGIN ProtoContext data members

    typename Config::Ptr config;
    ProtoStats::Ptr stats;

    size_t hmac_size;
    bool use_tls_auth;
    bool server_;
    unsigned int key_id;

    HMACContext ta_hmac_send;
    HMACContext ta_hmac_recv;
    PacketIDSend ta_pid_send;
    PacketIDReceive ta_pid_recv;

    ProtoSessionID psid_self;
    ProtoSessionID psid_peer;

    typename KeyContext::Ptr primary;
    typename KeyContext::Ptr secondary;

    // END ProtoContext data members
  };

} // namespace openvpn

#endif //OPENVPN_SSL_PROTO_H
