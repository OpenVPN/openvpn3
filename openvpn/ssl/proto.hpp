#ifndef OPENVPN_SSL_PROTO_H
#define OPENVPN_SSL_PROTO_H

#include <cstring>
#include <string>
#include <sstream>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/types.hpp>
#include <openvpn/common/version.hpp>
#include <openvpn/common/platform.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/mode.hpp>
#include <openvpn/log/log.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/random/prng.hpp>
#include <openvpn/crypto/crypto.hpp>
#include <openvpn/crypto/packet_id.hpp>
#include <openvpn/crypto/static_key.hpp>
#include <openvpn/log/protostats.hpp>
#include <openvpn/ssl/protostack.hpp>
#include <openvpn/ssl/psid.hpp>
#include <openvpn/ssl/tlsprf.hpp>
#include <openvpn/link/protocol.hpp>
#include <openvpn/tun/layer.hpp>
#include <openvpn/compress/compress.hpp>

#ifdef OPENVPN_DEBUG_PROTO
#define OPENVPN_LOG_PROTO(x) OPENVPN_LOG(x)
#else
#define OPENVPN_LOG_PROTO(x)
#endif

/*

ProtoContext -- OpenVPN protocol implementation

Protocol negotiation states:

Client:

1. send client reset to server
2. wait for server reset from server AND ack from 1 (C_WAIT_RESET, C_WAIT_RESET_ACK)
3. start SSL handshake
4. send auth message to server
5. wait for server auth message AND ack from 4 (C_WAIT_AUTH, C_WAIT_AUTH_ACK)
6. go active (ACTIVE)

Server:

1. wait for client reset (S_WAIT_RESET)
2. send server reset to client
3. wait for ACK from 2 (S_WAIT_RESET_ACK)
4. start SSL handshake
5. wait for auth message from client (S_WAIT_AUTH)
6. send auth message to client
7. wait for ACK from 6 (S_WAIT_AUTH_ACK)
8. go active (ACTIVE)

*/

namespace openvpn {

  // utility namespace for ProtoContext
  namespace proto_context_private {
    static const unsigned char auth_prefix[] = { 0, 0, 0, 0, 2 }; // CONST GLOBAL

    static const unsigned char keepalive_message[] = {    // CONST GLOBAL
      0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
      0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
    };

    enum {
      KEEPALIVE_FIRST_BYTE = 0x2a  // first byte of keepalive message
    };

    inline bool is_keepalive(const Buffer& buf)
    {
      return buf.size() >= sizeof(keepalive_message)
	&& buf[0] == KEEPALIVE_FIRST_BYTE
	&& !std::memcmp(keepalive_message, buf.c_data(), sizeof(keepalive_message));
    }

    inline void write_keepalive(Buffer& buf)
    {
      buf.write(keepalive_message, sizeof(keepalive_message));
    }
  }

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

    OPENVPN_SIMPLE_EXCEPTION(peer_psid_undef);
    OPENVPN_SIMPLE_EXCEPTION(bad_auth_prefix);

    static unsigned int mtu()
    {
      return 1500;
    }

    // configuration data passed to ProtoContext constructor
    class Config : public RC<thread_unsafe_refcount>
    {
    public:
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

      // Transport protocol, i.e. UDPv4, etc.
      Protocol protocol;

      // OSI layer
      Layer layer;

      // compressor
      CompressContext comp_ctx;

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

      // timeout parameters, relative to construction of KeyContext object
      Time::Duration handshake_window; // SSL/TLS negotiation must complete by this time
      Time::Duration become_primary;   // KeyContext (that is ACTIVE) becomes primary at this time
      Time::Duration renegotiate;      // start SSL/TLS renegotiation at this time
      Time::Duration expire;           // KeyContext expires at this time

      // keepalive parameters
      Time::Duration keepalive_ping;
      Time::Duration keepalive_timeout;

      void load(const OptionList& opt)
      {
	// first set defaults
	reliable_window = 4;
	max_ack_list = 4;
	pid_seq_backtrack = 64;
	pid_time_backtrack = 30;
	pid_debug_level = PacketIDReceive::DEBUG_MEDIUM;
	handshake_window = Time::Duration::seconds(60);
	become_primary = Time::Duration::seconds(60);
	renegotiate = Time::Duration::seconds(3600);
	expire = Time::Duration::seconds(7200);
	keepalive_ping = Time::Duration::seconds(8);
	keepalive_timeout = Time::Duration::seconds(40);
	comp_ctx = CompressContext(CompressContext::LZO_STUB);

	// tcp/udp
	{
	  const Option& o = opt.get_first("remote");
	  const std::string& proto = o.get(3);
	  if (proto == "udp")
	    {
	      protocol = Protocol(Protocol::UDPv4);
	      pid_mode = PacketIDReceive::UDP_MODE;
	    }
	  else if (proto == "tcp")
	    {
	      protocol = Protocol(Protocol::TCPv4);
	      pid_mode = PacketIDReceive::TCP_MODE;
	    }
	  else
	    throw option_error("bad protocol");
	}

	// layer
	{
	  const std::string& dev_type = opt.get("dev-type", 1);
	  if (dev_type == "tun")
	    layer = Layer(Layer::OSI_LAYER_3);
	  else if (dev_type == "tap")
	    layer = Layer(Layer::OSI_LAYER_2);
	  else
	    throw option_error("bad dev-type");
	}

	// cipher
	{
	  const Option *o = opt.get_ptr("cipher");
	  if (o)
	    cipher = Cipher(o->get(1));
	  else
	    cipher = Cipher("BF-CBC");
	}

	// digest
	{
	  const Option *o = opt.get_ptr("auth");
	  if (o)
	    digest = Digest(o->get(1));
	  else
	    digest = Digest("SHA1");
	}

	// tls-auth
	{
	  const Option *o = opt.get_ptr("tls-auth");
	  if (o)
	    {
	      tls_auth_key.parse(o->get(1));
	      tls_auth_digest = digest;
	    }
	}
      }

      // generate a string summarizing options that will be
      // transmitted to peer for options consistency check
      std::string options_string() const
      {
	std::ostringstream out;

	const bool server = ssl_ctx->mode().is_server();

	out << "V4";

	out << ",dev-type " << layer.dev_type();
	out << ",link-mtu " << mtu() + link_mtu_adjust();
	out << ",tun-mtu " << mtu();
	out << ",proto " << protocol.str();
	
	{
	  const char *compstr = comp_ctx.options_string();
	  if (compstr)
	    out << ',' << compstr;
	}

	if (server)
	  out << ",keydir 0";
	else
	  out << ",keydir 1";

	out << ",cipher " << cipher.name();
	out << ",auth " << digest.name();
	out << ",keysize " << cipher.key_length_in_bits();
	if (tls_auth_key.defined())
	  out << ",tls-auth";
	out << ",key-method 2";

	if (server)
	  out << ",tls-server";
	else
	  out << ",tls-client";

	return out.str();
      }

      // generate a string summarizing information about the client
      // including capabilities
      std::string peer_info_string() const
      {
	std::ostringstream out;
	out << "IV_VER=" << OPENVPN_VERSION << '\n';
	out << "IV_PLAT=" << platform_name() << '\n';
	{
	  const char *compstr = comp_ctx.peer_info_string();
	  if (compstr)
	    out << compstr;
	}
	return out.str();
      }

    private:
      // used to generate link_mtu option sent to peer
      unsigned int link_mtu_adjust() const
      {
	return 1 +                                    // leading op byte
	  comp_ctx.extra_payload_bytes() +            // compression magic byte
	  PacketID::size(PacketID::SHORT_FORM) +      // sequence number
	  digest.size() +                             // HMAC
	  cipher.iv_length() +                        // Cipher IV
	  cipher.block_size();                        // worst-case cipher padding expansion
      }
    };

    // Used to describe an incoming network packet
    class PacketType
    {
      friend class ProtoContext;

      enum {
	DEFINED=1<<0,     // packet is valid (otherwise invalid)
	CONTROL=1<<1,     // packet for control channel (otherwise for data channel)
	SECONDARY=1<<2,   // packet is associated with secondary KeyContext (otherwise primary)
	SOFT_RESET=1<<3,  // packet is a CONTROL_SOFT_RESET_V1 message indicating a request for SSL/TLS renegotiation
      };

    public:
      bool is_defined() const { return flags & DEFINED; }
      bool is_control() const { return (flags & (CONTROL|DEFINED)) == (CONTROL|DEFINED); }
      bool is_data()    const { return (flags & (CONTROL|DEFINED)) == DEFINED; }
      bool is_soft_reset() const { return (flags & (CONTROL|DEFINED|SECONDARY|SOFT_RESET)) == (CONTROL|DEFINED|SECONDARY|SOFT_RESET); }

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

	if (opcode == DATA_V1)
	  {
	    out << " SIZE=" << b.size() << '/' << orig_size;
	  }
	else
	  {
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
      }
      catch (std::exception& e)
	{
	  out << " EXCEPTION: " << e.what();
	}
      return out.str();
    }

  protected:

    // used for reading/writing authentication strings (username, password, etc.)

    static void write_string_length(const size_t size, Buffer& buf)
    {
      const boost::uint16_t net_size = htons(size);
      buf.write((const unsigned char *)&net_size, sizeof(net_size));
    }

    static size_t read_string_length(Buffer& buf)
    {
      if (buf.size())
	{
	  boost::uint16_t net_size;
	  buf.read((unsigned char *)&net_size, sizeof(net_size));
	  return ntohs(net_size);
	}
      else
	return 0;
    }

    template <typename S>
    static void write_auth_string(const S& str, Buffer& buf)
    {
      const size_t len = str.length();
      if (len)
	{
	  write_string_length(len+1, buf);
	  buf.write((const unsigned char *)str.c_str(), len);
	  buf.push_back(0);
	}
      else
	write_string_length(0, buf);
    }

    template <typename S>
    static S read_auth_string(Buffer& buf)
    {
      const size_t len = read_string_length(buf);
      if (len)
	{
	  const char *data = (const char *) buf.read_alloc(len);
	  if (len > 1)
	    return S(data, len-1);
	}
      return S();
    }

    template <typename S>
    static void write_control_string(const S& str, Buffer& buf)
    {
      const size_t len = str.length();
      buf.write((const unsigned char *)str.c_str(), len);
      buf.push_back(0);
    }

    template <typename S>
    static S read_control_string(const Buffer& buf)
    {
      size_t size = buf.size();
      if (size)
	{
	  if (buf[size-1] == 0)
	    --size;
	  if (size)
	    return S((const char *)buf.c_data(), size);
	}
      return S();
    }

    template <typename S>
    void write_control_string(const S& str)
    {
      const size_t len = str.length();
      BufferPtr bp = new BufferAllocated(len+1, 0);
      write_control_string(str, *bp);
      control_send(bp);
    }

    static unsigned char *skip_string(Buffer& buf)
    {
      const size_t len = read_string_length(buf);
      return buf.read_alloc(len);
    }

    static void write_empty_string(Buffer& buf)
    {
      write_string_length(0, buf);
    }

    // Packet structure for managing network packets, passed as a template
    // parameter to ProtoStackBase
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

    // KeyContext encapsulates a single SSL/TLS session
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
      typedef boost::intrusive_ptr<KeyContext> Ptr;

      // timeline of events for KeyContext (occurring in order)
      enum EventType {
	KEV_NONE,
	KEV_ACTIVE,         // KeyContext has reached the ACTIVE state
	KEV_NEGOTIATE,      // SSL/TLS negotiation must complete by this time
	KEV_BECOME_PRIMARY, // KeyContext becomes primary for data channel traffic
	KEV_RENEGOTIATE,    // start renegotiating a new KeyContext at this time
	KEV_EXPIRE,         // expiration of KeyContext
	KEV_NEGOTIATE_FAILED, // SSL/TLS negotiation failed
      };

      KeyContext(ProtoContext& p, const bool initiator)
	: Base(*p.config->ssl_ctx, p.config->now, p.config->frame, p.stats,
	       p.config->reliable_window, p.config->max_ack_list),
	  proto(p),
	  dirty(0),
	  handled_pid_wrap(false),
	  tlsprf_self(p.is_server()),
	  tlsprf_peer(!p.is_server())
      {
	state = initiator ? C_INITIAL : S_WAIT_RESET;

	// get key_id from parent
	key_id_ = proto.next_key_id();

	// remember when we were constructed
	construct_time = *now;

	// set must-negotiate-by time
	current_event = KEV_NONE;
	next_event = KEV_NEGOTIATE;
	next_event_time = construct_time + p.config->handshake_window;

	// construct compressor/decompressor
	compress = p.config->comp_ctx.new_compressor(p.config->frame, proto.stats);
      }

      // need to call only on the initiator side of the connection (i.e. client)
      void start()
      {
	if (state == C_INITIAL)
	  {
	    send_reset();
	    state = C_WAIT_RESET;
	    dirty = true;
	  }
      }

      // control channel flush
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

      void invalidate()
      {
	Base::invalidate();
      }

      // retransmit packets as part of reliability layer
      void retransmit()
      {
	// note that we don't set dirty here
	Base::retransmit();
      }

      // when should we next call retransmit method
      Time next_retransmit() const
      {
	const Time t = Base::next_retransmit();
	if (t <= next_event_time)
	  return t;
	else
	  return next_event_time;
      }

      // send app-level cleartext data to peer via SSL
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

      // pass received ciphertext packets on network to SSL/reliability layers
      void net_recv(Packet& pkt)
      {
	Base::net_recv(pkt);
	dirty = true;
      }

      // data channel encrypt
      void encrypt(BufferAllocated& buf)
      {
	if (state >= ACTIVE && !invalidated())
	  {
	    // compress packet
	    compress->compress(buf, true);

	    // encrypt packet
	    crypto.encrypt.encrypt(buf, now->seconds_since_epoch());

	    // prepend op
	    buf.push_front(op_compose(DATA_V1, key_id_));

	    // check for rare situation where packet ID is near overflow
	    test_pid_wrap();
	  }
	else
	  buf.reset_size(); // no crypto context available
      }

      // data channel decrypt
      void decrypt(BufferAllocated& buf)
      {
	try {
	  if (state >= ACTIVE && !invalidated())
	    {
	      // knock off leading op from buffer
	      buf.advance(1);

	      // decrypt packet
	      crypto.decrypt.decrypt(buf, now->seconds_since_epoch());

	      // decompress packet
	      compress->decompress(buf);
	    }
	  else
	    buf.reset_size(); // no crypto context available
	}
	catch (buffer_exception& e)
	  {
	    proto.stats->error(ProtoStats::BUFFER_ERROR);
	    buf.reset_size();
	  }
      }

      // usually called by parent ProtoContext object when this KeyContext
      // has been retired.
      void prepare_expire()
      {
	current_event = KEV_NONE;
	next_event = KEV_EXPIRE;
	next_event_time = construct_time + proto.config->expire;
      }

      // is an KEV_x event pending?
      bool event_pending()
      {
	if (current_event == KEV_NONE && *now >= next_event_time)
	  process_next_event();
	return current_event != KEV_NONE;
      }

      // get KEV_x event
      EventType get_event() const { return current_event; }

      // clear KEV_x event
      void reset_event() { current_event = KEV_NONE; }

      // was session invalidated by an exception?
      bool invalidated() const { return Base::invalidated(); }

      // our Key ID in the OpenVPN protocol
      unsigned int key_id() const { return key_id_; }

      // indicates that data channel is keyed and ready to encrypt/decrypt packets
      bool data_channel_ready() const { return state >= ACTIVE; }

      bool is_dirty() const { return dirty; }

      // time that our state transitioned to ACTIVE
      Time reached_active() const { return reached_active_time_; }

      // transmit a keepalive message to peer
      void send_keepalive()
      {
	if (state >= ACTIVE && !invalidated())
	  {
	    // allocate packet
	    Packet pkt;
	    pkt.frame_prepare(*proto.config->frame, Frame::WRITE_KEEPALIVE);

	    // write keepalive message
	    proto_context_private::write_keepalive(*pkt.buf);

	    // process packet for transmission
	    compress->compress(*pkt.buf, false); // set compress hint to "no"
	    crypto.encrypt.encrypt(*pkt.buf, now->seconds_since_epoch());
	    pkt.buf->push_front(op_compose(DATA_V1, key_id_));

	    // send it
	    proto.net_send(key_id_, pkt);
	  }
      }

      // validate the integrity of a packet
      static bool validate(const Buffer& net_buf, ProtoContext& proto, TimePtr now)
      {
	try {
	  Buffer recv(net_buf);
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
		recv.advance(proto.hmac_size);
		if (!proto.ta_hmac_recv.hmac3_cmp(orig_data, orig_size,
						  1 + ProtoSessionID::SIZE,
						  proto.hmac_size,
						  PacketID::size(PacketID::LONG_FORM)))
		  return false;
	      }

	      // verify source PSID
	      if (!proto.psid_peer.match(src_psid))
		return false;

	      // read tls_auth packet ID
	      const PacketID pid = proto.ta_pid_recv.read_next(recv);

	      // get current time_t
	      const PacketID::time_t t = now->seconds_since_epoch();

	      // verify tls_auth packet ID
	      const bool pid_ok = proto.ta_pid_recv.test(pid, t);

	      // make sure that our own PSID is contained in packet received from peer
	      if (ReliableAck::ack_skip(recv))
		{
		  ProtoSessionID dest_psid(recv);
		  if (!proto.psid_self.match(dest_psid))
		    return false;
		}

	      return pid_ok;
	    }
	  else
	    {
	      // advance buffer past initial op byte
	      recv.advance(1);

	      // verify source PSID
	      ProtoSessionID src_psid(recv);
	      if (!proto.psid_peer.match(src_psid))
		return false;

	      // make sure that our own PSID is contained in packet received from peer
	      if (ReliableAck::ack_skip(recv))
		{
		  ProtoSessionID dest_psid(recv);
		  if (!proto.psid_self.match(dest_psid))
		    return false;
		}

	      return true;
	    }
	}
	catch (buffer_exception& e)
	  {
	    return false;
	  }
      }

    private:
      // called by ProtoStackBase when session is invalidated
      virtual void invalidate_callback()
      {
	reached_active_time_ = Time();
	next_event = KEV_NONE;
	next_event_time = Time::infinite();
      }

      // Trigger a new SSL/TLS negotiation if packet ID (a 32-bit unsigned int)
      // is getting close to wrapping around.  If it wraps back to 0 without
      // a renegotiation, it would cause the relay protection logic to wrongly
      // think that all further packets are replays.
      void test_pid_wrap()
      {
	if (!handled_pid_wrap && crypto.encrypt.pid_send.wrap_warning())
	  {
	    trigger_renegotiation();
	    handled_pid_wrap = true;
	  }
      }

      void trigger_renegotiation()
      {
	if (state >= ACTIVE && !invalidated())
	  {
	    current_event = KEV_RENEGOTIATE;
	    next_event = KEV_EXPIRE;
	    next_event_time = construct_time + proto.config->expire;
	  }
      }

      void active_event()
      {
	current_event = KEV_ACTIVE;
	next_event = KEV_BECOME_PRIMARY;
	next_event_time = construct_time + proto.config->become_primary;
      }

      void process_next_event()
      {
	if (*now >= next_event_time)
	  {
	    switch (next_event)
	      {
	      case KEV_NEGOTIATE:
		if (state >= ACTIVE)
		  {
		    current_event = KEV_NEGOTIATE;
		    next_event = KEV_BECOME_PRIMARY;
		    next_event_time = construct_time + proto.config->become_primary;
		  }
		else
		  {
		    invalidate();
		    current_event = KEV_NEGOTIATE_FAILED;
		  }
		break;
	      case KEV_BECOME_PRIMARY:
		current_event = KEV_BECOME_PRIMARY;
		next_event = KEV_RENEGOTIATE;
		next_event_time = construct_time + proto.config->renegotiate;
		break;
	      case KEV_RENEGOTIATE:
		current_event = KEV_RENEGOTIATE;
		next_event = KEV_EXPIRE;
		next_event_time = construct_time + proto.config->expire;
		break;
	      case KEV_EXPIRE:
		invalidate();
		current_event = KEV_EXPIRE;
		break;
	      default:
		break;
	      }
	  }
      }

      unsigned int initial_op(const bool sender) const
      {
	if (key_id_)
	  return CONTROL_SOFT_RESET_V1;
	else
	  return (proto.is_server() == sender) ? CONTROL_HARD_RESET_SERVER_V2 : CONTROL_HARD_RESET_CLIENT_V2;
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
	  case S_WAIT_AUTH_ACK: // rare case where client receives auth, goes ACTIVE, but the ACK response is dropped
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
		active();
		state = ACTIVE;
		break;
	      case S_WAIT_AUTH_ACK:
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
	buf->write(proto_context_private::auth_prefix, sizeof(proto_context_private::auth_prefix));
	tlsprf_self.randomize();
	tlsprf_self.write(*buf);
	const std::string options = proto.config->options_string();
	write_auth_string(options, *buf);
	if (!proto.is_server())
	  {
	    buf->or_flags(BufferAllocated::DESTRUCT_ZERO);
	    proto.client_auth(*buf);
	    const std::string peer_info = proto.config->peer_info_string();
	    write_auth_string(peer_info, *buf);
	  }
	Base::app_send(buf);
	dirty = true;
      }

      void recv_auth(BufferAllocated& buf)
      {
	const unsigned char *buf_pre = buf.read_alloc(sizeof(proto_context_private::auth_prefix));
	if (std::memcmp(buf_pre, proto_context_private::auth_prefix, sizeof(proto_context_private::auth_prefix)))
	  throw bad_auth_prefix();
	tlsprf_peer.read(buf);
	const std::string options = read_auth_string<std::string>(buf);
	if (proto.is_server())
	  {
	    Buffer auth(buf);
	    skip_string(buf); // username
	    skip_string(buf); // password
	    auth.set_size(buf.offset() - auth.offset());
	    const std::string peer_info = read_auth_string<std::string>(buf);
	    proto.server_auth(auth, peer_info);
	  }
      }

      void active()
      {
	generate_session_keys();
	while (!app_pre_write_queue.empty())
	  {
	    Base::app_send(app_pre_write_queue.front());
	    app_pre_write_queue.pop_front();
	    dirty = true;
	  }
	reached_active_time_ = *now;
	proto.slowest_handshake_.max(reached_active_time_ - construct_time);
	active_event();
      }

      // use the TLS PRF construction to exchange session keys for building
      // the data channel crypto context
      void generate_session_keys()
      {
	OpenVPNStaticKey key;
	tlsprf_self.generate_key_expansion(key, tlsprf_peer, proto.psid_self, proto.psid_peer);
	OPENVPN_LOG_PROTO("KEY " << proto.mode().str() << ' ' << key.render());
	init_data_channel_crypto_context(key);
	tlsprf_self.erase();
	tlsprf_peer.erase();
      }

      // given our ephemeral session key, initialize the components of the
      // OpenVPN data channel protocol
      void init_data_channel_crypto_context(const OpenVPNStaticKey& key)
      {
	const Config& c = *proto.config;
	const unsigned int key_dir = proto.is_server() ? OpenVPNStaticKey::INVERSE : OpenVPNStaticKey::NORMAL;

	// initialize CryptoContext encrypt
	crypto.encrypt.frame = c.frame;
	crypto.encrypt.cipher.init(c.cipher,
				   key.slice(OpenVPNStaticKey::CIPHER | OpenVPNStaticKey::ENCRYPT | key_dir),
				   CipherContext::ENCRYPT);
	crypto.encrypt.hmac.init(c.digest,
				 key.slice(OpenVPNStaticKey::HMAC | OpenVPNStaticKey::ENCRYPT | key_dir));
	crypto.encrypt.pid_send.init(PacketID::SHORT_FORM);
	crypto.encrypt.prng = c.prng;

	// initialize CryptoContext decrypt
	crypto.decrypt.frame = c.frame;
	crypto.decrypt.stats = proto.stats;
	crypto.decrypt.cipher.init(c.cipher,
				   key.slice(OpenVPNStaticKey::CIPHER | OpenVPNStaticKey::DECRYPT | key_dir),
				   CipherContext::DECRYPT);
	crypto.decrypt.hmac.init(c.digest,
				 key.slice(OpenVPNStaticKey::HMAC | OpenVPNStaticKey::DECRYPT | key_dir));
	crypto.decrypt.pid_recv.init(c.pid_mode,
				     PacketID::SHORT_FORM,
				     c.pid_seq_backtrack, c.pid_time_backtrack,
				     "DATA", int(key_id_),
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
	    buf.prepend_alloc(proto.hmac_size);

	    // write source PSID
	    proto.psid_self.prepend(buf);

	    // write opcode
	    buf.push_front(op_compose(opcode, key_id_));

	    // write hmac
	    proto.ta_hmac_send.hmac3_gen(buf.data(), buf.size(),
					 1 + ProtoSessionID::SIZE,
					 proto.hmac_size,
					 PacketID::size(PacketID::LONG_FORM));
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
		proto.stats->error(ProtoStats::CC_ERROR);
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
		proto.stats->error(ProtoStats::CC_ERROR);
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
	    proto.stats->error(ProtoStats::CC_ERROR);
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
	try {
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
		recv.advance(proto.hmac_size);
		if (!proto.ta_hmac_recv.hmac3_cmp(orig_data, orig_size,
						  1 + ProtoSessionID::SIZE,
						  proto.hmac_size,
						  PacketID::size(PacketID::LONG_FORM)))
		  {
		    proto.stats->error(ProtoStats::HMAC_ERROR);
		    return false;
		  }      
	      }

	      // update our last-packet-received time
	      proto.update_last_received();

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
		      proto.stats->error(ProtoStats::REPLAY_ERROR);
		      if (pid.is_valid())
			xmit_acks.push_back(id); // even replayed packets must be ACKed or protocol could deadlock
		    }
		}
	    }
	  else // non tls_auth mode
	    {
	      // update our last-packet-received time
	      proto.update_last_received();

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
	}
	catch (buffer_exception& e)
	  {
	    proto.stats->error(ProtoStats::BUFFER_ERROR);
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
      bool handled_pid_wrap;
      Time construct_time;
      Time reached_active_time_;
      Time next_event_time;
      EventType current_event;
      EventType next_event;
      Compress::Ptr compress;
      std::deque<BufferPtr> app_pre_write_queue;
      CryptoContext crypto;
      TLSPRF tlsprf_self;
      TLSPRF tlsprf_peer;
    };

  public:
    OPENVPN_SIMPLE_EXCEPTION(select_key_context_error);

    ProtoContext(const typename Config::Ptr& config_arg,  // configuration
		 const ProtoStats::Ptr& stats_arg)        // error stats
      : config(config_arg),
	stats(stats_arg),
	mode_(config_arg->ssl_ctx->mode()),
	n_key_ids(0),
	now_(config_arg->now),
	keepalive_ping(config_arg->keepalive_ping),
	keepalive_timeout(config_arg->keepalive_timeout)
    {
      const Config& c = *config;

      // tls-auth setup
      if (c.tls_auth_key.defined())
	{
	  use_tls_auth = true;

	  // get HMAC size from Digest object
	  hmac_size = c.tls_auth_digest.size();
	}
      else
	{
	  use_tls_auth = false;
	  hmac_size = 0;
	}
      reset();
    }

    void reset()
    {
      const Config& c = *config;

      // clear key contexts
      primary.reset();
      secondary.reset();

      // start with key ID 0
      upcoming_key_id = 0;

      // tls-auth initialization
      if (use_tls_auth)
	{
	  // init tls_auth hmac
	  const unsigned int key_dir = is_server() ? OpenVPNStaticKey::NORMAL : OpenVPNStaticKey::INVERSE;
	  ta_hmac_send.init(c.tls_auth_digest, c.tls_auth_key.slice(OpenVPNStaticKey::HMAC | OpenVPNStaticKey::ENCRYPT | key_dir));
	  ta_hmac_recv.init(c.tls_auth_digest, c.tls_auth_key.slice(OpenVPNStaticKey::HMAC | OpenVPNStaticKey::DECRYPT | key_dir));

	  // init tls_auth packet ID
	  ta_pid_send.init(PacketID::LONG_FORM);
	  ta_pid_recv.init(c.pid_mode,
			   PacketID::LONG_FORM,
			   c.pid_seq_backtrack, c.pid_time_backtrack,
			   "SSL-CC", 0,
			   c.pid_debug_level
			   );
	}

      // initialize proto session ID
      psid_self.randomize(*c.prng);
      psid_peer.reset();

      // initialize key contexts
      primary.reset(new KeyContext(*this, is_client()));

      // initialize keepalive timers
      keepalive_expire = Time::infinite();   // initially disabled
      update_last_sent();                    // set timer for initial keepalive send
    }

    virtual ~ProtoContext() {}

    // return the PacketType of an incoming network packet
    PacketType packet_type(const Buffer& buf)
    {
      PacketType pt;
      if (buf.size())
	{
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
	      else if (pt.opcode == CONTROL_SOFT_RESET_V1 && kid == upcoming_key_id)
		pt.flags |= (PacketType::DEFINED | PacketType::SECONDARY | PacketType::SOFT_RESET);
	    }
	}
      return pt;
    }

    // start protocol negotiation
    void start()
    {
      primary->start();
      update_last_received(); // set an upper bound on when we expect a response
    }

    // trigger a protocol renegotiation
    void renegotiate()
    {
      // initialize secondary key context
      secondary.reset(new KeyContext(*this, true));
      secondary->start();
    }

    // Should be called at the end of sequence of send/recv
    // operations on underlying protocol object.
    // If control_channel is true, do a full flush.
    // If control_channel is false, optimize flush for data
    // channel only.
    void flush(const bool control_channel)
    {
      if (control_channel || process_events())
	{
	  do {
	    primary->flush();
	    if (secondary)
	      secondary->flush();
	  } while (process_events());
	}
    }

    // Perform various time-based housekeeping tasks such as retransmiting
    // unacknowleged packets as part of the reliability layer and testing
    // for keepalive timouts.
    // Should be called at the time returned by next_housekeeping.
    void housekeeping()
    {
      // handle control channel retransmissions on primary
      primary->retransmit();

      // handle control channel retransmissions on secondary
      if (secondary)
	secondary->retransmit();

      // handle possible events
      flush(false);

      // handle keepalive/expiration
      keepalive_housekeeping();
    }

    // When should we next call housekeeping?
    // Will return a time value for immediate execution
    // if session has been invalidated.
    Time next_housekeeping() const
    {
      if (!invalidated())
	{
	  Time ret = primary->next_retransmit();
	  if (secondary)
	    ret.min(secondary->next_retransmit());
	  ret.min(keepalive_xmit);
	  ret.min(keepalive_expire);
	  return ret;
	}
      else
	return Time();
    }

    // send app-level cleartext to remote peer

    void control_send(BufferPtr& app_bp)
    {
      select_control_send_context().app_send(app_bp);
    }

    void control_send(BufferAllocated& app_buf)
    {
      BufferPtr bp = new BufferAllocated();
      bp->move(app_buf);
      select_control_send_context().app_send(bp);
    }

    // validate a control channel network packet
    bool control_net_validate(const PacketType& type, const Buffer& net_buf)
    {
      return type.is_defined() && KeyContext::validate(net_buf, *this, now_);
    }

    // pass received control channel network packets (ciphertext) into protocol object

    void control_net_recv(const PacketType& type, BufferAllocated& net_buf)
    {
      BufferPtr bp = new BufferAllocated();
      bp->move(net_buf);
      Packet pkt(bp, type.opcode);
      if (type.is_soft_reset() && !renegotiate_request(pkt))
	return;
      select_key_context(type, true).net_recv(pkt);
    }

    void control_net_recv(const PacketType& type, BufferPtr& net_bp)
    {
      Packet pkt(net_bp, type.opcode);
      if (type.is_soft_reset() && !renegotiate_request(pkt))
	return;
      select_key_context(type, true).net_recv(pkt);
    }

    // encrypt a data channel packet using primary KeyContext
    void data_encrypt(BufferAllocated& in_out)
    {
      primary->encrypt(in_out);
    }

    // decrypt a data channel packet (automatically select primary
    // or secondary KeyContext based on packet content)
    void data_decrypt(const PacketType& type, BufferAllocated& in_out)
    {
      select_key_context(type, false).decrypt(in_out);

      // update time of most recent packet received
      if (in_out.size())
	update_last_received();

      // discard keepalive packets
      if (proto_context_private::is_keepalive(in_out))
	{
	  in_out.reset_size();
	}
    }

    // enter disconnected state
    void disconnect()
    {
      primary->invalidate();
      if (secondary)
	secondary->invalidate();
    }

    // should be called after a successful network packet transmit
    void update_last_sent() { keepalive_xmit = *now_ + keepalive_ping; }

    // can we call data_encrypt or data_decrypt yet?
    bool data_channel_ready() const { return primary->data_channel_ready(); }

    // total number of SSL/TLS negotiations during lifetime of ProtoContext object
    unsigned int negotiations() const { return n_key_ids; }

    // worst-case handshake time
    const Time::Duration& slowest_handshake() { return slowest_handshake_; }

    // was primary context invalidated by an exception?
    bool invalidated() const { return primary->invalidated(); }

    // current time
    const Time& now() const { return *now_; }
    void update_now() { now_->update(); }

    // frame
    const Frame& frame() const { return *config->frame; }
    const Frame::Ptr& frameptr() const { return config->frame; }

    // client or server?
    const Mode& mode() const { return mode_; }
    bool is_server() const { return mode_.is_server(); }
    bool is_client() const { return mode_.is_client(); }

    // configuration
    const Config& conf() const { return *config; }

  private:
    virtual void control_net_send(const Buffer& net_buf) = 0;

    virtual void control_recv(BufferPtr& app_bp) = 0;

    // Called on client to request username/password credentials.
    // Should be overriden by derived class if credentials are required.
    // username and password should be written into buf with write_auth_string().
    virtual void client_auth(Buffer& buf)
    {
      write_empty_string(buf); // username
      write_empty_string(buf); // password
    }

    // Called on server with credentials and peer info provided by client.
    // Should be overriden by derived class if credentials are required.
    // Username and password should be read from buf with read_auth_string().
    virtual void server_auth(Buffer& buf, const std::string& peer_info)
    {
    }

    // Called when initial KeyContext transitions to ACTIVE state
    virtual void active()
    {
    }

    void update_last_received() { keepalive_expire = *now_ + keepalive_timeout; }

    void net_send(const unsigned int key_id, const Packet& net_pkt)
    {
      control_net_send(net_pkt.buffer());
    }

    void app_recv(const unsigned int key_id, BufferPtr& to_app_buf)
    {
      control_recv(to_app_buf);
    }

    // we're getting a request from peer to renegotiate.
    bool renegotiate_request(Packet& pkt)
    {
      if (KeyContext::validate(pkt.buffer(), *this, now_))
	{
	  secondary.reset(new KeyContext(*this, false));
	  return true;
	}
      else
	return false;
    }

    // select a KeyContext (primary or secondary) for received network packets
    KeyContext& select_key_context(const PacketType& type, const bool control)
    {
      const unsigned int flags = type.flags & (PacketType::DEFINED|PacketType::SECONDARY|PacketType::CONTROL);
      if (!control)
	{
	  if (flags == (PacketType::DEFINED))
	    return *primary;
	  else if (flags == (PacketType::DEFINED|PacketType::SECONDARY) && secondary)
	    return *secondary;
	}
      else
	{
	  if (flags == (PacketType::DEFINED|PacketType::CONTROL))
	    return *primary;
	  else if (flags == (PacketType::DEFINED|PacketType::SECONDARY|PacketType::CONTROL) && secondary)
	    return *secondary;
	}
      throw select_key_context_error();
    }

    // Select a KeyContext (primary or secondary) for control channel sends.
    // NOTE: possible incompatibility with existing OpenVPN protocol.
    // Even after new key context goes active, we still wait for
    // KEV_BECOME_PRIMARY event before we use it for app-level control-channel
    // transmissions.  Simulations have found this method to be more reliable.
    KeyContext& select_control_send_context()
    {
      return *primary;
    }

    // Possibly send a keepalive message, and check for expiration
    // of session due to lack of received packets from peer.
    void keepalive_housekeeping()
    {
      const Time now = *now_;

      // check for keepalive timeouts
      if (now >= keepalive_xmit)
	{
	  primary->send_keepalive();
	  update_last_sent();
	}
      if (now >= keepalive_expire)
	{
	  // no contact with peer, disconnect
	  stats->error(ProtoStats::KEEPALIVE_TIMEOUT);
	  disconnect();
	}
    }

    // Process KEV_x events
    // Return true if any events were processed.
    bool process_events()
    {
      bool did_work = false;

      // primary
      if (primary->event_pending())
	{
	  process_primary_event();
	  did_work = true;
	}

      // secondary
      if (secondary && secondary->event_pending())
	{
	  process_secondary_event();
	  did_work = true;
	}

      return did_work;
    }

    // Promote a newly renegotiated KeyContext to primary status.
    // This is usually triggered by become_primary variable (Time::Duration)
    // in Config.
    void promote_secondary_to_primary()
    {
      primary.swap(secondary);
      secondary->prepare_expire();
    }

    void process_primary_event()
    {
      const typename KeyContext::EventType ev = primary->get_event();
      if (ev != KeyContext::KEV_NONE)
	{
	  primary->reset_event();
	  switch (ev)
	    {
	    case KeyContext::KEV_ACTIVE:
	      OPENVPN_LOG_PROTO("*** SESSION_ACTIVE");
	      active();
	      break;
	    case KeyContext::KEV_RENEGOTIATE:
	      renegotiate();
	      break;
	    case KeyContext::KEV_EXPIRE:
	      if (secondary && !secondary->invalidated())
		promote_secondary_to_primary();
	      else
		stats->error(ProtoStats::PRIMARY_EXPIRE);
		disconnect(); // primary context expired and no secondary context available
	      break;
	    case KeyContext::KEV_NEGOTIATE_FAILED:
	      stats->error(ProtoStats::HANDSHAKE_TIMEOUT);
	      disconnect();   // primary negotiation failed
	      break;
	    default:
	      break;
	    }
	}
    }

    void process_secondary_event()
    {
      const typename KeyContext::EventType ev = secondary->get_event();
      if (ev != KeyContext::KEV_NONE)
	{
	  secondary->reset_event();
	  switch (ev)
	    {
	    case KeyContext::KEV_ACTIVE:
	      primary->prepare_expire();
	      break;
	    case KeyContext::KEV_BECOME_PRIMARY:
	      if (!secondary->invalidated())
		promote_secondary_to_primary();
	      break;
	    case KeyContext::KEV_EXPIRE:
	      secondary.reset();
	      break;
	    case KeyContext::KEV_NEGOTIATE_FAILED:
	      stats->error(ProtoStats::HANDSHAKE_TIMEOUT);
	      renegotiate();
	      break;
	    default:
	      break;
	    }
	}
    }

    unsigned int validate_opcode(const unsigned int op)
    {
      // get opcode
      const unsigned int opcode = opcode_extract(op);

      // validate opcode
      if (opcode >= CONTROL_SOFT_RESET_V1 && opcode <= DATA_V1)
	return opcode;
      if (is_server())
	  {
	    if (opcode == CONTROL_HARD_RESET_CLIENT_V2)
	      return opcode;
	  }
      else
	{
	  if (opcode == CONTROL_HARD_RESET_SERVER_V2)
	    return opcode;
	}

      stats->error(ProtoStats::CC_ERROR);
      return INVALID_OPCODE;
    }

    // key_id starts at 0, increments to KEY_ID_MASK, then recycles back to 1.
    // Therefore, if key_id is 0, it is the first key.
    unsigned int next_key_id()
    {
      ++n_key_ids;
      unsigned int ret = upcoming_key_id;
      if ((upcoming_key_id = (upcoming_key_id + 1) & KEY_ID_MASK) == 0)
	upcoming_key_id = 1;
      return ret;
    }

    // BEGIN ProtoContext data members

    typename Config::Ptr config;
    ProtoStats::Ptr stats;

    size_t hmac_size;
    bool use_tls_auth;
    Mode mode_;                        // client or server
    unsigned int upcoming_key_id;
    unsigned int n_key_ids;

    TimePtr now_;                      // pointer to current time (a clone of config->now)
    Time::Duration keepalive_ping;     // copied from config
    Time keepalive_xmit;               // time in future when we will transmit a keepalive (subject to continuous change)
    Time::Duration keepalive_timeout;  // copied from config
    Time keepalive_expire;             // time in future when we must have received a packet from peer or we will timeout session

    Time::Duration slowest_handshake_; // longest time to reach a successful handshake

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
