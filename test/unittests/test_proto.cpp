//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

/**
   @file
   @brief Unit test for OpenVPN Protocol implementation (class ProtoContext)
*/

#include "test_common.hpp"

#include <iostream>
#include <string>
#include <sstream>
#include <deque>
#include <algorithm>
#include <cstring>
#include <limits>
#include <thread>

#include <gmock/gmock.h>
#include <openvpn/common/platform.hpp>
#include <openvpn/ssl/sslchoose.hpp>
#include <openvpn/client/cliproto.hpp>


#define OPENVPN_DEBUG

#if !defined(USE_TLS_AUTH) && !defined(USE_TLS_CRYPT)
// #define USE_TLS_AUTH
// #define USE_TLS_CRYPT
#define USE_TLS_CRYPT_V2
#endif

// Data limits for Blowfish and other 64-bit block-size ciphers
#ifndef BF
#define BF 0
#endif
#if BF == 1
#define PROTO_CIPHER "BF-CBC"
#define TLS_VER_MIN TLSVersion::UNDEF
#define HANDSHAKE_WINDOW 60
#define BECOME_PRIMARY_CLIENT 5
#define BECOME_PRIMARY_SERVER 5
#define TLS_TIMEOUT_CLIENT 1000
#define TLS_TIMEOUT_SERVER 1000
#define FEEDBACK 0
#elif BF == 2
#define PROTO_CIPHER "BF-CBC"
#define TLS_VER_MIN TLSVersion::UNDEF
#define HANDSHAKE_WINDOW 10
#define BECOME_PRIMARY_CLIENT 10
#define BECOME_PRIMARY_SERVER 10
#define TLS_TIMEOUT_CLIENT 2000
#define TLS_TIMEOUT_SERVER 1000
#define FEEDBACK 0
#elif BF == 3
#define PROTO_CIPHER "BF-CBC"
#define TLS_VER_MIN TLSVersion::UNDEF
#define HANDSHAKE_WINDOW 60
#define BECOME_PRIMARY_CLIENT 60
#define BECOME_PRIMARY_SERVER 10
#define TLS_TIMEOUT_CLIENT 2000
#define TLS_TIMEOUT_SERVER 1000
#define FEEDBACK 0
#elif BF != 0
#error unknown BF value
#endif

// TLS timeout
#ifndef TLS_TIMEOUT_CLIENT
#define TLS_TIMEOUT_CLIENT 2000
#endif
#ifndef TLS_TIMEOUT_SERVER
#define TLS_TIMEOUT_SERVER 2000
#endif

// NoisyWire
#ifndef NOERR
#define SIMULATE_OOO
#define SIMULATE_DROPPED
#define SIMULATE_CORRUPTED
#endif

// how many virtual seconds between SSL renegotiations
#ifdef PROTO_RENEG
#define RENEG PROTO_RENEG
#else
#define RENEG 900
#endif

// feedback
#ifndef FEEDBACK
#define FEEDBACK 1
#else
#define FEEDBACK 0
#endif

// number of iterations
#ifdef PROTO_ITER
#define ITER PROTO_ITER
#else
#define ITER 1000000
#endif

// number of high-level session iterations
#ifdef PROTO_SITER
#define SITER PROTO_SITER
#else
#define SITER 1
#endif

// number of retries for failed test
#ifndef N_RETRIES
#define N_RETRIES 2
#endif

// potentially, the above manifest constants can be converted to variables and modified
// within the different TEST() functions that replace main() in the original file

// abort if we reach this limit
// #define DROUGHT_LIMIT 100000

#if !defined(PROTO_VERBOSE) && !defined(QUIET) && ITER <= 10000
#define VERBOSE
#endif

#define STRINGIZE1(x) #x
#define STRINGIZE(x) STRINGIZE1(x)

// setup cipher
#ifndef PROTO_CIPHER
#ifdef PROTOv2
#define PROTO_CIPHER "AES-256-GCM"
#define TLS_VER_MIN TLSVersion::Type::V1_2
#else
#define PROTO_CIPHER "AES-128-CBC"
#define TLS_VER_MIN TLSVersion::Type::UNDEF
#endif
#endif

// setup digest
#ifndef PROTO_DIGEST
#define PROTO_DIGEST "SHA1"
#endif

// setup compressor
#ifdef PROTOv2
#ifdef HAVE_LZ4
#define COMP_METH CompressContext::LZ4v2
#else
#define COMP_METH CompressContext::COMP_STUBv2
#endif
#else
#define COMP_METH CompressContext::LZO_STUB
#endif

#include <filesystem>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/common/count.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/random/mtrandapi.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/ssl/proto.hpp>
#include <openvpn/init/initprocess.hpp>

#include <openvpn/crypto/cryptodcsel.hpp>

#if !(defined(USE_OPENSSL) || defined(USE_MBEDTLS))
#error Must define one or more of USE_OPENSSL, USE_MBEDTLS.
#endif

#if defined(USE_OPENSSL) && defined(USE_MBEDTLS)
#undef USE_OPENSSL
#define USE_OPENSSL_SERVER
#elif !defined(USE_OPENSSL) && defined(USE_MBEDTLS)
#define USE_MBEDTLS_SERVER
#elif defined(USE_OPENSSL) && !defined(USE_MBEDTLS)
#define USE_OPENSSL_SERVER
#else
#error no server setup
#endif

#if defined(USE_OPENSSL) || defined(USE_OPENSSL_SERVER)
#include <openvpn/openssl/crypto/api.hpp>
#include <openvpn/openssl/ssl/sslctx.hpp>
#include <openvpn/openssl/util/rand.hpp>
#endif

#if defined(USE_MBEDTLS) || defined(USE_MBEDTLS_SERVER)
#include <openvpn/mbedtls/crypto/api.hpp>
#include <openvpn/mbedtls/ssl/sslctx.hpp>
#include <openvpn/mbedtls/util/rand.hpp>
#include <mbedtls/debug.h>
#endif

#include <openvpn/crypto/selftest.hpp>

using namespace openvpn;

// server Crypto/SSL/Rand implementation
#ifdef USE_MBEDTLS_SERVER
typedef MbedTLSCryptoAPI ServerCryptoAPI;
typedef MbedTLSContext ServerSSLAPI;
typedef MbedTLSRandom ServerRandomAPI;
#elif defined(USE_OPENSSL_SERVER)
using ServerCryptoAPI = OpenSSLCryptoAPI;
using ServerSSLAPI = OpenSSLContext;
using ServerRandomAPI = OpenSSLRandom;
#else
#error No server SSL implementation defined
#endif

// client SSL implementation can be OpenSSL or MbedTLS
#ifdef USE_MBEDTLS
typedef MbedTLSCryptoAPI ClientCryptoAPI;
typedef MbedTLSContext ClientSSLAPI;
typedef MbedTLSRandom ClientRandomAPI;
#elif defined(USE_OPENSSL)
using ClientCryptoAPI = OpenSSLCryptoAPI;
using ClientSSLAPI = OpenSSLContext;
using ClientRandomAPI = OpenSSLRandom;
#else
#error No client SSL implementation defined
#endif

const char message[] = "Message _->_ 0000000000 It was a bright cold day in April, and the clocks\n"
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

// A "Drought" measures the maximum period of time between
// any two successive events.  Used to measure worst-case
// packet loss.
class DroughtMeasure
{
  public:
    OPENVPN_SIMPLE_EXCEPTION(drought_limit_exceeded);

    DroughtMeasure(const std::string &name_arg, TimePtr now_arg)
        : now(now_arg), name(name_arg)
    {
    }

    void event()
    {
        if (last_event.defined())
        {
            Time::Duration since_last = *now - last_event;
            if (since_last > drought)
            {
                drought = since_last;
#if defined(VERBOSE) || defined(DROUGHT_LIMIT)
                {
                    const unsigned int r = drought.raw();
#if defined(VERBOSE)
                    std::cout << "*** Drought " << name << " has reached " << r << "\n";
#endif
#ifdef DROUGHT_LIMIT
                    if (r > DROUGHT_LIMIT)
                        throw drought_limit_exceeded();
#endif
                }
#endif
            }
        }
        last_event = *now;
    }

    Time::Duration operator()() const
    {
        return drought;
    }

  private:
    TimePtr now;
    Time last_event;
    Time::Duration drought;
    std::string name;
};

// test the OpenVPN protocol implementation in ProtoContext
class TestProto : public ProtoContextCallbackInterface
{
    /* Callback methods that are not used */
    void active(bool primary) override
    {
    }

    bool supports_epoch_data() override
    {
        return true;
    }

  public:
    OPENVPN_EXCEPTION(session_invalidated);

    TestProto(const ProtoContext::ProtoConfig::Ptr &config,
              const SessionStats::Ptr &stats)
        : proto_context(this, config, stats),
          control_drought("control", config->now),
          data_drought("data", config->now),
          frame(config->frame)
    {
        // zero progress value
        std::memset(progress_, 0, 11);
    }

    void reset()
    {
        net_out.clear();
        wkc_pkt_sizes_.clear();
        max_ctrl_pkt_size_ = 0;
        proto_context.reset();
        proto_context.conf().mss_parms.mssfix = MSSParms::MSSFIX_DEFAULT;
    }

    void initial_app_send(const char *msg)
    {
        proto_context.start();
        const size_t msglen = std::strlen(msg) + 1;
        BufferAllocated app_buf((unsigned char *)msg, msglen, BufAllocFlags::NO_FLAGS);
        copy_progress(app_buf);
        control_send(std::move(app_buf));
        proto_context.flush(true);
    }

    void app_send_templ_init(const char *msg)
    {
        proto_context.start();
        const size_t msglen = std::strlen(msg) + 1;
        templ = BufferAllocatedRc::Create((unsigned char *)msg, msglen, BufAllocFlags::NO_FLAGS);
        proto_context.flush(true);
    }

    void app_send_templ()
    {
#if !FEEDBACK
        if (bool(iteration++ & 1) == is_server())
        {
            modmsg(templ);
            BufferAllocated app_buf(*templ);
            control_send(std::move(app_buf));
            flush(true);
            ++n_control_send_;
        }
#endif
    }

    bool do_housekeeping()
    {
        if (proto_context.now() >= proto_context.next_housekeeping())
        {
            proto_context.housekeeping();
            return true;
        }
        return false;
    }

    void control_send(BufferPtr &&app_bp)
    {
        app_bytes_ += app_bp->size();
        proto_context.control_send(std::move(app_bp));
    }

    void control_send(BufferAllocated &&app_buf)
    {
        app_bytes_ += app_buf.size();
        proto_context.control_send(std::move(app_buf));
    }

    BufferPtr data_encrypt_string(const char *str)
    {
        BufferPtr bp = BufferAllocatedRc::Create();
        frame->prepare(Frame::READ_LINK_UDP, *bp);
        bp->write((unsigned char *)str, std::strlen(str));
        data_encrypt(*bp);
        return bp;
    }

    void data_encrypt(BufferAllocated &in_out)
    {
        proto_context.data_encrypt(in_out);
    }

    void data_decrypt(const ProtoContext::PacketType &type, BufferAllocated &in_out)
    {
        proto_context.data_decrypt(type, in_out);
        if (!in_out.empty())
        {
            data_bytes_ += in_out.size();
            data_drought.event();
        }
    }

    size_t net_bytes() const
    {
        return net_bytes_;
    }
    size_t app_bytes() const
    {
        return app_bytes_;
    }
    size_t data_bytes() const
    {
        return data_bytes_;
    }
    size_t n_control_recv() const
    {
        return n_control_recv_;
    }
    size_t n_control_send() const
    {
        return n_control_send_;
    }

    const char *progress() const
    {
        return progress_;
    }

    void finalize()
    {
        data_drought.event();
        control_drought.event();
    }

    void check_invalidated()
    {
        if (proto_context.invalidated())
            throw session_invalidated(Error::name(proto_context.invalidation_reason()));
    }

    void disable_xmit()
    {
        disable_xmit_ = true;
    }

    ProtoContext proto_context;

    std::deque<BufferPtr> net_out;

    // sizes of the CONTROL_WKC_V1 packets (the tls-crypt-v2 WKc riders)
    // emitted via control_net_send().  Only these are recorded, so the
    // vector stays tiny even across the long feedback tests.
    std::vector<size_t> wkc_pkt_sizes_;

    // largest control channel packet emitted via control_net_send()
    size_t max_ctrl_pkt_size_ = 0;

    size_t max_ctrl_pkt_size() const
    {
        return max_ctrl_pkt_size_;
    }

    // Verify every emitted CONTROL_WKC_V1 packet fits within max_size,
    // and that at least one such packet was emitted.
    bool verify_wkc_packets_fit(size_t max_size) const
    {
        if (wkc_pkt_sizes_.empty())
        {
            std::cerr << "no CONTROL_WKC_V1 packet was emitted by the client\n";
            return false;
        }
        for (const size_t size : wkc_pkt_sizes_)
        {
            if (size > max_size)
            {
                std::cerr << "CONTROL_WKC_V1 packet too large: " << size
                          << " > " << max_size << '\n';
                return false;
            }
        }
        return true;
    }

    DroughtMeasure control_drought;
    DroughtMeasure data_drought;

  private:
    void control_net_send(const Buffer &net_buf) override
    {
        if (disable_xmit_)
            return;
        net_bytes_ += net_buf.size();
        max_ctrl_pkt_size_ = std::max(max_ctrl_pkt_size_, net_buf.size());
        if (net_buf.size()
            && (net_buf.c_data()[0] >> ProtoContext::OPCODE_SHIFT) == ProtoContext::CONTROL_WKC_V1)
            wkc_pkt_sizes_.push_back(net_buf.size());
        net_out.push_back(BufferAllocatedRc::Create(net_buf, BufAllocFlags::NO_FLAGS));
    }

    void control_recv(BufferPtr &&app_bp) override
    {
        BufferPtr work;
        work.swap(app_bp);
        if (work->size() >= 23)
            std::memcpy(progress_, work->data() + 13, 10);

#ifdef VERBOSE
        {
            const ssize_t trunc = 64;
            const std::string show((char *)work->data(), trunc);
            std::cout << now().raw() << " " << mode().str() << " " << show << "\n";
        }
#endif
#if FEEDBACK
        modmsg(work);
        control_send(std::move(work));
#endif
        control_drought.event();
        ++n_control_recv_;
    }

    void copy_progress(Buffer &buf)
    {
        if (progress_[0]) // make sure progress was initialized
            std::memcpy(buf.data() + 13, progress_, 10);
    }

    void modmsg(BufferPtr &buf)
    {
        char *msg = (char *)buf->data();
        if (proto_context.is_server())
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
            msg[i] = '0';
        }
    }

    Frame::Ptr frame;
    size_t app_bytes_ = 0;
    size_t net_bytes_ = 0;
    size_t data_bytes_ = 0;
    size_t n_control_send_ = 0;
    size_t n_control_recv_ = 0;
    BufferPtr templ;
#if !FEEDBACK
    size_t iteration = 0;
#endif
    char progress_[11];
    bool disable_xmit_ = false;
};

class TestProtoClient : public TestProto
{
    using Base = TestProto;

  public:
    TestProtoClient(const ProtoContext::ProtoConfig::Ptr &config,
                    const SessionStats::Ptr &stats)
        : TestProto(config, stats)
    {
    }

  private:
    void client_auth(Buffer &buf) override
    {
        const std::string username("foo");
        const std::string password("bar");
        ProtoContext::write_auth_string(username, buf);
        ProtoContext::write_auth_string(password, buf);
    }
};

class TestProtoServer : public TestProto
{

  public:
    void start()
    {
        proto_context.start();
    }

    OPENVPN_SIMPLE_EXCEPTION(auth_failed);


    TestProtoServer(const ProtoContext::ProtoConfig::Ptr &config,
                    const SessionStats::Ptr &stats)
        : TestProto(config, stats)
    {
    }

  private:
    void server_auth(const std::string &username,
                     const SafeString &password,
                     const std::string &peer_info,
                     const AuthCert::Ptr &auth_cert) override
    {
#ifdef VERBOSE
        std::cout << "**** AUTHENTICATE " << username << '/' << password << " PEER INFO:\n";
        std::cout << peer_info;
#endif
        if (username != "foo" || password != "bar")
            throw auth_failed();
    }
};

// Simulate a noisy transmission channel where packets can be dropped,
// reordered, or corrupted.
class NoisyWire
{
  public:
    NoisyWire(const std::string &title_arg,
              TimePtr now_arg,
              RandomAPI &rand_arg,
              const unsigned int reorder_prob_arg,
              const unsigned int drop_prob_arg,
              const unsigned int corrupt_prob_arg)
        : title(title_arg),
#ifdef VERBOSE
          now(now_arg),
#endif
          random(rand_arg),
          reorder_prob(reorder_prob_arg),
          drop_prob(drop_prob_arg),
          corrupt_prob(corrupt_prob_arg)
    {
    }

    template <typename T1, typename T2>
    void xfer(T1 &a, T2 &b)
    {
        // check for errors
        a.check_invalidated();
        b.check_invalidated();

        // need to retransmit?
        if (a.do_housekeeping())
        {
#ifdef VERBOSE
            std::cout << now->raw() << " " << title << " Housekeeping\n";
#endif
        }

        // queue a control channel packet
        a.app_send_templ();

        // queue a data channel packet
        if (a.proto_context.data_channel_ready())
        {
            BufferPtr bp = a.data_encrypt_string("Waiting for godot A... Waiting for godot B... Waiting for godot C... Waiting for godot D... Waiting for godot E... Waiting for godot F... Waiting for godot G... Waiting for godot H... Waiting for godot I... Waiting for godot J...");
            wire.push_back(bp);
        }

        // transfer network packets from A -> wire
        while (!a.net_out.empty())
        {
            BufferPtr bp = a.net_out.front();
#ifdef VERBOSE
            std::cout << now->raw() << " " << title << " " << a.dump_packet(*bp) << "\n";
#endif
            a.net_out.pop_front();
            wire.push_back(bp);
        }

        // transfer network packets from wire -> B
        while (true)
        {
            BufferPtr bp = recv();
            if (!bp)
                break;
            typename ProtoContext::PacketType pt = b.proto_context.packet_type(*bp);
            if (pt.is_control())
            {
#ifdef VERBOSE
                if (!b.control_net_validate(pt, *bp)) // not strictly necessary since control_net_recv will also validate
                    std::cout << now->raw() << " " << title << " CONTROL PACKET VALIDATION FAILED\n";
#endif
                b.proto_context.control_net_recv(pt, std::move(bp));
            }
            else if (pt.is_data())
            {
                try
                {
                    b.data_decrypt(pt, *bp);
#ifdef VERBOSE
                    if (bp->size())
                    {
                        const std::string show((char *)bp->data(), std::min(bp->size(), size_t(40)));
                        std::cout << now->raw() << " " << title << " DATA CHANNEL DECRYPT: " << show << "\n";
                    }
#endif
                }
                catch ([[maybe_unused]] const std::exception &e)
                {
#ifdef VERBOSE
                    std::cout << now->raw() << " " << title << " Exception on data channel decrypt: " << e.what() << "\n";
#endif
                }
            }
            else
            {
#ifdef VERBOSE
                std::cout << now->raw() << " " << title << " KEY_STATE_ERROR\n";
#endif
                b.proto_context.stat().error(Error::KEY_STATE_ERROR);
            }

#ifdef SIMULATE_UDP_AMPLIFY_ATTACK
            if (b.proto_context.is_state_client_wait_reset_ack())
            {
                b.disable_xmit();
#ifdef VERBOSE
                std::cout << now->raw() << " " << title << " SIMULATE_UDP_AMPLIFY_ATTACK disable client xmit\n";
#endif
            }
#endif
        }
        b.proto_context.flush(true);
    }

  private:
    BufferPtr recv()
    {
#ifdef SIMULATE_OOO
        // simulate packets being received out of order
        if (wire.size() >= 2 && !rand(reorder_prob))
        {
            const size_t i = random.randrange(wire.size() - 1) + 1;
#ifdef VERBOSE
            std::cout << now->raw() << " " << title << " Simulating packet reordering " << i << " -> 0\n";
#endif
            std::swap(wire[0], wire[i]);
        }
#endif

        if (!wire.empty())
        {
            BufferPtr bp = wire.front();
            wire.pop_front();

#ifdef VERBOSE
            std::cout << now->raw() << " " << title << " Received packet, size=" << bp->size() << "\n";
#endif

#ifdef SIMULATE_DROPPED
            // simulate dropped packet
            if (!rand(drop_prob))
            {
#ifdef VERBOSE
                std::cout << now->raw() << " " << title << " Simulating a dropped packet\n";
#endif
                return BufferPtr();
            }
#endif

#ifdef SIMULATE_CORRUPTED
            // simulate corrupted packet
            if (!bp->empty() && !rand(corrupt_prob))
            {
#ifdef VERBOSE
                std::cout << now->raw() << " " << title << " Simulating a corrupted packet\n";
#endif
                const size_t pos = random.randrange(bp->size());
                const unsigned char value = random.randrange(std::numeric_limits<unsigned char>::max());
                (*bp)[pos] = value;
            }
#endif
            return bp;
        }

        return BufferPtr();
    }

    unsigned int rand(const unsigned int prob)
    {
        if (prob)
            return random.randrange(prob);
        return 1;
    }

    std::string title;
#ifdef VERBOSE
    TimePtr now;
#endif
    RandomAPI &random;
    unsigned int reorder_prob;
    unsigned int drop_prob;
    unsigned int corrupt_prob;
    std::deque<BufferPtr> wire;
};

class MySessionStats : public SessionStats
{
  public:
    using Ptr = RCPtr<MySessionStats>;

    MySessionStats()
    {
        std::memset(errors, 0, sizeof(errors));
    }

    void error(const size_t err_type, const std::string *text = nullptr) override
    {
        if (err_type < Error::N_ERRORS)
            ++errors[err_type];
    }

    count_t get_error_count(const Error::Type type) const
    {
        if (type < Error::N_ERRORS)
            return errors[type];
        return 0;
    }

    void show_error_counts() const
    {
        for (size_t i = 0; i < Error::N_ERRORS; ++i)
        {
            count_t c = errors[i];
            if (c)
                std::cerr << Error::name(i) << " : " << c << '\n';
        }
    }

  private:
    count_t errors[Error::N_ERRORS];
};

/**
 * Create a client ssl config for testing.
 * @return
 */
static auto create_client_ssl_config(Frame::Ptr frame, ClientRandomAPI::Ptr rng, bool tls_version_mismatch = false)
{
    const std::string client_crt = read_text(TEST_KEYCERT_DIR "client.crt");
    const std::string client_key = read_text(TEST_KEYCERT_DIR "client.key");
    const std::string ca_crt = read_text(TEST_KEYCERT_DIR "ca.crt");

    // client config
    ClientSSLAPI::Config::Ptr cc(new ClientSSLAPI::Config());
    cc->set_mode(Mode(Mode::CLIENT));
    cc->set_frame(frame);
    cc->set_rng(rng);
    cc->load_ca(ca_crt, true);
    cc->load_cert(client_crt);
    cc->load_private_key(client_key);
    if (tls_version_mismatch)
        cc->set_tls_version_max(TLSVersion::Type::V1_2);
    else
        cc->set_tls_version_min(TLS_VER_MIN);
#ifdef VERBOSE
    cc->set_debug_level(1);
#endif
    return cc;
}

static auto create_client_proto_context(ClientSSLAPI::Config::Ptr cc,
                                        Frame::Ptr frame,
                                        ClientRandomAPI::Ptr rng,
                                        MySessionStats::Ptr cli_stats,
                                        Time &time,
                                        const std::string &tls_crypt_v2_key_fn = "",
                                        bool tls_auth_only = false,
                                        bool use_dynamic_tls_crypt = false,
                                        const std::string &tls_crypt_v2_dir = TEST_KEYCERT_DIR)
{
    const std::string tls_auth_key = read_text(TEST_KEYCERT_DIR "tls-auth.key");
    const std::string tls_crypt_v2_client_key = tls_crypt_v2_key_fn.empty()
                                                    ? read_text(TEST_KEYCERT_DIR "tls-crypt-v2-client.key")
                                                    : read_text(tls_crypt_v2_dir + tls_crypt_v2_key_fn);

    // client ProtoContext config
    using ClientProtoContext = ProtoContext;
    ClientProtoContext::ProtoConfig::Ptr cp(new ClientProtoContext::ProtoConfig);
    cp->ssl_factory = cc->new_factory();
    CryptoAlgs::allow_default_dc_algs<ClientCryptoAPI>(cp->ssl_factory->libctx(), false, false);
    cp->dc.set_factory(new CryptoDCSelect<ClientCryptoAPI>(cp->ssl_factory->libctx(), frame, cli_stats, rng));
    cp->tlsprf_factory.reset(new CryptoTLSPRFFactory<ClientCryptoAPI>());
    cp->frame = std::move(frame);
    cp->now = &time;
    cp->rng = rng;
    cp->prng = rng;
    cp->protocol = Protocol(Protocol::UDPv4);
    cp->layer = Layer(Layer::OSI_LAYER_3);
#ifdef PROTOv2
    cp->enable_op32 = true;
    cp->remote_peer_id = 100;
#endif
    cp->comp_ctx = CompressContext(COMP_METH, false);
    cp->dc.set_cipher(CryptoAlgs::lookup(PROTO_CIPHER));
    cp->dc.set_digest(CryptoAlgs::lookup(PROTO_DIGEST));

#ifdef USE_TLS_AUTH
    cp->tls_auth_factory.reset(new CryptoOvpnHMACFactory<ClientCryptoAPI>());
    cp->tls_auth_key.parse(tls_auth_key);
    cp->set_tls_auth_digest(CryptoAlgs::lookup(PROTO_DIGEST));
    cp->key_direction = 0;
#endif
#ifdef USE_TLS_CRYPT
    cp->tls_crypt_factory.reset(new CryptoTLSCryptFactory<ClientCryptoAPI>());
    cp->tls_crypt_key.parse(tls_auth_key);
    cp->set_tls_crypt_algs();
    cp->tls_crypt_ = ProtoContext::ProtoConfig::TLSCrypt::V1;
#endif
#ifdef USE_TLS_CRYPT_V2
    if (tls_auth_only)
    {
        // A plain tls-auth client, for testing a server that holds a tls-crypt-v2 key as
        // well: such a session must stay in TLS_AUTH mode from end to end.
        cp->tls_auth_factory.reset(new CryptoOvpnHMACFactory<ClientCryptoAPI>());
        cp->tls_auth_key.parse(tls_auth_key);
        cp->set_tls_auth_digest(CryptoAlgs::lookup(PROTO_DIGEST));
        cp->key_direction = 0;
    }
    else
    {
        cp->tls_crypt_factory.reset(new CryptoTLSCryptFactory<ClientCryptoAPI>());
        cp->set_tls_crypt_algs();
        {
            TLSCryptV2ClientKey tls_crypt_v2_key(cp->tls_crypt_context);
            tls_crypt_v2_key.parse(tls_crypt_v2_client_key);
            tls_crypt_v2_key.extract_key(cp->tls_crypt_key);
            tls_crypt_v2_key.extract_wkc(cp->wkc);
        }
        cp->tls_crypt_ = ProtoContext::ProtoConfig::TLSCrypt::V2;
    }
    if (use_dynamic_tls_crypt)
        cp->enable_dynamic_tls_crypt();
#endif
#ifdef HANDSHAKE_WINDOW
    cp->handshake_window = Time::Duration::seconds(HANDSHAKE_WINDOW);
#elif SITER > 1
    cp->handshake_window = Time::Duration::seconds(30);
#else
    cp->handshake_window = Time::Duration::seconds(18); // will cause a small number of handshake failures
#endif
#ifdef BECOME_PRIMARY_CLIENT
    cp->become_primary = Time::Duration::seconds(BECOME_PRIMARY_CLIENT);
#else
    cp->become_primary = cp->handshake_window;
#endif
    cp->tls_timeout = Time::Duration::milliseconds(TLS_TIMEOUT_CLIENT);
#ifdef CLIENT_NO_RENEG
    cp->renegotiate = Time::Duration::infinite();
#else
    cp->renegotiate = Time::Duration::seconds(RENEG);
#endif
    cp->expire = cp->renegotiate + cp->renegotiate;
    cp->keepalive_ping = Time::Duration::seconds(5);
    cp->keepalive_timeout = Time::Duration::seconds(60);
    cp->keepalive_timeout_early = cp->keepalive_timeout;

#ifdef VERBOSE
    std::cout << "CLIENT OPTIONS: " << cp->options_string() << "\n";
    std::cout << "CLIENT PEER INFO:\n";
    std::cout << cp->peer_info_string();
#endif
    return cp;
}

// Configures one specific test run */
struct proto_test
{
    bool use_tls_ekm = false;
    bool tls_version_mismatch = false;
    const std::string &tls_crypt_v2_key_fn = "";
    //! Where the client key named above and the server keys it names by K_id are
    //! read from. A test minting its own keys points this at them.
    const std::string &tls_crypt_v2_dir = TEST_KEYCERT_DIR;
    bool use_tls_auth_with_tls_crypt_v2 = false;
    bool client_tls_auth_only = false;
    bool spoof_hard_reset_v3 = false;
    bool force_resend_wkc = false;
    bool use_dynamic_tls_crypt = false;
    size_t control_payload = 378;
    size_t mssfix_ctrl = 0;
};

// execute the unit test in one thread
int test(const struct proto_test &t)
{
    try
    {
        // frame
        Frame::Ptr frame(new Frame(Frame::Context(128, 378, 128, 0, 16, BufAllocFlags::NO_FLAGS)));
        // Shrink only the control-channel ciphertext context, mirroring what
        // mssfix-ctrl does in production (see frame_init()): the cleartext
        // staging buffers (e.g. WRITE_SSL_CLEARTEXT, used for the auth
        // message) keep their normal size.
        (*frame)[Frame::READ_BIO_MEMQ_STREAM] = Frame::Context(128, t.control_payload, 128, 0, 16, BufAllocFlags::NO_FLAGS);

        // RNG
        ClientRandomAPI::Ptr prng_cli(new ClientRandomAPI());
        ServerRandomAPI::Ptr prng_serv(new ServerRandomAPI());
        MTRand rng_noncrypto;

        // init simulated time
        Time time;
        const Time::Duration time_step = Time::Duration::binary_ms(100);

        // config files
        const std::string ca_crt = read_text(TEST_KEYCERT_DIR "ca.crt");
        const std::string server_crt = read_text(TEST_KEYCERT_DIR "server.crt");
        const std::string server_key = read_text(TEST_KEYCERT_DIR "server.key");
        const std::string dh_pem = read_text(TEST_KEYCERT_DIR "dh.pem");
        const std::string tls_auth_key = read_text(TEST_KEYCERT_DIR "tls-auth.key");
        const std::string tls_crypt_v2_server_key = t.tls_crypt_v2_key_fn.empty()
                                                        ? read_text(TEST_KEYCERT_DIR "tls-crypt-v2-server.key")
                                                        : "";

        // client config
        ClientSSLAPI::Config::Ptr cc = create_client_ssl_config(frame, prng_cli, t.tls_version_mismatch);
        MySessionStats::Ptr cli_stats(new MySessionStats);

        auto cp = create_client_proto_context(std::move(cc), frame, prng_cli, cli_stats, time, t.tls_crypt_v2_key_fn, t.client_tls_auth_only, t.use_dynamic_tls_crypt, t.tls_crypt_v2_dir);
        if (t.use_tls_ekm)
            cp->dc.set_key_derivation(CryptoAlgs::KeyDerivation::TLS_EKM);
        if (t.mssfix_ctrl)
            cp->mssfix_ctrl = t.mssfix_ctrl;

        // server config
        MySessionStats::Ptr serv_stats(new MySessionStats);

        ServerSSLAPI::Config::Ptr sc(new ClientSSLAPI::Config());
        sc->set_mode(Mode(Mode::SERVER));
        sc->set_frame(frame);
        sc->set_rng(prng_serv);
        sc->load_ca(ca_crt, true);
        sc->load_cert(server_crt);
        sc->load_private_key(server_key);
        sc->load_dh(dh_pem);
        sc->set_tls_version_min(t.tls_version_mismatch ? TLSVersion::Type::V1_3 : TLS_VER_MIN);
#ifdef VERBOSE
        sc->set_debug_level(1);
#endif

        // server ProtoContext config
        using ServerProtoContext = ProtoContext;
        ServerProtoContext::ProtoConfig::Ptr sp(new ServerProtoContext::ProtoConfig);
        sp->ssl_factory = sc->new_factory();
        sp->dc.set_factory(new CryptoDCSelect<ServerCryptoAPI>(sp->ssl_factory->libctx(), frame, serv_stats, prng_serv));
        sp->tlsprf_factory.reset(new CryptoTLSPRFFactory<ServerCryptoAPI>());
        sp->frame = frame;
        sp->now = &time;
        sp->rng = prng_serv;
        sp->prng = prng_serv;
        sp->protocol = Protocol(Protocol::UDPv4);
        sp->layer = Layer(Layer::OSI_LAYER_3);
#ifdef PROTOv2
        sp->enable_op32 = true;
        sp->remote_peer_id = 101;
#endif
        sp->comp_ctx = CompressContext(COMP_METH, false);
        sp->dc.set_cipher(CryptoAlgs::lookup(PROTO_CIPHER));
        sp->dc.set_digest(CryptoAlgs::lookup(PROTO_DIGEST));
        if (t.use_tls_ekm)
            sp->dc.set_key_derivation(CryptoAlgs::KeyDerivation::TLS_EKM);
#ifdef USE_TLS_AUTH
        sp->tls_auth_factory.reset(new CryptoOvpnHMACFactory<ServerCryptoAPI>());
        sp->tls_auth_key.parse(tls_auth_key);
        sp->set_tls_auth_digest(CryptoAlgs::lookup(PROTO_DIGEST));
        sp->key_direction = 1;
#endif
#ifdef USE_TLS_CRYPT
        sp->tls_crypt_factory.reset(new CryptoTLSCryptFactory<ClientCryptoAPI>());
        sp->tls_crypt_key.parse(tls_auth_key);
        sp->set_tls_crypt_algs();
        cp->tls_crypt_ = ProtoContext::ProtoConfig::TLSCrypt::V1;
#endif
#ifdef USE_TLS_CRYPT_V2
        sp->tls_crypt_factory.reset(new CryptoTLSCryptFactory<ClientCryptoAPI>());

        if (t.tls_crypt_v2_key_fn.empty())
        {
            TLSCryptV2ServerKey tls_crypt_v2_key;
            tls_crypt_v2_key.parse(tls_crypt_v2_server_key);
            tls_crypt_v2_key.extract_key(sp->tls_crypt_key);
        }

        sp->set_tls_crypt_algs();
        sp->tls_crypt_metadata_factory.reset(new CryptoTLSCryptMetadataFactory());
        sp->tls_crypt_ = ProtoContext::ProtoConfig::TLSCrypt::V2;
        sp->tls_crypt_v2_serverkey_id = !t.tls_crypt_v2_key_fn.empty();
        sp->tls_crypt_v2_serverkey_dir = t.tls_crypt_v2_dir;

        if (t.use_dynamic_tls_crypt)
            sp->enable_dynamic_tls_crypt();

        if (t.use_tls_auth_with_tls_crypt_v2)
        {
            sp->tls_auth_factory.reset(new CryptoOvpnHMACFactory<ServerCryptoAPI>());
            sp->tls_auth_key.parse(tls_auth_key);
            sp->set_tls_auth_digest(CryptoAlgs::lookup(PROTO_DIGEST));
            sp->key_direction = 1;
        }
#endif
#ifdef HANDSHAKE_WINDOW
        sp->handshake_window = Time::Duration::seconds(HANDSHAKE_WINDOW);
#elif SITER > 1
        sp->handshake_window = Time::Duration::seconds(30);
#else
        sp->handshake_window = Time::Duration::seconds(17) + Time::Duration::binary_ms(512);
#endif
#ifdef BECOME_PRIMARY_SERVER
        sp->become_primary = Time::Duration::seconds(BECOME_PRIMARY_SERVER);
#else
        sp->become_primary = sp->handshake_window;
#endif
        sp->tls_timeout = Time::Duration::milliseconds(TLS_TIMEOUT_SERVER);
#ifdef SERVER_NO_RENEG
        sp->renegotiate = Time::Duration::infinite();
#else
        // NOTE: if we don't add sp->handshake_window, both client and server reneg-sec (RENEG)
        // will be equal and will therefore occasionally collide.  Such collisions can sometimes
        // produce this OpenSSL error:
        // OpenSSLContext::SSL::read_cleartext: BIO_read failed, cap=400 status=-1: error:140E0197:SSL routines:SSL_shutdown:shutdown while in init
        // The issue was introduced by this patch in OpenSSL:
        //   https://github.com/openssl/openssl/commit/64193c8218540499984cd63cda41f3cd491f3f59
        sp->renegotiate = Time::Duration::seconds(RENEG) + sp->handshake_window;
#endif
        sp->expire = sp->renegotiate + sp->renegotiate;
        sp->keepalive_ping = Time::Duration::seconds(5);
        sp->keepalive_timeout = Time::Duration::seconds(60);
        sp->keepalive_timeout_early = Time::Duration::seconds(10);

#ifdef VERBOSE
        std::cout << "SERVER OPTIONS: " << sp->options_string() << "\n";
        std::cout << "SERVER PEER INFO:\n";
        std::cout << sp->peer_info_string();
#endif

        TestProtoClient cli_proto(cp, cli_stats);
        TestProtoServer serv_proto(sp, serv_stats);

        for (int i = 0; i < SITER; ++i)
        {
#ifdef VERBOSE
            std::cout << "***** SITER " << i << "\n";
#endif
            cli_proto.reset();
            serv_proto.reset();

            NoisyWire client_to_server("Client -> Server", &time, rng_noncrypto, 8, 16, 32); // last value: 32
            NoisyWire server_to_client("Server -> Client", &time, rng_noncrypto, 8, 16, 32); // last value: 32

            int j = -1;
            try
            {
#if FEEDBACK
                // start feedback loop
                cli_proto.initial_app_send(message);
                serv_proto.start();
#else
                cli_proto.app_send_templ_init(message);
                serv_proto.app_send_templ_init(message);
#endif

                if (t.spoof_hard_reset_v3)
                {
                    // What an off-path attacker can put on the wire: a
                    // CONTROL_HARD_RESET_CLIENT_V3 opcode over garbage.
                    // packet_type() weighs the opcode and the key id and nothing
                    // else, so this reaches decapsulate() and asks a tls-auth
                    // server to make itself a tls-crypt-v2 one. Nothing in it
                    // authenticates, so the handshake below must still run its
                    // course.
                    BufferPtr bp = BufferAllocatedRc::Create(128, BufAllocFlags::GROW);
                    bp->push_back(ProtoContext::op_compose(ProtoContext::CONTROL_HARD_RESET_CLIENT_V3, 0));
                    for (size_t k = 0; k < 64; ++k)
                        bp->push_back(static_cast<unsigned char>(k));

                    const ProtoContext::PacketType pt = serv_proto.proto_context.packet_type(*bp);
                    if (!pt.is_control())
                        return 1;
                    serv_proto.proto_context.control_net_recv(pt, std::move(bp));
                }

                if (t.force_resend_wkc)
                {
                    // Pretend the server asked the client to resend the
                    // tls-crypt-v2 WKc on the first control packet, so the
                    // client's ClientHello is emitted as CONTROL_WKC_V1 with
                    // the WKc appended -- as is every retransmission of that
                    // packet, which the noisy wire below produces plenty of.
                    // The server has to take the WKc off each of them, so the
                    // handshake completes like any other.
                    cli_proto.proto_context.force_resend_wkc();
                }

                // message loop
                for (j = 0; j < ITER; ++j)
                {
                    client_to_server.xfer(cli_proto, serv_proto);
                    server_to_client.xfer(serv_proto, cli_proto);
                    time += time_step;
                }

                if (t.force_resend_wkc)
                {
                    // Frame control context above is Context(128, control_payload, ...).
                    // Even the WKc-bearing packet must stay within headroom +
                    // payload; without the reservation fix it overflows by
                    // ~wkc.size() bytes.
                    if (!cli_proto.verify_wkc_packets_fit(128 + t.control_payload))
                        return 1;
                    // when a wire cap is configured, every emitted control
                    // packet must stay within it after all wrappings
                    if (t.mssfix_ctrl && cli_proto.max_ctrl_pkt_size() > t.mssfix_ctrl)
                    {
                        std::cerr << "control packet exceeded mssfix_ctrl: "
                                  << cli_proto.max_ctrl_pkt_size()
                                  << " > " << t.mssfix_ctrl << '\n';
                        return 1;
                    }
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << "Exception[" << i << '/' << j << "]: " << e.what() << '\n';
                return 1;
            }
        }

        cli_proto.finalize();
        serv_proto.finalize();

        const size_t ab = cli_proto.app_bytes() + serv_proto.app_bytes();
        const size_t nb = cli_proto.net_bytes() + serv_proto.net_bytes();
        const size_t db = cli_proto.data_bytes() + serv_proto.data_bytes();

        std::cerr << "*** app bytes=" << ab
                  << " net_bytes=" << nb
                  << " data_bytes=" << db
                  << " prog=" << cli_proto.progress() << '/' << serv_proto.progress()
#if !FEEDBACK
                  << " CTRL=" << cli_proto.n_control_recv() << '/' << cli_proto.n_control_send() << '/' << serv_proto.n_control_recv() << '/' << serv_proto.n_control_send()
#endif
                  << " D=" << cli_proto.control_drought().raw() << '/' << cli_proto.data_drought().raw() << '/' << serv_proto.control_drought().raw() << '/' << serv_proto.data_drought().raw()
                  << " N=" << cli_proto.proto_context.negotiations() << '/' << serv_proto.proto_context.negotiations()
                  << " SH=" << cli_proto.proto_context.slowest_handshake().raw() << '/' << serv_proto.proto_context.slowest_handshake().raw()
                  << " HE=" << cli_stats->get_error_count(Error::HANDSHAKE_TIMEOUT) << '/' << serv_stats->get_error_count(Error::HANDSHAKE_TIMEOUT)
                  << '\n';

        if (t.use_dynamic_tls_crypt)
        {
            // The rekey is the first thing to use the derived key, and it is a control
            // channel handshake like any other: if the two ends derived different keys,
            // nothing either sends can authenticate and neither gets past its first one.
            if (cli_proto.proto_context.negotiations() < 2 || serv_proto.proto_context.negotiations() < 2)
            {
                std::cerr << "dynamic tls-crypt: no rekey completed\n";
                return 1;
            }
        }

#ifdef STATS
        std::cerr << "-------- CLIENT STATS --------\n";
        cli_stats->show_error_counts();
        std::cerr << "-------- SERVER STATS --------\n";
        serv_stats->show_error_counts();
#endif
#ifdef OPENVPN_MAX_DATALIMIT_BYTES
        std::cerr << "------------------------------\n";
        std::cerr << "MAX_DATALIMIT_BYTES=" << DataLimit::max_bytes() << "\n";
#endif
    }
    catch (const std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << '\n';
        return 1;
    }
    return 0;
}

int test_retry(const int n_retries, const struct proto_test &test_config)
{
    int ret = 1;
    for (int i = 0; i < n_retries; ++i)
    {
        ret = test(test_config);
        if (!ret)
            return 0;
        std::cout << "Retry " << (i + 1) << '/' << n_retries << '\n';
    }
    std::cout << "Failed\n";
    return ret;
}

class ProtoUnitTest : public testing::Test
{
    // Sets up the test fixture.
    void SetUp() override
    {
#ifdef USE_MBEDTLS
        mbedtls_debug_set_threshold(1);
#endif

        openvpn::Compress::set_log_level(0);

#ifdef PROTO_VERBOSE
        openvpn::ProtoContext::set_log_level(2);
#else
        openvpn::ProtoContext::set_log_level(0);
#endif
    }

    // Tears down the test fixture.
    void TearDown() override
    {
#ifdef USE_MBEDTLS
        mbedtls_debug_set_threshold(4);
#endif
        openvpn::Compress::set_log_level(openvpn::Compress::default_log_level);
        openvpn::ProtoContext::set_log_level(openvpn::ProtoContext::default_log_level);
    }
};

TEST_F(ProtoUnitTest, BaseSingleThreadTlsEkm)
{
    if (!openvpn::SSLLib::SSLAPI::support_key_material_export())
        GTEST_SKIP_("our mbed TLS implementation does not support TLS EKM");

    int ret = 0;

    ret = test_retry(N_RETRIES, {.use_tls_ekm = true});

    EXPECT_EQ(ret, 0);
}

TEST_F(ProtoUnitTest, BaseSingleThreadNoTlsEkm)
{
    int ret = 0;

    ret = test_retry(N_RETRIES, {.use_tls_ekm = false});

    EXPECT_EQ(ret, 0);
}

// Our mbedtls currently has a no-op set_tls_version_max() implementation,
// so we can't set mismatched client and server TLS versions.
// For now, just test this for OPENSSL which is full-featured.
#ifdef USE_OPENSSL
TEST_F(ProtoUnitTest, BaseSingleThreadTlsVersionMismatch)
{
    int ret = test({.tls_version_mismatch = true});
    EXPECT_NE(ret, 0);
}
#endif

#ifdef USE_TLS_CRYPT_V2
TEST_F(ProtoUnitTest, BaseSingleThreadTlsCryptV2WithEmbeddedServerkey)
{
    int ret = test_retry(N_RETRIES, {.tls_crypt_v2_key_fn = "tls-crypt-v2-client-with-serverkey.key"});
    EXPECT_EQ(ret, 0);
}

TEST_F(ProtoUnitTest, BaseSingleThreadTlsCryptV2WithMissingEmbeddedServerkey)
{
    int ret = test({.tls_crypt_v2_key_fn = "tls-crypt-v2-client-with-missing-serverkey.key"});
    EXPECT_NE(ret, 0);
}

TEST_F(ProtoUnitTest, BaseSingleThreadTlsCryptV2WithTlsAuthAlsoActive)
{
    int ret = test_retry(N_RETRIES, {.tls_crypt_v2_key_fn = "tls-crypt-v2-client-with-serverkey.key", .use_tls_auth_with_tls_crypt_v2 = true});
    EXPECT_EQ(ret, 0);
}

/**
 * @brief Mint a tls-crypt-v2 key pair the way the deployment tooling does.
 *
 * @param dir        Directory to write both keys to; created if absent.
 * @param client_fn  Basename for the client key file.
 * @param k_id       Server key ID to name the server key by.
 * @param metadata   Metadata to embed in the client key's WKc.
 */
static void write_generated_tls_crypt_v2_keys(const std::string &dir,
                                              const std::string &client_fn,
                                              const std::uint32_t k_id,
                                              const std::string &metadata)
{
    ServerRandomAPI::Ptr rng(new ServerRandomAPI());

    TLSCryptV2ServerKey server_key;
    server_key.generate(*rng);

    // <NN>/<KID8>.key, NN being the first two digits of the uppercase hex K_id:
    // the path unwrap_tls_crypt_wkc() composes from the K_id on the wire.
    const std::string k_id_hex = render_hex_number(k_id, true);
    const std::string key_dir = dir + k_id_hex.substr(0, 2);
    std::filesystem::create_directories(key_dir);
    write_string(key_dir + "/" + k_id_hex + ".key", server_key.render());

    TLSCryptFactory::Ptr tls_crypt_factory(new CryptoTLSCryptFactory<ServerCryptoAPI>());
    TLSCryptContext::Ptr tls_crypt_context = tls_crypt_factory->new_obj(nullptr,
                                                                        CryptoAlgs::lookup("SHA256"),
                                                                        CryptoAlgs::lookup("AES-256-CTR"));
    TLSCryptV2ClientKey client_key(tls_crypt_context);
    client_key.generate(*rng, server_key, metadata, 0x00, k_id);
    write_string(dir + client_fn, client_key.render());
}

// Everything the generator feeds (the SCT's client cohort, the KVM test's client) is only
// as good as its wire format, so mint a pair here and run the full handshake against it,
// through the same server-key-ID path the checked-in fixtures exercise. Fails if the tag
// stops covering the length prefix or K_id, if the CTR IV drifts from the tag, or if K_id
// lands anywhere but between the ciphertext and the trailing length.
TEST_F(ProtoUnitTest, BaseSingleThreadTlsCryptV2WithGeneratedKeys)
{
    const std::string dir = getTempDirPath("ovpn3-tls-crypt-v2-generated/");
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);

    write_generated_tls_crypt_v2_keys(dir, "client.key", 0x1A2B3C4D, "v=1,type=connector,tenant=SCT-01");

    int ret = test_retry(N_RETRIES, {.tls_crypt_v2_key_fn = "client.key", .tls_crypt_v2_dir = dir});
    EXPECT_EQ(ret, 0);

    std::filesystem::remove_all(dir);
}

// The same, against a server that also holds a tls-auth key: the mixed shape the SCT
// runs, where a tls-crypt-v2 client converts a session the server started in TLS_AUTH mode.
TEST_F(ProtoUnitTest, BaseSingleThreadTlsCryptV2WithGeneratedKeysAndTlsAuth)
{
    const std::string dir = getTempDirPath("ovpn3-tls-crypt-v2-generated-ta/");
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);

    write_generated_tls_crypt_v2_keys(dir, "client.key", 0x00FF0011, "v=1,type=connector,tenant=SCT-02");

    int ret = test_retry(N_RETRIES,
                         {.tls_crypt_v2_key_fn = "client.key",
                          .tls_crypt_v2_dir = dir,
                          .use_tls_auth_with_tls_crypt_v2 = true});
    EXPECT_EQ(ret, 0);

    std::filesystem::remove_all(dir);
}

// A server holding both keys becomes a tls-crypt-v2 one on the say-so of an opcode, which
// costs an off-path attacker one forged datagram. Here the client is a plain tls-auth one,
// so the session must stay in TLS_AUTH mode however loudly the forgery asks otherwise:
// before the wrap mode was taken back, the spoofed packet left the server unable to
// authenticate anything the real client went on to send.
TEST_F(ProtoUnitTest, TlsAuthSessionSurvivesSpoofedTlsCryptV2Opcode)
{
    int ret = test_retry(N_RETRIES,
                         {.tls_crypt_v2_key_fn = "tls-crypt-v2-client-with-serverkey.key",
                          .use_tls_auth_with_tls_crypt_v2 = true,
                          .client_tls_auth_only = true,
                          .spoof_hard_reset_v3 = true});
    EXPECT_EQ(ret, 0);
}

// Dynamic tls-crypt rekeys the control channel with a key each end derives from the TLS
// session -- so it needs keying material export, which our mbed TLS does not have -- and
// mixes its own tls-crypt key into. A tls-crypt-v2 server's ProtoConfig holds
// the server key it unwraps WKc's with, not the Kc inside them, so mixing that in derived a
// key the client could not match and the rekey never completed. Both server key modes are
// covered: with a server key in the config the server mixed in the wrong key, and with
// serverkey_id it had none to mix in and skipped the step the client had taken.
TEST_F(ProtoUnitTest, DynamicTlsCryptRekeysTlsCryptV2WithServerkeyInConfig)
{
    if (!openvpn::SSLLib::SSLAPI::support_key_material_export())
        GTEST_SKIP_("our mbed TLS implementation does not support TLS EKM");

    int ret = test_retry(N_RETRIES, {.use_dynamic_tls_crypt = true});
    EXPECT_EQ(ret, 0);
}

TEST_F(ProtoUnitTest, DynamicTlsCryptRekeysTlsCryptV2WithServerkeyId)
{
    if (!openvpn::SSLLib::SSLAPI::support_key_material_export())
        GTEST_SKIP_("our mbed TLS implementation does not support TLS EKM");

    int ret = test_retry(N_RETRIES, {.tls_crypt_v2_key_fn = "tls-crypt-v2-client-with-serverkey.key", .use_dynamic_tls_crypt = true});
    EXPECT_EQ(ret, 0);
}

// The two above run tls-crypt-v2-only servers, where the config the key is picked from and
// the mode the session is in cannot disagree. A server holding a tls-auth key as well --
// what PG deploys -- is the case that can: reset_tls_wrap_mode() prefers TLS_AUTH, so such a
// session starts as tls-auth and only decapsulate() converts it once the client's WKc
// arrives. Picking the key to mix from the config then had the server mix tls_auth_key while
// its tls-crypt-v2 client mixed Kc; the handshake came up fine and the session died at the
// first rekey, hours in. Both server key modes, as above.
TEST_F(ProtoUnitTest, DynamicTlsCryptRekeysTlsCryptV2OnTlsAuthServerWithServerkeyInConfig)
{
    if (!openvpn::SSLLib::SSLAPI::support_key_material_export())
        GTEST_SKIP_("our mbed TLS implementation does not support TLS EKM");

    int ret = test_retry(N_RETRIES,
                         {.use_tls_auth_with_tls_crypt_v2 = true,
                          .use_dynamic_tls_crypt = true});
    EXPECT_EQ(ret, 0);
}

TEST_F(ProtoUnitTest, DynamicTlsCryptRekeysTlsCryptV2OnTlsAuthServerWithServerkeyId)
{
    if (!openvpn::SSLLib::SSLAPI::support_key_material_export())
        GTEST_SKIP_("our mbed TLS implementation does not support TLS EKM");

    int ret = test_retry(N_RETRIES,
                         {.tls_crypt_v2_key_fn = "tls-crypt-v2-client-with-serverkey.key",
                          .use_tls_auth_with_tls_crypt_v2 = true,
                          .use_dynamic_tls_crypt = true});
    EXPECT_EQ(ret, 0);
}

// Regression test: when the tls-crypt-v2 WKc is appended to the first
// ciphertext-bearing control packet (EARLY_NEG_FLAG_RESEND_WKC -> the client
// emits CONTROL_WKC_V1), the SSL ciphertext placed into that packet must be
// trimmed to leave room for the WKc, so the assembled datagram still fits the
// control-channel frame.  Without the reservation fix the packet overflows the
// frame by ~wkc.size() bytes and gets dropped, stalling the handshake.
TEST_F(ProtoUnitTest, TlsCryptV2WkcRidesFirstControlPacket)
{
    int ret = test_retry(N_RETRIES, {.tls_crypt_v2_key_fn = "tls-crypt-v2-client-with-serverkey.key", .force_resend_wkc = true});
    EXPECT_EQ(ret, 0);
}

// Degenerate variant of the above: the control-channel payload is smaller
// than the WKc itself (mssfix-ctrl may go as low as 256 while a WKc can be
// up to 1024 bytes).  The WKc reservation must clamp instead of wrapping the
// unsigned subtraction -- a wrap disables the trim entirely and the WKc
// packet overflows the frame again.  The WKc of the test key is 328 bytes;
// 278 puts the payload just below it.
TEST_F(ProtoUnitTest, TlsCryptV2WkcLargerThanControlPayload)
{
    int ret = test_retry(N_RETRIES, {.tls_crypt_v2_key_fn = "tls-crypt-v2-client-with-serverkey.key", .force_resend_wkc = true, .control_payload = 278});
    EXPECT_EQ(ret, 0);
}

// Every control packet, including the WKc-bearing one, must stay within the
// configured mssfix_ctrl limit after all tls wrappings have been applied.
// 420 leaves just enough room for the unsplittable WKc packet (~406 bytes
// worst case: tls-crypt header + full ACK block + the 328 byte WKc).
TEST_F(ProtoUnitTest, TlsCryptV2ControlPacketCapHonored)
{
    int ret = test_retry(N_RETRIES, {.tls_crypt_v2_key_fn = "tls-crypt-v2-client-with-serverkey.key", .force_resend_wkc = true, .mssfix_ctrl = 420});
    EXPECT_EQ(ret, 0);
}

// Security regression test: unwrap_tls_crypt_wkc() reads the 16-bit WKc length
// (wkc_len) from the last two bytes of the received packet. For CONTROL_WKC_V1
// packets that value is fully attacker-controlled and, before the bounds-check
// fix, was fed straight into unsigned pointer arithmetic
// (wkc_raw = orig_data + orig_size - wkc_len). A wkc_len larger than the packet
// underflowed the size_t computation into a wild pointer and a bogus/oversized
// ciphertext length, producing an out-of-bounds read during decryption -- a
// pre-authentication remote crash (DoS). The unwrap must instead reject the
// packet with Error::CC_ERROR without dereferencing out of bounds.
//
// Builds a minimal ProtoConfig / tls-crypt server context (no full handshake
// needed) since the malformed length is rejected before any key material is
// touched.
class TlsCryptV2WkcUnwrapTest : public testing::Test
{
  protected:
    ProtoContext::ProtoConfig::Ptr pcfg;
    TLSCryptInstance::Ptr tls_crypt_server;

    void SetUp() override
    {
        pcfg.reset(new ProtoContext::ProtoConfig());
        pcfg->tls_crypt_factory.reset(new CryptoTLSCryptFactory<ClientCryptoAPI>());
        pcfg->set_tls_crypt_algs();
        // Fully initialize the server context (single server key, no key ID) so
        // that a malformed packet which slips past the length validation reaches
        // the real decrypt() read -- that is the read that goes out of bounds
        // without the fix (a segfault / ASan SEGV), and which the fix must avoid
        // by rejecting the packet up front.
        pcfg->tls_crypt_key.parse(read_text(TEST_KEYCERT_DIR "tls-auth.key"));
        tls_crypt_server = pcfg->tls_crypt_context->new_obj_recv();
        tls_crypt_server->init(nullptr,
                               pcfg->tls_crypt_key.slice(OpenVPNStaticKey::HMAC),
                               pcfg->tls_crypt_key.slice(OpenVPNStaticKey::CIPHER));
    }

    // Build a CONTROL_WKC_V1 packet of the given size with the trailing 16-bit
    // WKc length field set to wkc_len (host order). Contents are otherwise
    // arbitrary -- the unwrap should bail on the length alone.
    BufferAllocated make_wkc_v1_packet(size_t size, uint16_t wkc_len)
    {
        BufferAllocated buf(size, BufAllocFlags::CONSTRUCT_ZERO);
        buf.set_size(size);
        // op byte = op_compose(CONTROL_WKC_V1, key_id=0). CONTROL_WKC_V1 (11)
        // and op_compose() are protected members of ProtoContext, so encode it
        // directly here: (opcode << OPCODE_SHIFT[=3]) | key_id. Any opcode other
        // than CONTROL_HARD_RESET_CLIENT_V3 (10) selects the attacker-controlled
        // wkc_len branch being exercised.
        buf.data()[0] = static_cast<unsigned char>(11u << 3);
        const uint16_t net_wkc_len = htons(wkc_len);
        std::memcpy(buf.data() + size - sizeof(net_wkc_len), &net_wkc_len, sizeof(net_wkc_len));
        return buf;
    }

    //! Smallest tls-crypt frame a WKc can follow, from the code under test
    size_t frame_size() const
    {
        return ProtoContext::KeyContext::tls_crypt_frame_size(*pcfg);
    }

    //! Smallest WKc strip_resent_wkc() accepts, from the code under test: everything a
    //! WKc carries besides the key, plus the key it wraps
    uint16_t min_wkc_len() const
    {
        return static_cast<uint16_t>(ProtoContext::KeyContext::wkc_overhead(*pcfg)
                                     + OpenVPNStaticKey::KEY_SIZE);
    }
};

// wkc_len far larger than the packet: pre-fix this underflowed wkc_raw into a
// wild pointer read.
TEST_F(TlsCryptV2WkcUnwrapTest, RejectsWkcLenLargerThanPacket)
{
    BufferAllocated buf = make_wkc_v1_packet(200, 60000);
    ProtoContext::KeyContext::UnwrappedWkc unwrapped;
    EXPECT_EQ(ProtoContext::KeyContext::unwrap_tls_crypt_wkc(buf, *pcfg, *tls_crypt_server, unwrapped),
              Error::CC_ERROR);
    EXPECT_FALSE(unwrapped.client_key.defined());
}

// wkc_len smaller than the auth tag: pre-fix the decrypt ciphertext length
// (wkc_raw_size - hmac_size) underflowed to a huge oversized read.
TEST_F(TlsCryptV2WkcUnwrapTest, RejectsWkcLenSmallerThanAuthTag)
{
    BufferAllocated buf = make_wkc_v1_packet(200, 4);
    ProtoContext::KeyContext::UnwrappedWkc unwrapped;
    EXPECT_EQ(ProtoContext::KeyContext::unwrap_tls_crypt_wkc(buf, *pcfg, *tls_crypt_server, unwrapped),
              Error::CC_ERROR);
    EXPECT_FALSE(unwrapped.client_key.defined());
}

// strip_resent_wkc() takes the WKc off a retransmitted CONTROL_WKC_V1 without
// unwrapping it again.  It reads the same attacker-controlled trailing length
// field as the unwrap above and needs the same guards, so exercise them here
// too: a length that survives validation is used to trim the packet, and one
// that doesn't must leave the packet alone and drop it.

// A WKc's K_id names a file and the K_id is whatever the packet says it is, so a client whose
// key we never had -- or a forgery -- points at a file that is not there. read_text() throws
// open_file_error for it, which is not a BufferException, so it sailed past the only catch in
// decapsulate() and out of the psid cookie layer's intercept(), from a path reached before
// anything about the packet has been authenticated.
TEST_F(TlsCryptV2WkcUnwrapTest, UnknownServerKeyIdIsAnErrorAndNotAnException)
{
    pcfg->tls_crypt_v2_serverkey_id = true;
    pcfg->tls_crypt_v2_serverkey_dir = TEST_KEYCERT_DIR;

    // room for a WKc behind a tls-crypt frame; the buffer is zero filled, so the K_id it
    // carries is 0 and names <dir>/00/00000000.key
    const uint16_t wkc_len = min_wkc_len();
    BufferAllocated buf = make_wkc_v1_packet(frame_size() + wkc_len, wkc_len);

    ProtoContext::KeyContext::UnwrappedWkc unwrapped;
    Error::Type ret = Error::SUCCESS;
    EXPECT_NO_THROW(
        ret = ProtoContext::KeyContext::unwrap_tls_crypt_wkc(buf, *pcfg, *tls_crypt_server, unwrapped));
    EXPECT_EQ(ret, Error::DECRYPT_ERROR);
    EXPECT_FALSE(unwrapped.client_key.defined());
}

TEST_F(TlsCryptV2WkcUnwrapTest, StripsResentWkc)
{
    BufferAllocated buf = make_wkc_v1_packet(frame_size() + 300, 300);
    EXPECT_TRUE(ProtoContext::KeyContext::strip_resent_wkc(buf, *pcfg));
    // what is left is the frame the tls-crypt auth tag actually covers
    EXPECT_EQ(buf.size(), frame_size());
}

TEST_F(TlsCryptV2WkcUnwrapTest, StripRejectsWkcLenLargerThanPacket)
{
    BufferAllocated buf = make_wkc_v1_packet(400, 60000);
    EXPECT_FALSE(ProtoContext::KeyContext::strip_resent_wkc(buf, *pcfg));
    EXPECT_EQ(buf.size(), 400u);
}

// a WKc too small to even hold the client key it is supposed to wrap
TEST_F(TlsCryptV2WkcUnwrapTest, StripRejectsWkcLenSmallerThanClientKey)
{
    BufferAllocated buf = make_wkc_v1_packet(400, min_wkc_len() - 1);
    EXPECT_FALSE(ProtoContext::KeyContext::strip_resent_wkc(buf, *pcfg));
    EXPECT_EQ(buf.size(), 400u);
}

// one byte more than the packet can spare: trimming it would leave less than a
// tls-crypt frame in front of the WKc
TEST_F(TlsCryptV2WkcUnwrapTest, StripRejectsWkcLeavingNoTlsCryptFrame)
{
    BufferAllocated buf = make_wkc_v1_packet(400, static_cast<uint16_t>(400 - frame_size() + 1));
    EXPECT_FALSE(ProtoContext::KeyContext::strip_resent_wkc(buf, *pcfg));
    EXPECT_EQ(buf.size(), 400u);
}

// too short to hold a frame plus the trailing length field at all; the length
// read itself must not happen
TEST_F(TlsCryptV2WkcUnwrapTest, StripRejectsPacketShorterThanAFrame)
{
    BufferAllocated buf = make_wkc_v1_packet(frame_size() + 1, 300);
    EXPECT_FALSE(ProtoContext::KeyContext::strip_resent_wkc(buf, *pcfg));
}

// with server key IDs in use -- how PG deploys tls-crypt-v2 -- the WKc carries a
// 4 byte K_id as well, so the minimum grows by that much
TEST_F(TlsCryptV2WkcUnwrapTest, StripAccountsForServerKeyId)
{
    pcfg->tls_crypt_v2_serverkey_id = true;
    // the one place the number is spelled out rather than asked for: length field, a
    // SHA-256 tag, K_id and the client key
    ASSERT_EQ(min_wkc_len(), sizeof(uint16_t) + 32 + sizeof(uint32_t) + OpenVPNStaticKey::KEY_SIZE);

    BufferAllocated too_small = make_wkc_v1_packet(400, min_wkc_len() - 1);
    EXPECT_FALSE(ProtoContext::KeyContext::strip_resent_wkc(too_small, *pcfg));

    BufferAllocated ok = make_wkc_v1_packet(400, min_wkc_len());
    EXPECT_TRUE(ProtoContext::KeyContext::strip_resent_wkc(ok, *pcfg));
    EXPECT_EQ(ok.size(), 400u - min_wkc_len());
}
#endif

TEST_F(ProtoUnitTest, BaseMultipleThread)
{
    unsigned int num_threads = std::thread::hardware_concurrency();
#if defined(PROTO_N_THREADS) && PROTO_N_THREADS >= 1
    num_threads = PROTO_N_THREADS;
#endif

    std::vector<std::thread> running_threads{};
    std::vector<int> results(num_threads, -777);

    for (unsigned int i = 0; i < num_threads; ++i)
    {
        running_threads.emplace_back([i, &results]()
                                     {
            /* Use ekm on odd threads */
            const bool use_ekm = openvpn::SSLLib::SSLAPI::support_key_material_export() && (i % 2 == 0);
            results[i] = test_retry(N_RETRIES, { .use_tls_ekm = use_ekm }); });
    }
    for (unsigned int i = 0; i < num_threads; ++i)
    {
        running_threads[i].join();
    }


    // expect 1 for all threads
    const std::vector<int> expected_results(num_threads, 0);

    EXPECT_THAT(expected_results, ::testing::ContainerEq(results));
}

TEST(Proto, IvCiphersAead)
{
    CryptoAlgs::allow_default_dc_algs<SSLLib::CryptoAPI>(nullptr, true, false);

    auto protoConf = openvpn::ProtoContext::ProtoConfig();

    auto infostring = protoConf.peer_info_string(false);

    auto ivciphers = infostring.substr(infostring.find("IV_CIPHERS="));
    ivciphers = ivciphers.substr(0, ivciphers.find("\n"));


    std::string expectedstr{"IV_CIPHERS=AES-128-GCM:AES-192-GCM:AES-256-GCM"};
    if (SSLLib::CryptoAPI::CipherContextAEAD::is_supported(nullptr, openvpn::CryptoAlgs::CHACHA20_POLY1305))
        expectedstr += ":CHACHA20-POLY1305";

    EXPECT_EQ(ivciphers, expectedstr);
}

TEST(Proto, IvCiphersNonPreferred)
{
    CryptoAlgs::allow_default_dc_algs<SSLLib::CryptoAPI>(nullptr, false, false);

    auto protoConf = openvpn::ProtoContext::ProtoConfig();

    auto infostring = protoConf.peer_info_string(true);

    auto ivciphers = infostring.substr(infostring.find("IV_CIPHERS="));
    ivciphers = ivciphers.substr(0, ivciphers.find("\n"));


    std::string expectedstr{"IV_CIPHERS=AES-128-CBC:AES-192-CBC:AES-256-CBC:AES-128-GCM:AES-192-GCM:AES-256-GCM"};
    if (SSLLib::CryptoAPI::CipherContextAEAD::is_supported(nullptr, openvpn::CryptoAlgs::CHACHA20_POLY1305))
        expectedstr += ":CHACHA20-POLY1305";

    EXPECT_EQ(ivciphers, expectedstr);
}

TEST(Proto, IvCiphersLegacy)
{

    /* Need to a whole lot of things to enable legacy provider/OpenSSL context */
    SSLLib::SSLAPI::Config::Ptr config = new SSLLib::SSLAPI::Config;
    EXPECT_TRUE(config);

    StrongRandomAPI::Ptr rng(new SSLLib::RandomAPI());
    config->set_rng(rng);

    config->set_mode(Mode(Mode::CLIENT));
    config->set_flags(SSLConfigAPI::LF_ALLOW_CLIENT_CERT_NOT_REQUIRED);
    config->set_local_cert_enabled(false);
    config->enable_legacy_algorithms(true);

    auto factory_client = config->new_factory();
    EXPECT_TRUE(factory_client);

    auto client = factory_client->ssl();
    auto libctx = factory_client->libctx();


    CryptoAlgs::allow_default_dc_algs<SSLLib::CryptoAPI>(libctx, false, true);

    auto protoConf = openvpn::ProtoContext::ProtoConfig();

    auto infostring = protoConf.peer_info_string(false);

    auto ivciphers = infostring.substr(infostring.find("IV_CIPHERS="));
    ivciphers = ivciphers.substr(0, ivciphers.find("\n"));



    std::string expectedstr{"IV_CIPHERS=none:AES-128-CBC:AES-192-CBC:AES-256-CBC:DES-CBC:DES-EDE3-CBC"};

    if (SSLLib::CryptoAPI::CipherContext::is_supported(libctx, openvpn::CryptoAlgs::BF_CBC))
        expectedstr += ":BF-CBC";

    expectedstr += ":AES-128-GCM:AES-192-GCM:AES-256-GCM";

    if (SSLLib::CryptoAPI::CipherContextAEAD::is_supported(nullptr, openvpn::CryptoAlgs::CHACHA20_POLY1305))
        expectedstr += ":CHACHA20-POLY1305";

    EXPECT_EQ(ivciphers, expectedstr);
}

TEST(Proto, ControlmessageInvalidchar)
{
    std::string valid_auth_fail{"AUTH_FAILED: go away"};
    std::string valid_auth_fail_newline_end{"AUTH_FAILED: go away\n"};
    std::string invalid_auth_fail{"AUTH_FAILED: go\n away\n"};
    std::string lot_of_whitespace{"AUTH_FAILED: a lot of white space\n\n\r\n\r\n\r\n"};
    std::string only_whitespace{"\n\n\r\n\r\n\r\n"};
    std::string empty{""};

    BufferAllocated valid_auth_fail_buf{reinterpret_cast<const unsigned char *>(valid_auth_fail.c_str()), valid_auth_fail.size(), BufAllocFlags::GROW};
    BufferAllocated valid_auth_fail_newline_end_buf{reinterpret_cast<const unsigned char *>(valid_auth_fail_newline_end.c_str()), valid_auth_fail_newline_end.size(), BufAllocFlags::GROW};
    BufferAllocated invalid_auth_fail_buf{reinterpret_cast<const unsigned char *>(invalid_auth_fail.c_str()), invalid_auth_fail.size(), BufAllocFlags::GROW};
    BufferAllocated lot_of_whitespace_buf{reinterpret_cast<const unsigned char *>(lot_of_whitespace.c_str()), lot_of_whitespace.size(), BufAllocFlags::GROW};
    BufferAllocated only_whitespace_buf{reinterpret_cast<const unsigned char *>(only_whitespace.c_str()), only_whitespace.size(), BufAllocFlags::GROW};
    BufferAllocated empty_buf{reinterpret_cast<const unsigned char *>(empty.c_str()), empty.size(), BufAllocFlags::GROW};

    auto msg = ProtoContext::read_control_string<std::string>(valid_auth_fail_buf);
    EXPECT_EQ(msg, valid_auth_fail);
    EXPECT_TRUE(Unicode::is_valid_utf8(msg, Unicode::UTF8_NO_CTRL));

    auto msg2 = ProtoContext::read_control_string<std::string>(valid_auth_fail_newline_end_buf);
    EXPECT_EQ(msg2, valid_auth_fail);
    EXPECT_TRUE(Unicode::is_valid_utf8(msg2, Unicode::UTF8_NO_CTRL));

    auto msg3 = ProtoContext::read_control_string<std::string>(invalid_auth_fail_buf);
    EXPECT_EQ(msg3, "AUTH_FAILED: go\n away");
    EXPECT_FALSE(Unicode::is_valid_utf8(msg3, Unicode::UTF8_NO_CTRL));

    auto msg4 = ProtoContext::read_control_string<std::string>(lot_of_whitespace_buf);
    EXPECT_EQ(msg4, "AUTH_FAILED: a lot of white space");
    EXPECT_TRUE(Unicode::is_valid_utf8(msg4, Unicode::UTF8_NO_CTRL));

    auto msg5 = ProtoContext::read_control_string<std::string>(only_whitespace_buf);
    EXPECT_EQ(msg5, "");
    EXPECT_TRUE(Unicode::is_valid_utf8(msg5, Unicode::UTF8_NO_CTRL));

    auto msg6 = ProtoContext::read_control_string<std::string>(empty_buf);
    EXPECT_EQ(msg6, "");
    EXPECT_TRUE(Unicode::is_valid_utf8(msg5, Unicode::UTF8_NO_CTRL));
}

class MockCallback : public openvpn::ClientProto::NotifyCallback
{
    void client_proto_terminate()
    {
    }
};

class EventQueueVector : public openvpn::ClientEvent::Queue
{
  public:
    void add_event(openvpn::ClientEvent::Base::Ptr event) override
    {
        events.push_back(event);
    }

    std::vector<openvpn::ClientEvent::Base::Ptr> events;
};

TEST(Proto, ClientProtoCheckCcMsg)
{
    asio::io_context io_context;
    ClientRandomAPI::Ptr rng_cli(new ClientRandomAPI());
    Frame::Ptr frame(new Frame(Frame::Context(128, 378, 128, 0, 16, BufAllocFlags::NO_FLAGS)));
    MySessionStats::Ptr cli_stats(new MySessionStats);
    Time time;

    openvpn::ClientEvent::Queue::Ptr eqv_ptr = new EventQueueVector{};
    /* keep a reference to the right class to avoid repeated casted */
    EventQueueVector *eqv = dynamic_cast<EventQueueVector *>(eqv_ptr.get());
    /* check that the cast worked */
    ASSERT_TRUE(eqv);

    MockCallback mockCB;
    openvpn::ClientProto::Session::Config clisessconf{};
    clisessconf.proto_context_config = create_client_proto_context(create_client_ssl_config(frame, rng_cli),
                                                                   frame,
                                                                   rng_cli,
                                                                   std::move(cli_stats),
                                                                   time);
    clisessconf.cli_events = std::move(eqv_ptr);
    openvpn::ClientProto::Session::Ptr clisession = new ClientProto::Session{io_context, clisessconf, &mockCB};

    clisession->validate_and_post_cc_msg("valid message");


    EXPECT_TRUE(eqv->events.empty());

    clisession->validate_and_post_cc_msg("invalid\nmessage");
    EXPECT_EQ(eqv->events.size(), 1);
    auto ev = eqv->events.back();
    auto uf = dynamic_cast<openvpn::ClientEvent::UnsupportedFeature *>(ev.get());
    /* check that the cast worked */
    ASSERT_TRUE(uf);
    EXPECT_EQ(uf->name, "Invalid chars in control message");
    EXPECT_EQ(uf->reason, "Control channel message with invalid characters not allowed to be send with post_cc_msg");
}
