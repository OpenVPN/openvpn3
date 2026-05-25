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

#ifndef OPENVPN_TRANSPORT_GREMLIN_H
#define OPENVPN_TRANSPORT_GREMLIN_H

#include <memory>
#include <deque>
#include <vector>
#include <utility>
#include <sstream>

#include <openvpn/common/rc.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/number.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/time/asiotimer.hpp>
#include <openvpn/random/mtrandapi.hpp>

namespace openvpn::Gremlin {

OPENVPN_EXCEPTION(gremlin_error);

struct DelayedQueue : public RC<thread_unsafe_refcount>
{
  public:
    typedef RCPtr<DelayedQueue> Ptr;

    DelayedQueue(openvpn_io::io_context &io_context,
                 const unsigned int delay_ms)
        : dur(Time::Duration::milliseconds(delay_ms)),
          next_event(io_context)
    {
    }

    template <class F>
    void queue(F &&func_arg)
    {
        const bool empty = events.empty();
        events.emplace_back(new Event<F>(Time::now() + dur, std::move(func_arg)));
        if (empty)
            set_timer();
    }

    size_t size() const
    {
        return events.size();
    }

    void stop()
    {
        next_event.cancel();
    }

  private:
    struct EventBase
    {
        virtual void call() = 0;
        virtual const Time &fire_time() = 0;
        virtual ~EventBase() = default;
    };

    template <class F>
    struct Event : public EventBase
    {
      public:
        Event(Time fire_arg, F &&func_arg)
            : fire(fire_arg),
              func(std::move(func_arg))
        {
        }

        void call() override
        {
            func();
        }

        const Time &fire_time() override
        {
            return fire;
        }

      private:
        Time fire;
        F func;
    };

    void set_timer()
    {
        if (events.empty())
            return;
        EventBase &ev = *events.front();
        next_event.expires_at(ev.fire_time());
        next_event.async_wait([self = Ptr(this)](const openvpn_io::error_code &error)
                              {
				if (!error)
				  {
				    EventBase& ev = *self->events.front();
				    ev.call();
				    self->events.pop_front();
				    self->set_timer();
				  } });
    }

    Time::Duration dur;
    AsioTimer next_event;
    std::deque<std::unique_ptr<EventBase>> events;
};

class Config : public RC<thread_unsafe_refcount>
{
  public:
    typedef RCPtr<Config> Ptr;

    Config(const std::string &config_str)
    {
        const std::vector<std::string> parms = string::split(config_str, ',');
        if (parms.size() < 4)
            throw gremlin_error("need at least 4 comma-separated values for send_delay_ms, recv_delay_ms, send_drop_prob, recv_drop_prob[, send_corrupt_prob]");
        if (!parse_number(string::trim_copy(parms[0]), send_delay_ms))
            throw gremlin_error("send_delay_ms");
        if (!parse_number(string::trim_copy(parms[1]), recv_delay_ms))
            throw gremlin_error("recv_delay_ms");
        if (!parse_number(string::trim_copy(parms[2]), send_drop_probability))
            throw gremlin_error("send_drop_probability");
        if (!parse_number(string::trim_copy(parms[3]), recv_drop_probability))
            throw gremlin_error("recv_drop_probability");
        if (parms.size() >= 5 && !parse_number(string::trim_copy(parms[4]), send_corrupt_probability))
            throw gremlin_error("send_corrupt_probability");
    }

    std::string to_string() const
    {
        std::ostringstream os;
        os << '[' << send_delay_ms << ',' << recv_delay_ms << ',' << send_drop_probability << ',' << recv_drop_probability << ',' << send_corrupt_probability << ']';
        return os.str();
    }

    unsigned int send_delay_ms = 0;
    unsigned int recv_delay_ms = 0;
    unsigned int send_drop_probability = 0;
    unsigned int recv_drop_probability = 0;
    // 1-in-N probability of flipping one bit in an outgoing data-channel
    // packet (post-encryption). 0 disables corruption. Used to exercise
    // server-side decrypt-fail-limit enforcement.
    unsigned int send_corrupt_probability = 0;
};

class SendRecvQueue
{
  public:
    SendRecvQueue(openvpn_io::io_context &io_context,
                  const Config::Ptr &conf_arg,
                  const bool tcp_arg)
        : conf(conf_arg),
          send(new DelayedQueue(io_context, conf->send_delay_ms)),
          recv(new DelayedQueue(io_context, conf->recv_delay_ms)),
          tcp(tcp_arg)
    {
    }

    template <class F>
    void send_queue(F &&func_arg)
    {
        if (tcp || flip(conf->send_drop_probability))
            send->queue(std::move(func_arg));
    }

    template <class F>
    void recv_queue(F &&func_arg)
    {
        if (tcp || flip(conf->recv_drop_probability))
            recv->queue(std::move(func_arg));
    }

    /**
      @brief Maybe flip one bit in an outgoing data-channel packet so the
             peer's AEAD/HMAC authentication fails.

      Non-data packets are left alone so the TLS handshake can complete.
      Corruption fires with 1-in-N probability where N is the
      send_corrupt_probability configured on the gremlin Config; if that
      value is 0, the function is a no-op.

      @param buf            Buffer to mutate in place.
      @param opcode_offset  Byte index of the OpenVPN opcode in buf
                            (0 for UDP, 2 for TCP because of the 2-byte
                            length prefix prepended by PacketStream).
    */
    void maybe_corrupt_data(Buffer &buf, const size_t opcode_offset)
    {
        if (!conf->send_corrupt_probability || buf.size() <= opcode_offset + 1)
            return;
        const unsigned int opcode = static_cast<unsigned int>(buf.c_data()[opcode_offset]) >> 3;
        constexpr unsigned int DATA_V1 = 6;
        constexpr unsigned int DATA_V2 = 9;
        if (opcode != DATA_V1 && opcode != DATA_V2)
            return;
        if (ri.randrange(conf->send_corrupt_probability) != 0)
            return;
        const size_t payload_start = opcode_offset + 1;
        const size_t idx = payload_start + ri.randrange(buf.size() - payload_start);
        buf.data()[idx] ^= 1u << ri.randrange(8);
    }

    size_t send_size() const
    {
        return send->size();
    }

    size_t recv_size() const
    {
        return recv->size();
    }

    void stop()
    {
        send->stop();
        recv->stop();
    }

  private:
    bool flip(const unsigned int prob)
    {
        if (prob)
            return ri.randrange(prob) != 0;
        else
            return true;
    }

    Config::Ptr conf;
    MTRand ri;
    DelayedQueue::Ptr send;
    DelayedQueue::Ptr recv;
    bool tcp;
};
} // namespace openvpn::Gremlin

#endif
