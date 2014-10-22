//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// OpenVPN protocol implementation for client-instance object on server

#ifndef OPENVPN_SERVER_SERVPROTO_H
#define OPENVPN_SERVER_SERVPROTO_H

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/unicode.hpp>
#include <openvpn/common/abort.hpp>
#include <openvpn/common/link.hpp>
#include <openvpn/time/asiotimer.hpp>
#include <openvpn/time/coarsetime.hpp>
#include <openvpn/ssl/proto.hpp>
#include <openvpn/server/manage.hpp>
#include <openvpn/transport/server/transbase.hpp>

#ifdef OPENVPN_DEBUG_SERVPROTO
#define OPENVPN_LOG_SERVPROTO(x) OPENVPN_LOG(x)
#else
#define OPENVPN_LOG_SERVPROTO(x)
#endif

namespace openvpn {

  class ServerProto
  {
    typedef ProtoContext Base;
    typedef Link<TransportClientInstanceSend, TransportClientInstanceRecv> TransportLink;

  public:
    class Session;

    class Factory : public TransportClientInstanceFactory
    {
    public:
      typedef boost::intrusive_ptr<Factory> Ptr;
      typedef Base::Config ProtoConfig;

      Factory(boost::asio::io_service& io_service_arg,
	      const Base::Config& c)
	: io_service(io_service_arg)
      {
	if (c.tls_auth_enabled())
	  preval.reset(new Base::TLSAuthPreValidate(c));
      }

      virtual TransportClientInstanceRecv::Ptr new_client_instance();

      virtual bool validate_initial_packet(const Buffer& net_buf)
      {
	if (preval)
	  {
	    const bool ret = preval->validate(net_buf);
	    if (!ret)
	      stats->error(Error::TLS_AUTH_FAIL);
	    return ret;
	  }
	else
	  return true;
      }

      boost::asio::io_service& io_service;
      ProtoConfig::Ptr proto_context_config;
      SessionStats::Ptr stats;

    private:
      Base::TLSAuthPreValidate::Ptr preval;
    };

    // This is the main server-side client instance object
    class Session : Base,                  // OpenVPN protocol implementation
		    public TransportLink   // Transport layer
    {
      friend class Factory; // calls constructor

      typedef Base::PacketType PacketType;

      using Base::now;
      using Base::stat;

    public:
      typedef boost::intrusive_ptr<Session> Ptr;

      virtual bool defined() const
      {
	return defined_();
      }

      virtual void start(const TransportClientInstanceSend::Ptr& parent)
      {
	if (halt || !parent)
	  return;

	OPENVPN_LOG("Servproto start called"); // fixme

	TransportLink::send = parent;

	// init OpenVPN protocol handshake
	Base::update_now();
	Base::reset();
	Base::start();
	Base::flush(true);

	// coarse wakeup range
	housekeeping_schedule.init(Time::Duration::binary_ms(512), Time::Duration::binary_ms(1024));

	OPENVPN_LOG("Servproto start finished"); // fixme
      }

      virtual void stop()
      {
	if (!halt)
	  {
	    halt = true;
	    housekeeping_timer.cancel();
	    Base::pre_destroy();
	    if (TransportLink::send)
	      {
		TransportLink::send->stop();
		TransportLink::send.reset();
	      }
	  }
      }

      // called with OpenVPN-encapsulated packets from transport layer
      virtual void transport_recv(BufferAllocated& buf)
      {
	try {
	  OPENVPN_LOG_SERVPROTO("Transport RECV[" << buf.size() << "] " << client_endpoint_render() << ' ' << Base::dump_packet(buf));

	  // update current time
	  Base::update_now();

	  // get packet type
	  Base::PacketType pt = Base::packet_type(buf);

	  // process packet
	  if (pt.is_data())
	    {
	      // data packet
	      Base::data_decrypt(pt, buf);
	      if (buf.size())
		{
#ifdef OPENVPN_PACKET_LOG
		  log_packet(buf, false);
#endif
		  // make packet appear as incoming on tun interface
		  if (true) // fixme: was tun
		    {
		      OPENVPN_LOG_SERVPROTO("TUN SEND[" << buf.size()) << ']';
		      // fixme -- code me
		    }
		}

	      // do a lightweight flush
	      Base::flush(false);
	    }
	  else if (pt.is_control())
	    {
	      // control packet
	      Base::control_net_recv(pt, buf);

	      // do a full flush
	      Base::flush(true);
	    }

	  // schedule housekeeping wakeup
	  set_housekeeping_timer();
	}
	catch (const std::exception& e)
	  {
	    error(e);
	  }
      }

      // called with cleartext IP packets from routing layer
      virtual void tun_recv(BufferAllocated& buf)
      {
	// fixme -- code me
      }

      // Called with control channel push commands to
      // newly connected client by manager layer.
      virtual void push(BufferPtr& buf, bool auth_status)
      {
	// fixme -- code me
      }

      virtual ~Session()
      {
	// fatal error if destructor called while Session is active
	if (defined_())
	  std::abort();
      }

    private:
      Session(boost::asio::io_service& io_service_arg,
	      const Factory& factory)
	: Base(factory.proto_context_config, factory.stats),
	  io_service(io_service_arg),
	  halt(false),
	  housekeeping_timer(io_service_arg),
	  stats(factory.stats)
      {}

      bool defined_() const
      {
	return !halt && TransportLink::send;
      }

      // proto base class calls here for control channel network sends
      virtual void control_net_send(const Buffer& net_buf)
      {
	OPENVPN_LOG_SERVPROTO("Transport SEND[" << net_buf.size() << "] " << client_endpoint_render() << ' ' << Base::dump_packet(net_buf));
	if (TransportLink::send->transport_send_const(net_buf))
	  Base::update_last_sent();
      }

      // proto base class calls here for app-level control-channel messages received
      virtual void control_recv(BufferPtr& app_bp)
      {
	const std::string msg = Unicode::utf8_printable(Base::template read_control_string<std::string>(*app_bp),
							Unicode::UTF8_FILTER);

	OPENVPN_LOG_SERVPROTO("************************************ CLIENT MSG: " << msg); // fixme

	// fixme -- handle messages from client
	Base::write_control_string(std::string("AUTH_FAILED"));
	Base::flush(true);
	set_housekeeping_timer();
      }

      void housekeeping_callback(const boost::system::error_code& e)
      {
	try {
	  if (!e && !halt)
	    {
	      // update current time
	      Base::update_now();

	      housekeeping_schedule.reset();
	      Base::housekeeping();
	      if (Base::invalidated())
		error(std::string("Session invalidated: ") + Error::name(Base::invalidation_reason()));
	      else
		set_housekeeping_timer();
	    }
	}
	catch (const std::exception& e)
	  {
	    error(e);
	  }
      }

      void set_housekeeping_timer()
      {
	Time next = Base::next_housekeeping();
	if (!housekeeping_schedule.similar(next))
	  {
	    if (!next.is_infinite())
	      {
		next.max(now());
		housekeeping_schedule.reset(next);
		housekeeping_timer.expires_at(next);
		housekeeping_timer.async_wait(asio_dispatch_timer(&Session::housekeeping_callback, this));
	      }
	    else
	      {
		housekeeping_timer.cancel();
	      }
	  }
      }

      std::string client_endpoint_render()
      {
	if (TransportLink::send)
	  return TransportLink::send->info();
	else
	  return "";
      }

      void error(const std::string& error)
      {
	OPENVPN_LOG("ServerProto: " << error);
	stop();
      }

      void error(const std::exception& e)
      {
	error(e.what());
      }

      boost::asio::io_service& io_service;
      bool halt;

      CoarseTime housekeeping_schedule;
      AsioTimer housekeeping_timer;

      SessionStats::Ptr stats;
    };
  };

  inline TransportClientInstanceRecv::Ptr ServerProto::Factory::new_client_instance()
  {
    return TransportClientInstanceRecv::Ptr(new Session(io_service, *this));
  }
}

#endif
