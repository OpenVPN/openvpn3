//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
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

// Transmit TunBuilderCapture object (as JSON) to a unix
// domain socket server that will establish tunnel.

#ifndef OPENVPN_CLIENT_UNIX_CMDAGENT_H
#define OPENVPN_CLIENT_UNIX_CMDAGENT_H

#include <utility>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/jsonhelper.hpp>
#include <openvpn/common/scoped_fd.hpp>
#include <openvpn/common/xmitfd.hpp>
#include <openvpn/buffer/bufstr.hpp>
#include <openvpn/frame/frame_init.hpp>
#include <openvpn/ws/httpcliset.hpp>
#include <openvpn/tun/builder/setup.hpp>

namespace openvpn {

  class UnixCommandAgent : public TunBuilderSetup::Factory
  {
  public:
    typedef RCPtr<UnixCommandAgent> Ptr;

    OPENVPN_EXCEPTION(ovpnagent);

    static TunBuilderSetup::Factory::Ptr new_agent(const OptionList& opt)
    {
      return new UnixCommandAgent(opt);
    }

  private:
    struct Config : public RC<thread_unsafe_refcount>
    {
      typedef RCPtr<Config> Ptr;

      Config()
      {
	uds_name = "/var/run/ovpnagent.sock";
	debug_level = 1;
      }

      std::string uds_name;     // unix domain socket name
      int debug_level;
    };

    class SetupClient : public TunBuilderSetup::Base
    {
    public:
      SetupClient(const Config::Ptr& config_arg)
	: config(config_arg)
      {
      }

    private:
      virtual int establish(const TunBuilderCapture& pull, // defined by TunBuilderSetup::Base
			    TunBuilderSetup::Config* tbs_config,
			    Stop* stop,
			    std::ostream& os) override
      {
	os << "SetupClient: transmitting tun setup list to " << config->uds_name << std::endl;

	// Build JSON request
	Json::Value jreq(Json::objectValue);
	jreq["tun"] = pull.to_json(); // convert TunBuilderCapture to JSON
	if (tbs_config)
	  {
	    Json::Value jconf = tbs_config->to_json();
	    if (!jconf.isNull())
	      jreq["config"] = std::move(jconf);
	  }
	const std::string jtxt = jreq.toStyledString();
	os << jtxt; // dump it

	// Create HTTP transaction container
	WS::ClientSet::TransactionSet::Ptr ts = new_transaction_set();

	// Set up a completion function to fetch the tunnel fd
	ScopedFD tun_fd;
	ts->completion = [&tun_fd](WS::ClientSet::TransactionSet& ts) {
	  if (!ts.http_status_success())
	    return;
	  try {
	    // get HTTP socket
	    const int fd = ts.hsc.unix_fd();
	    if (fd < 0)
	      OPENVPN_THROW_EXCEPTION("cannot get HTTP socket");

	    // send FD request
	    XmitFD::xmit_fd(fd, -1, "t", 5000);

	    // receive payload FD
	    std::string msg;
	    tun_fd.reset(XmitFD::recv_fd(fd, msg, 256, 5000));
	    if (msg != "T")
	      OPENVPN_THROW_EXCEPTION("bad message tag");
	  }
	  catch (const std::exception& e)
	    {
	      OPENVPN_THROW(ovpnagent, "cannot fetch tunnel fd from agent: " << e.what());
	    }
	};

	// Make transaction
	{
	  std::unique_ptr<WS::ClientSet::Transaction> t(new WS::ClientSet::Transaction);
	  t->req.method = "POST";
	  t->req.uri = "/tun-setup";
	  t->ci.keepalive = true;
	  t->ci.type = "application/json";
	  t->content_out.push_back(buf_from_string(jtxt));
	  ts->transactions.push_back(std::move(t));
	}

	// Execute transaction.  sps is true because we need to hold the
	// HTTP connection state long enough to fetch the received tun socket.
	WS::ClientSet::new_request_synchronous(ts, stop, nullptr, true);

	// Get result
	const Json::Value jres = get_json_result(os, *ts);

	// Get config
	{
	  const Json::Value& jconf = jres["config"];
	  os << jconf.toStyledString();
	  tbs_config->from_json(jconf, "config");
	}

	// Dump log
	const std::string log_txt = json::get_string(jres, "log_txt");
	os << log_txt;

	// return tun fd
	return tun_fd.release();
      }

      virtual void destroy(std::ostream& os) override // defined by DestructorBase
      {
	os << "SetupClient: transmitting tun destroy request to " << config->uds_name << std::endl;

	// Create HTTP transaction container
	WS::ClientSet::TransactionSet::Ptr ts = new_transaction_set();

	// Make transaction
	{
	  std::unique_ptr<WS::ClientSet::Transaction> t(new WS::ClientSet::Transaction);
	  t->req.method = "GET";
	  t->req.uri = "/tun-destroy";
	  ts->transactions.push_back(std::move(t));
	}

	// Execute transaction
	WS::ClientSet::new_request_synchronous(ts);

	// Process result
	const Json::Value jres = get_json_result(os, *ts);

	// Dump log
	const std::string log_txt = json::get_string(jres, "log_txt");
	os << log_txt;
      }

      WS::ClientSet::TransactionSet::Ptr new_transaction_set()
      {
	WS::Client::Config::Ptr hc(new WS::Client::Config());
	hc->frame = frame_init_simple(2048);
	hc->connect_timeout = 10;
	hc->general_timeout = 60;

	WS::ClientSet::TransactionSet::Ptr ts = new WS::ClientSet::TransactionSet;
	ts->host.host = config->uds_name;
	ts->host.port = "unix";
	ts->http_config = hc;
	ts->debug_level = config->debug_level;

	ts->post_connect = [this](WS::ClientSet::TransactionSet& ts, AsioPolySock::Base& sock) {
	  SockOpt::Creds creds;
	  if (sock.peercreds(creds))
	    {
	      if (!creds.root_uid())
		OPENVPN_THROW(ovpnagent, "unix socket server " << config->uds_name << " not running as root");
	    }
	  else
	    OPENVPN_THROW(ovpnagent, "unix socket server " << config->uds_name << " could not be validated");
	};

	return ts;
      }

      Json::Value get_json_result(std::ostream& os, WS::ClientSet::TransactionSet& ts)
      {
	// Get content
	if (ts.transactions.size() != 1)
	  throw ovpnagent("unexpected transaction set size");
	WS::ClientSet::Transaction& t = *ts.transactions[0];
	const std::string content = t.content_in.to_string();
	os << t.format_status(ts) << std::endl;
	if (!t.comm_status_success())
	  {
	    os << content;
	    throw ovpnagent("communication error");
	  }
	if (!t.request_status_success())
	  {
	    os << content;
	    throw ovpnagent("request error");
	  }

	// Verify content-type
	if (t.reply.headers.get_value_trim("content-type") != "application/json")
	  {
	    os << content;
	    throw ovpnagent("unexpected content-type");
	  }

	// Parse the returned json dict
	Json::Value jres;
	Json::Reader reader;
	if (!reader.parse(content, jres, false))
	  {
	    os << content;
	    OPENVPN_THROW(ovpnagent, "error parsing returned JSON: " << reader.getFormattedErrorMessages());
	  }
	if (!jres.isObject())
	  throw ovpnagent("returned JSON content is not a dictionary");
	return jres;
      }

      Config::Ptr config;
    };

    virtual TunBuilderSetup::Base::Ptr new_setup_obj() override
    {
      if (config)
	return new SetupClient(config);
      else
	return TunBuilderSetup::Base::Ptr();
    }

    UnixCommandAgent(const OptionList& opt_parent)
    {
      config.reset(new Config);
    }

    Config::Ptr config;
  };
}
#endif
