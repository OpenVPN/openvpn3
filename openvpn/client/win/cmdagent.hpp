//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
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

// Transmit TunBuilderCapture object (as JSON) to a named pipe
// server that will establish tunnel.

#ifndef OPENVPN_CLIENT_WIN_CMDAGENT_H
#define OPENVPN_CLIENT_WIN_CMDAGENT_H

#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/wstring.hpp>
#include <openvpn/common/jsonhelper.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/buffer/bufstr.hpp>
#include <openvpn/frame/frame_init.hpp>
#include <openvpn/ws/httpcliset.hpp>
#include <openvpn/client/win/agentconfig.hpp>
#include <openvpn/win/modname.hpp>
#include <openvpn/tun/win/client/setupbase.hpp>
#include <openvpn/win/npinfo.hpp>

namespace openvpn {

  class WinCommandAgent : public TunWin::SetupFactory
  {
  public:
    typedef RCPtr<WinCommandAgent> Ptr;

    OPENVPN_EXCEPTION(ovpnagent);

    static TunWin::SetupFactory::Ptr new_agent(const OptionList& opt)
    {
      return new WinCommandAgent(opt);
    }

  private:
    struct Config : public RC<thread_unsafe_refcount>
    {
      typedef RCPtr<Config> Ptr;

      Config()
      {
	npserv = Agent::named_pipe_path();
	client_exe = Win::module_name_utf8();
	debug_level = 1;
      }

      std::string npserv;     // server pipe
      std::string client_exe; // for validation
      int debug_level;
    };

    class SetupClient : public TunWin::SetupBase
    {
    public:
      SetupClient(const Config::Ptr& config_arg)
	: config(config_arg)
      {
      }

    private:
      virtual HANDLE establish(const TunBuilderCapture& pull,
			       Stop* stop,
			       std::ostream& os) override // TunWin::SetupBase
      {
	os << "SetupClient: transmitting tun setup list to " << config->npserv << std::endl;

	// Build JSON request
	Json::Value jreq(Json::objectValue);
#if _WIN32_WINNT < 0x0600 // pre-Vista needs us to explicitly communicate our PID
	jreq["pid"] = Json::Value((Json::UInt)::GetProcessId(::GetCurrentProcess()));
#endif
	jreq["tun"] = pull.to_json(); // convert TunBuilderCapture to JSON
	const std::string jtxt = jreq.toStyledString();
	os << jtxt; // dump it

	// Create HTTP transaction container
	WS::ClientSet::TransactionSet::Ptr ts = new_transaction_set();

	// Make transaction
	{
	  std::unique_ptr<WS::ClientSet::Transaction> t(new WS::ClientSet::Transaction);
	  t->req.method = "POST";
	  t->req.uri = "/tun-setup";
	  t->ci.type = "application/json";
	  t->content_out.push_back(buf_from_string(jtxt));
	  ts->transactions.push_back(std::move(t));
	}

	// Execute transaction
	WS::ClientSet::new_request_synchronous(ts, stop);

	// Get result
	const Json::Value jres = get_json_result(os, *ts);

	// Dump log
	const std::string log_txt = json::get_string(jres, "log_txt");
	os << log_txt;

	// Parse TAP handle
	const std::string tap_handle_hex = json::get_string(jres, "tap_handle_hex");
	os << "TAP handle: " << tap_handle_hex << std::endl;
	HANDLE h;
	Buffer hb((unsigned char *)&h, sizeof(h), false);
	try {
	  parse_hex(hb, tap_handle_hex);
	}
	catch (const BufferException& e)
	  {
	    OPENVPN_THROW(ovpnagent, "tap_handle_hex unexpected size: " << e.what());
	  }
	if (hb.size() != sizeof(h))
	  throw ovpnagent("tap_handle_hex unexpected size");
	return h;
      }

      virtual void destroy(std::ostream& os) override // defined by DestructorBase
      {
	os << "SetupClient: transmitting tun destroy request to " << config->npserv << std::endl;

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
	ts->host.host = config->npserv;
	ts->host.port = "np";
	ts->http_config = hc;
	ts->debug_level = config->debug_level;

#if _WIN32_WINNT >= 0x0600 // Vista and higher
	ts->post_connect = [this](WS::ClientSet::TransactionSet& ts, AsioPolySock::Base& sock) {
	  AsioPolySock::NamedPipe* np = dynamic_cast<AsioPolySock::NamedPipe*>(&sock);
	  if (np)
	    {
	      Win::NamedPipePeerInfoServer npinfo(np->handle.native_handle());
	      const std::string server_exe = wstring::to_utf8(npinfo.exe_path);
	      if (!Agent::valid_pipe(config->client_exe, server_exe))
		OPENVPN_THROW(ovpnagent, config->npserv << " server running from " << server_exe << " could not be validated");
	    }
	};
#endif
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
	    OPENVPN_THROW(ovpnagent, "error parsing returned JSON: " << reader.getFormatedErrorMessages());
	  }
	return jres;
      }

      Config::Ptr config;
    };

    virtual TunWin::SetupBase::Ptr new_setup_obj() override
    {
      if (config)
	return new SetupClient(config);
      else
	return new TunWin::Setup();
    }

    WinCommandAgent(const OptionList& opt_parent)
    {
      config.reset(new Config);
    }

    Config::Ptr config;
  };
}
#endif
