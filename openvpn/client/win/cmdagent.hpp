//
//  cmdagent.hpp
//  OpenVPN
//
//  Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
//  All rights reserved.
//

// Transmit TunBuilderCapture object (as JSON) to a named pipe
// server that will establish tunnel.

#ifndef OPENVPN_CLIENT_WIN_CMDAGENT_H
#define OPENVPN_CLIENT_WIN_CMDAGENT_H

#include <utility>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/wstring.hpp>
#include <openvpn/common/jsonhelper.hpp>
#include <openvpn/buffer/bufstr.hpp>
#include <openvpn/buffer/bufhex.hpp>
#include <openvpn/frame/frame_init.hpp>
#include <openvpn/ws/httpcliset.hpp>
#include <openvpn/win/winerr.hpp>
#include <openvpn/client/win/agentconfig.hpp>
#include <openvpn/win/modname.hpp>
#include <openvpn/tun/win/client/setupbase.hpp>
#include <openvpn/win/npinfo.hpp>
#include <openvpn/win/handlecomm.hpp>
#include <openvpn/win/event.hpp>
#include <openvpn/error/error.hpp>

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
      SetupClient(openvpn_io::io_context& io_context,
		  const Config::Ptr& config_arg)
	: config(config_arg),
	  service_process(io_context)
      {
      }

    private:
      virtual HANDLE establish(const TunBuilderCapture& pull,
			       const std::wstring& openvpn_app_path,
			       Stop* stop,
			       std::ostream& os) override // TunWin::SetupBase
      {
	os << "SetupClient: transmitting tun setup list to " << config->npserv << std::endl;

	// Build JSON request
	Json::Value jreq(Json::objectValue);
#if _WIN32_WINNT < 0x0600 // pre-Vista needs us to explicitly communicate our PID
	jreq["pid"] = Json::Value((Json::UInt)::GetProcessId(::GetCurrentProcess()));
#endif
	jreq["confirm_event"] = confirm_event.duplicate_local();
	jreq["destroy_event"] = destroy_event.duplicate_local();
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
	const HANDLE tap = BufHex::parse<HANDLE>(tap_handle_hex, "TAP handle");
	return tap;
      }

      virtual void l2_finish(const TunBuilderCapture& pull,
			     Stop* stop,
			     std::ostream& os) override
      {
	throw ovpnagent("l2_finish not implemented");
      }

      virtual bool l2_ready(const TunBuilderCapture& pull) override
      {
	throw ovpnagent("l2_ready not implemented");
      }

      virtual void confirm() override
      {
	confirm_event.signal_event();
      }

      virtual void set_service_fail_handler(std::function<void()>&& handler)
      {
	if (service_process.is_open())
	  {
	    service_process.async_wait([handler=std::move(handler)](const openvpn_io::error_code& error) {
		if (!error)
		  handler();
	      });
	  }
      }

      virtual void destroy(std::ostream& os) override // defined by DestructorBase
      {
	os << "SetupClient: signaling tun destroy event" << std::endl;
	service_process.close();
	destroy_event.signal_event();
      }

      WS::ClientSet::TransactionSet::Ptr new_transaction_set()
      {
	WS::Client::Config::Ptr hc(new WS::Client::Config());
	hc->frame = frame_init_simple(2048);
	hc->connect_timeout = 30;
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
	      service_process.assign(npinfo.proc.release());
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

	if (t.comm_status_timeout())
	  {
	    // this could be the case when agent service
	    // hasn't been started yet, so we throw a non-fatal
	    // exception which makes core retry.
	    os << "connection timeout";
	    throw ExceptionCode(Error::TUN_ERROR);
	  }

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
	return jres;
      }

      Config::Ptr config;
      openvpn_io::windows::object_handle service_process;
      Win::Event confirm_event;
      Win::DestroyEvent destroy_event;
    };

    virtual TunWin::SetupBase::Ptr new_setup_obj(openvpn_io::io_context& io_context) override
    {
      if (config)
	return new SetupClient(io_context, config);
      else
	return new TunWin::Setup(io_context);
    }

    WinCommandAgent(const OptionList& opt_parent)
    {
      config.reset(new Config);
    }

    Config::Ptr config;
  };
}

#endif
