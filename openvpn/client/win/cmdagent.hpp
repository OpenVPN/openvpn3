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

// Special ActionList that transmits actions to a named pipe
// server that will execute them in LocalSystem context.

#ifndef OPENVPN_CLIENT_WIN_CMDAGENT_H
#define OPENVPN_CLIENT_WIN_CMDAGENT_H

#include <openvpn/common/exception.hpp>
#include <openvpn/common/action.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/wstring.hpp>
#include <openvpn/frame/frame_init.hpp>
#include <openvpn/ws/httpcliset.hpp>
#include <openvpn/client/win/agentconfig.hpp>
#include <openvpn/win/modname.hpp>

#if _WIN32_WINNT >= 0x0600 // Vista and higher
#include <openvpn/win/npinfo.hpp>
#endif

namespace openvpn {

  class WinCommandAgent : public ActionListFactory
  {
  public:
    typedef RCPtr<WinCommandAgent> Ptr;

    static ActionListFactory::Ptr new_agent(const OptionList& opt)
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

    class ActionListClient : public ActionList
    {
    public:
      ActionListClient(const Config::Ptr& config_arg)
	: config(config_arg)
      {
      }

    private:
      virtual void execute(std::ostream& os) override
      {
	if (is_halt())
	  return;

	os << "ActionListClient: transmitting action list to " << config->npserv << std::endl;

	const std::string content = get_content();

	os << content;

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
		OPENVPN_THROW_EXCEPTION(config->npserv << " server running from " << server_exe << " could not be validated");
	    }
	};
#endif

	{
	  std::unique_ptr<WS::ClientSet::Transaction> t(new WS::ClientSet::Transaction);
	  t->req.method = "POST";
	  t->req.uri = "/actions";
	  t->ci.type = "application/x-ovpn-actions";
	  t->content_out.push_back(buf_from_string(content));
	  ts->transactions.push_back(std::move(t));
	}

	// execute transaction
	WS::ClientSet::new_request_synchronous(ts);

	// dump result
	{
	  WS::ClientSet::Transaction& t = *ts->transactions.at(0);
	  os << t.format_status(*ts) << std::endl;
	  os << t.content_in.to_string();
	  if (!t.http_status_success())
	    throw Exception("ovpnagent communication error");
	}
      }

      std::string get_content() const
      {
	Json::Value jact(Json::arrayValue);
	for (auto &a : *this)
	  jact.append(a->to_json());
	return jact.toStyledString();
      }

      Config::Ptr config;
    };

    virtual ActionList::Ptr new_action_list()
    {
      if (config)
	return new ActionListClient(config);
      else
	return new ActionList();
    }

    WinCommandAgent(const OptionList& opt_parent)
    {
      config.reset(new Config);
    }

    Config::Ptr config;
  };
}
#endif
