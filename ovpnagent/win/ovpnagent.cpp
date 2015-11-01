// OpenVPN
// Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
// All rights reserved

// Boilerplate for general-purpose Named pipe HTTP server

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <utility>

#include <asio.hpp>

// debug settings (production setting in parentheses)
#define OPENVPN_LOG_SSL(x) OPENVPN_LOG(x)

// VERSION version can be passed on build command line
#include <openvpn/common/stringize.hpp>
#ifdef VERSION
#define HTTP_SERVER_VERSION OPENVPN_STRINGIZE(VERSION)
#else
#define HTTP_SERVER_VERSION "0.1.0"
#endif

#include <openvpn/log/logbase.hpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/path.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/splitlines.hpp>
#include <openvpn/common/wstring.hpp>
#include <openvpn/log/logbasesimple.hpp>
#include <openvpn/buffer/buflist.hpp>
#include <openvpn/init/initprocess.hpp>
#include <openvpn/ssl/sslchoose.hpp>
#include <openvpn/ws/httpserv.hpp>
#include <openvpn/client/win/agentconfig.hpp>
#include <openvpn/win/winsvc.hpp>
#include <openvpn/win/logfile.hpp>

#if _WIN32_WINNT >= 0x0600 // Vista and higher
#include <openvpn/win/npinfo.hpp>
#endif

// actions
#include <openvpn/win/cmd.hpp>
#include <openvpn/win/sleep.hpp>
#include <openvpn/tun/win/tunutil.hpp>

#if defined(USE_POLARSSL)
#define SSL_LIB_NAME "PolarSSL"
#elif defined(USE_OPENSSL)
#define SSL_LIB_NAME "OpenSSL"
#else
#error no SSL library defined
#endif

void log_version()
{
  OPENVPN_LOG("OpenVPN Agent " HTTP_SERVER_VERSION " [" SSL_LIB_NAME "] built on " __DATE__ " " __TIME__);
}

using namespace openvpn;

struct MyConfig
{
  MyConfig()
  {
    pipe_name = Agent::named_pipe_path();
    server_exe = Win::module_name_utf8();
    n_pipe_instances = 4;
  }

  std::string pipe_name;
  std::string server_exe;
  unsigned int n_pipe_instances;
};

class MySessionStats : public SessionStats
{
public:
  typedef RCPtr<MySessionStats> Ptr;

  virtual void error(const size_t err_type, const std::string* text=nullptr) override
  {
    OPENVPN_LOG(Error::name(err_type));
  }

  std::string dump() const
  {
    std::ostringstream os;
    os << "OpenVPN Agent Stats" << std::endl;
    return os.str();
  }
};

class MyListener : public WS::Server::Listener
{
public:
  typedef RCPtr<MyListener> Ptr;

  MyListener(const MyConfig& config_arg,
	     asio::io_context& io_context,
	     const WS::Server::Config::Ptr& hconf,
	     const Listen::List& listen_list,
	     const WS::Server::Listener::Client::Factory::Ptr& client_factory)
    : WS::Server::Listener(io_context, hconf, listen_list, client_factory),
      config(config_arg),
      cmd_sanitizer(TunWin::Util::cmd_sanitizer())
  {
  }

  const MyConfig& config;
  const std::regex cmd_sanitizer;

private:
  virtual bool allow_client(AsioPolySock::Base& sock) override
  {
    AsioPolySock::NamedPipe* np = dynamic_cast<AsioPolySock::NamedPipe*>(&sock);
    if (np)
      {
#if _WIN32_WINNT >= 0x0600 // Vista and higher
	Win::NamedPipePeerInfoClient npinfo(np->handle.native_handle());
	const std::string client_exe = wstring::to_utf8(npinfo.exe_path);
	OPENVPN_LOG("connection from " << client_exe);
	if (Agent::valid_pipe(client_exe, config.server_exe))
	  return true;
	OPENVPN_LOG(client_exe << " not recognized as a valid client");
#else
	return true;
#endif
      }
    else
      OPENVPN_LOG("only named pipe clients are allowed");
    return false;
  }
};

class MyClientInstance : public WS::Server::Listener::Client
{
public:
  typedef RCPtr<MyClientInstance> Ptr;

  MyClientInstance(WS::Server::Listener::Client::Initializer& ci)
    : WS::Server::Listener::Client(ci)
  {
    OPENVPN_LOG("INSTANCE START");
  }

  virtual ~MyClientInstance()
  {
    OPENVPN_LOG("INSTANCE DESTRUCT");
  }

private:
  virtual void http_request_received() override
  {
    try {
      const HTTP::Request& req = request();
      OPENVPN_LOG("HTTP request received from " << sock->remote_endpoint_str() << '\n' << req.to_string());

      // get content-type
      const std::string content_type = req.headers.get_value_trim("content-type");

      if (req.method != "GET" && req.uri == "/actions")
	{
	  // verify correct content-type
	  if (string::strcasecmp(content_type, "application/x-ovpn-actions"))
	    throw Exception("bad content-type");

	  // parse the json dict
	  Json::Value root;
	  Json::Reader reader;
	  if (!reader.parse(in.to_string(), root, false))
	    OPENVPN_THROW_EXCEPTION("json parse error: " << reader.getFormatedErrorMessages());
	  if (!root.isArray())
	    throw Exception("json parse error: top level json object is not an array");

	  // alloc output buffer
	  std::ostringstream os;

	  // loop through action list
	  for (unsigned int i = 0; i < root.size(); ++i)
	    {
	      // get an action
	      const Json::Value& jact = root[i];

	      // get action type
	      if (!jact.isObject())
		throw Exception("json action list element is not a dictionary");
	      const Json::Value& jtype = jact["type"];
	      if (!jtype.isString())
		throw Exception("json type element in action entry is not a string");
	      const std::string type = jtype.asString();

	      // build the action object from json
	      Action::Ptr action;
	      try {
		if (type == "WinCmd")
		  action = WinCmd::from_json_untrusted(jact, parent()->cmd_sanitizer);
		else if (type == "ActionSetSearchDomain")
		  action = TunWin::Util::ActionSetSearchDomain::from_json_untrusted(jact);
		else if (type == "ActionDeleteAllRoutesOnInterface")
		  action = TunWin::Util::ActionDeleteAllRoutesOnInterface::from_json_untrusted(jact);
		else
		  OPENVPN_THROW_EXCEPTION("unknown action type: " << type);

		// execute the action
		action->execute(os);
	      }
	      catch (const std::exception& e)
		{
		  os << std::string(e.what()) << std::endl;
		}
	    }

	  out = buf_from_string(string::remove_blanks(os.str()));

	  WS::Server::ContentInfo ci;
	  ci.http_status = HTTP::Status::OK;
	  ci.type = "text/plain";
	  ci.length = out->size();
	  ci.keepalive = keepalive_request();
	  generate_reply_headers(ci);
	}
      else
	{
	  out = buf_from_string("page not found\n");
	  WS::Server::ContentInfo ci;
	  ci.http_status = HTTP::Status::NotFound;
	  ci.type = "text/plain";
	  ci.length = out->size();
	  generate_reply_headers(ci);
	}
    }
    catch (const std::exception& e)
      {
	out = buf_from_string(std::string(e.what()) + '\n');
	WS::Server::ContentInfo ci;
	ci.http_status = HTTP::Status::BadRequest;
	ci.type = "text/plain";
	ci.length = out->size();
	generate_reply_headers(ci);
      }
  }

  virtual void http_content_in(BufferAllocated& buf) override
  {
    if (buf.defined())
      in.emplace_back(new BufferAllocated(std::move(buf)));
  }

  virtual BufferPtr http_content_out() override
  {
    BufferPtr ret;
    ret.swap(out);
    return ret;
  }

  virtual bool http_out_eof() override
  {
    OPENVPN_LOG("HTTP output EOF");
    return true;
  }

  virtual void http_stop(const int status, const std::string& description) override
  {
    OPENVPN_LOG("INSTANCE STOP : " << WS::Server::Status::error_str(status) << " : " << description);
  }

  MyListener* parent()
  {
    return static_cast<MyListener*>(get_parent());
  }

  BufferList in;
  BufferPtr out;
};

class MyClientFactory : public WS::Server::Listener::Client::Factory
{
public:
  typedef RCPtr<MyClientFactory> Ptr;

  virtual WS::Server::Listener::Client::Ptr new_client(WS::Server::Listener::Client::Initializer& ci) override
  {
    return new MyClientInstance(ci);
  }
};

class MyService : public Win::Service
{
public:
  MyService()
    : Win::Service(config())
  {
  }

  virtual void service_work(DWORD argc, LPWSTR *argv) override
  {
    if (is_service())
      {
	try {
	  log.reset(new Win::LogFile(log_fn(), "", false));
	}
	catch (const std::exception& e)
	  {
	    std::cerr << e.what() << std::endl;
	  }
      }
    if (!log)
      log.reset(new LogBaseSimple());

    io_context.reset(new asio::io_context(1)); // concurrency hint=1

    log_version();

    MyConfig conf;

#if _WIN32_WINNT >= 0x0600 // Vista and higher
    Win::NamedPipePeerInfo::allow_client_query();
#endif

    WS::Server::Config::Ptr hconf = new WS::Server::Config();
    hconf->http_server_id = "ovpnagent/" HTTP_SERVER_VERSION;
    hconf->frame = frame_init_simple(2048);
    hconf->stats.reset(new MySessionStats);

    // DACL string for creating named pipe
    hconf->sddl_string =
      "D:"                         // discretionary ACL
      "(D;OICI;GA;;;S-1-5-2)"      // deny all access for network users
      "(A;OICI;GA;;;S-1-5-32-544)" // allow full access to Admin group
      "(A;OICI;GA;;;S-1-5-18)"     // allow full access to Local System account
      "(D;OICI;0x4;;;S-1-1-0)"     // deny FILE_CREATE_PIPE_INSTANCE for Everyone
      "(A;OICI;GRGW;;;S-1-5-11)"   // allow read/write access for authenticated users
      ;

    Listen::List ll;
    const unsigned int n_pipe_instances = 4;
    for (unsigned int i = 0; i < n_pipe_instances; ++i)
      {
	Listen::Item li;
	li.directive = "http-listen";
	li.addr = conf.pipe_name;
	li.proto = Protocol(Protocol::NamedPipe);
	li.ssl = Listen::Item::SSLOff;
	li.n_threads = n_pipe_instances;
	ll.push_back(std::move(li));
      }

    MyClientFactory::Ptr factory = new MyClientFactory();
    listener.reset(new MyListener(conf, *io_context, hconf, ll, factory));
    listener->start();

    report_service_running();

    io_context->run();
  }

  // Called by service control manager in another thread
  // to signal the service_work() method to exit.
  virtual void service_stop() override
  {
    asio::post(*io_context, [this]() {
	if (listener)
	  listener->stop();
      });
  }

private:
  static Config config()
  {
    Config c;
    c.name = "ovpnagent";
    c.display_name = "OpenVPN Agent";
#if _WIN32_WINNT < 0x0600 // pre-Vista
    c.dependencies.push_back("Dhcp"); // DHCP client
#endif
    return c;
  }

  static std::string log_fn()
  {
    const std::string modname = Win::module_name_utf8();
    const std::string moddir = path::dirname(modname);
    const std::string fn = path::join(moddir, "agent.log");
    return fn;
  }

  std::unique_ptr<asio::io_context> io_context;
  MyListener::Ptr listener;
  LogBase::Ptr log;
};

OPENVPN_SIMPLE_EXCEPTION(usage);

int main(int argc, char* argv[])
{
  int ret = 0;

  // process-wide initialization
  InitProcess::init();

  try {
    MyService serv;
    if (argc >= 2)
      {
	const std::string arg = argv[1];
	if (arg == "run")
	  serv.service_work(0, nullptr);
	else if (arg == "install")
	  serv.install();
	else if (arg == "remove")
	  serv.remove();
	else if (arg == "modname")
	  std::wcout << Win::module_name() << std::endl;
	else if (arg == "help")
	  {
	    std::cout << "usage: ovpnagent [options]" << std::endl;
	    std::cout << "  run       -- run in foreground (for debugging)" << std::endl;
	    std::cout << "  install   -- install as service" << std::endl;
	    std::cout << "  remove    -- uninstall" << std::endl;
	    std::cout << "  modname   -- show module name" << std::endl;
	    std::cout << "  help      -- show help message" << std::endl;
	    std::cout << "  [default] -- start as service" << std::endl;
	  }
	else
	  {
	    std::cout << "unrecognized option, use 'help' for more info" << std::endl;
	    ret = 2;
	  }
      }
    else
      serv.start();
  }
  catch (const std::exception& e)
    {
      std::cout << "ovpnagent: " << e.what() << std::endl;
      ret = 1;
    }

  InitProcess::uninit();
  return ret;
}
