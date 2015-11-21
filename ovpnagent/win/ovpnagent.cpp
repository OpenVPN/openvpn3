// OpenVPN
// Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
// All rights reserved

// OpenVPN agent for Windows

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
#include <openvpn/win/scoped_handle.hpp>
#include <openvpn/win/winsvc.hpp>
#include <openvpn/win/logfile.hpp>
#include <openvpn/tun/win/client/tunsetup.hpp>
#include <openvpn/win/npinfo.hpp>

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
      client_process(io_context)
  {
  }

  Win::ScopedHANDLE establish_tun(const TunBuilderCapture& tbc, std::ostream& os)
  {
    if (!tun)
      tun.reset(new TunWin::Setup);
    return Win::ScopedHANDLE(tun->establish(tbc, os));
  }

  void destroy_tun(std::ostream& os)
  {
    client_process.close();
    if (tun)
      {
	tun->destroy(os);
	tun.reset();
      }
  }

  void destroy_tun()
  {
    std::ostringstream os;
    destroy_tun(os);
  }

  void set_client_process(Win::ScopedHANDLE&& proc)
  {
    client_process.close();
    client_process.assign(proc.release());

    // special failsafe to destroy tun in case client crashes without closing it
    client_process.async_wait([self=Ptr(this)](const asio::error_code& error) {
	if (!error && self->tun)
	  {
	    std::ostringstream os;
	    self->tun->destroy(os);
	    OPENVPN_LOG_NTNL("FAILSAFE TUN CLOSE\n" << os.str());
	  }
      });
  }

  HANDLE get_client_process()
  {
    if (!client_process.is_open())
      throw Exception("no client process");
    return client_process.native_handle();
  }

  const MyConfig& config;

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

  TunWin::Setup::Ptr tun;
  asio::windows::object_handle client_process;
};

class MyClientInstance : public WS::Server::Listener::Client
{
public:
  typedef RCPtr<MyClientInstance> Ptr;

  MyClientInstance(WS::Server::Listener::Client::Initializer& ci)
    : WS::Server::Listener::Client(ci)
  {
    //OPENVPN_LOG("INSTANCE START");
  }

  virtual ~MyClientInstance()
  {
    //OPENVPN_LOG("INSTANCE DESTRUCT");
  }

private:
  virtual void http_request_received() override
  {
    // alloc output buffer
    std::ostringstream os;

    try {
      const HANDLE client_pipe = get_client_pipe();

      const HTTP::Request& req = request();
      OPENVPN_LOG("HTTP request received from " << sock->remote_endpoint_str() << '\n' << req.to_string());

      // get content-type
      const std::string content_type = req.headers.get_value_trim("content-type");

      if (req.method == "POST" && req.uri == "/tun-setup")
	{
	  // verify correct content-type
	  if (string::strcasecmp(content_type, "application/json"))
	    throw Exception("bad content-type");

	  // parse the json dict
	  const Json::Value root = json::parse(in.to_string(), "JSON request");
	  if (!root.isObject())
	    throw Exception("json parse error: top level json object is not a dictionary");

	  // get PID
	  ULONG pid = json::get_uint_optional(root, "pid", 0);

	  // parse JSON data into a TunBuilderCapture object
	  TunBuilderCapture::Ptr tbc = TunBuilderCapture::from_json(json::get_dict(root, "tun", false));
	  tbc->validate();

	  // establish the tun setup object
	  Win::ScopedHANDLE handle(parent()->establish_tun(*tbc, os));

	  // this section is impersonated in the context of the client
	  {
	    Win::NamedPipeImpersonate impersonate(client_pipe);

	    // remember the client process that sent the request
	    parent()->set_client_process(get_client_process(client_pipe, pid));

	    // build JSON return dictionary
	    Json::Value jout(Json::objectValue);
	    jout["log_txt"] = string::remove_blanks(os.str());
	    jout["tap_handle_hex"] = Win::NamedPipePeerInfo::send_handle(handle(), parent()->get_client_process());

	    out = buf_from_string(jout.toStyledString());
	  }

	  WS::Server::ContentInfo ci;
	  ci.http_status = HTTP::Status::OK;
	  ci.type = "application/json";
	  ci.length = out->size();
	  ci.keepalive = keepalive_request();
	  generate_reply_headers(ci);
	}
      else if (req.method == "GET" && req.uri == "/tun-destroy")
	{
	  // destroy tun object
	  parent()->destroy_tun(os);

	  // build JSON return dictionary
	  Json::Value jout(Json::objectValue);
	  jout["log_txt"] = string::remove_blanks(os.str());

	  out = buf_from_string(jout.toStyledString());

	  WS::Server::ContentInfo ci;
	  ci.http_status = HTTP::Status::OK;
	  ci.type = "application/json";
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
	out = buf_from_string(string::remove_blanks(os.str() + e.what() + '\n'));
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
    //OPENVPN_LOG("HTTP output EOF");
    return true;
  }

  virtual void http_stop(const int status, const std::string& description) override
  {
    if (status != WS::Server::Status::E_SUCCESS)
      OPENVPN_LOG("INSTANCE STOP : " << WS::Server::Status::error_str(status) << " : " << description);
  }

  HANDLE get_client_pipe() const
  {
    AsioPolySock::NamedPipe* np = dynamic_cast<AsioPolySock::NamedPipe*>(sock.get());
    if (!np)
      throw Exception("only named pipe clients are allowed");
    return np->handle.native_handle();
  }

  Win::ScopedHANDLE get_client_process(const HANDLE pipe, ULONG pid_hint) const
  {
#if _WIN32_WINNT >= 0x0600 // Vista and higher
    pid_hint = Win::NamedPipePeerInfo::get_pid(pipe, true);
#endif
    if (!pid_hint)
      throw Exception("cannot determine client PID");
    return Win::NamedPipePeerInfo::get_process(pid_hint, false);
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
	  {
	    listener->destroy_tun();
	    listener->stop();
	  }
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
