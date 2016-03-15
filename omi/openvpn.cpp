// OpenVPN
// Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
// All rights reserved

// OpenVPN 3 client with Management Interface

#include <string>
#include <vector>
#include <thread>
#include <memory>
#include <utility>

// don't export core symbols
#define OPENVPN_CORE_API_VISIBILITY_HIDDEN

// should be included before other openvpn includes,
// with the exception of openvpn/log includes
#include <client/ovpncli.cpp>

#include <openvpn/common/platform.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/platform_string.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/time/timestr.hpp>
#include <openvpn/omi/omi.hpp>

#if defined(OPENVPN_PLATFORM_WIN)
#else
#include <openvpn/common/redir.hpp>
#endif

// set SSL_LIB_NAME to name of SSL library
#if defined(USE_POLARSSL)
#define SSL_LIB_NAME "PolarSSL"
#elif defined(USE_OPENSSL)
#define SSL_LIB_NAME "OpenSSL"
#else
#error no SSL library defined
#endif

using namespace openvpn;

std::string log_version()
{
  return platform_string("OpenVPN Management Interface") + " [" SSL_LIB_NAME "] built on " __DATE__ " " __TIME__;
}

class Client;

class OMI : public OMICore, public ClientAPI::LogReceiver
{
public:
  typedef RCPtr<OMI> Ptr;

  OMI(asio::io_context& io_context, OptionList opt)
    : OMICore(io_context, std::move(opt)),
      log_context(this)
  {
  }

  virtual void log(const ClientAPI::LogInfo& msg) override
  {
    const std::string ts = date_time();
    {
      std::lock_guard<std::mutex> lock(log_mutex);
      std::cout << ts << ' ' << msg.text << std::flush;
    }
  }

  void log_client(const ClientAPI::LogInfo& msg)
  {
  }

  void event(const ClientAPI::Event& ev)
  {
  }

  void external_pki_cert_request(ClientAPI::ExternalPKICertRequest& certreq)
  {
  }

  void external_pki_sign_request(ClientAPI::ExternalPKISignRequest& signreq)
  {
  }

  virtual bool omi_command_is_multiline(const Option& option) override
  {
    return string::starts_with(option.get_optional(0, 64), "multi-"); // fixme
  }

  virtual void omi_command_in(std::unique_ptr<Command> cmd) override
  {
    OPENVPN_LOG_STRING(cmd->to_string());
  }

  virtual void omi_done(const bool eof) override
  {
    OPENVPN_LOG("OMI DONE eof=" << eof);
  }

  std::unique_ptr<Client> client;
  std::mutex log_mutex;
  Log::Context log_context; // should be initialized last
};

class Client : public ClientAPI::OpenVPNClient
{
public:
  Client(OMI* omi)
    : parent(omi)
  {
  }

private:
  virtual bool socket_protect(int socket) override
  {
    return true;
  }

  virtual void event(const ClientAPI::Event& ev) override
  {
    parent->event(ev);
  }

  virtual void log(const ClientAPI::LogInfo& msg) override
  {
    parent->log_client(msg);
  }

  virtual void external_pki_cert_request(ClientAPI::ExternalPKICertRequest& certreq) override
  {
    parent->external_pki_cert_request(certreq);
  }

  virtual void external_pki_sign_request(ClientAPI::ExternalPKISignRequest& signreq) override
  {
    parent->external_pki_sign_request(signreq);
  }

  virtual bool pause_on_connection_timeout() override
  {
    return false;
  }

  OMI* parent;
};

int run(OptionList opt)
{
  asio::io_context io_context(1);
  bool io_context_run_called = false;
  int ret = 0;
  OMI::Ptr omi;

  try {
    omi.reset(new OMI(io_context, std::move(opt)));
    omi->open_log();
    const std::string config = omi->get_config();
    omi->start();
    io_context_run_called = true;
    io_context.run();
    omi->stop();
  }
  catch (const std::exception& e)
    {
      if (omi)
	omi->stop();
      if (io_context_run_called)
	io_context.poll(); // execute completion handlers,
      std::cerr << "openvpn: run loop exception: " << e.what() << std::endl;
      ret = 1;
    }
  return ret;
}

int main(int argc, char *argv[])
{
  int ret = 0;

  try {
    Client::init_process();
    if (argc >= 2)
      {
	ret = run(OptionList::parse_from_argv_static(string::from_argv(argc, argv, true)));
      }
    else
      {
	std::cout << log_version() << std::endl;
	std::cout << "Usage: openvpn [args...]" << std::endl;
	ret = 2;
      }
  }
  catch (const std::exception& e)
    {
      std::cerr << "openvpn: " << e.what() << std::endl;
      ret = 1;
    }
  Client::uninit_process();
  return ret;
}
