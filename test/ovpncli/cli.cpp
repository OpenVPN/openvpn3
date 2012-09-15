#include <getopt.h> // for getopt_long
#include <stdlib.h> // for atoi

#include <string>
#include <iostream>
#include <fstream>
#include <signal.h>

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/thread/thread.hpp>

#define OPENVPN_CORE_API_VISIBILITY_HIDDEN  // don't export core symbols

#include <openvpn/common/exception.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/time/timestr.hpp>

#include <client/ovpncli.cpp>

using namespace openvpn;

class Client : public ClientAPI::OpenVPNClient
{
private:
  virtual bool socket_protect(int socket)
  {
    std::cout << "*** socket_protect " << socket << std::endl;
    return true;
  }

  virtual void event(const ClientAPI::Event& ev)
  {
    std::cout << date_time() << " EVENT: " << ev.name;
    if (!ev.info.empty())
      std::cout << ' ' << ev.info;
    if (ev.error)
      std::cout << " [ERR]";
    std::cout << std::endl << std::flush;
  }

  virtual void log(const ClientAPI::LogInfo& log)
  {
    std::cout << date_time() << ' ' << log.text << std::flush;
  }

  virtual void external_pki_cert_request(ClientAPI::ExternalPKICertRequest& certreq)
  {
    std::cout << "*** external_pki_cert_request" << std::endl;
    certreq.error = true;
    certreq.errorText = "external_pki_cert_request not implemented";
  }

  virtual void external_pki_sign_request(ClientAPI::ExternalPKISignRequest& signreq)
  {
    std::cout << "*** external_pki_sign_request" << std::endl;
    signreq.error = true;
    signreq.errorText = "external_pki_sign_request not implemented";
  }
};

Client *the_client = NULL;

void worker_thread()
{
  boost::asio::detail::signal_blocker signal_blocker; // signals should be handled by parent thread
  try {
    std::cout << "Thread starting..." << std::endl;
    ClientAPI::Status connect_status = the_client->connect();
    if (connect_status.error)
      std::cout << "connect error: " <<  connect_status.message << std::endl;
  }
  catch (const std::exception& e)
    {
      std::cout << "Connect thread exception: " << e.what() << std::endl;
    }
  std::cout << "Thread finished" << std::endl;
}

void handler(int signum)
{
  switch (signum)
    {
    case SIGTERM:
    case SIGINT:
      std::cout << "received stop signal " << signum << std::endl;
      if (the_client)
	the_client->stop();
      break;
    case SIGHUP:
      std::cout << "received reconnect signal " << signum << std::endl;
      if (the_client)
	the_client->reconnect(2);
      break;
    default:
      std::cout << "received unknown signal " << signum << std::endl;
      break;
    }
}

int main(int argc, char *argv[])
{
  static const struct option longopts[] = {
    { "username",   required_argument,      NULL,           'u' },
    { "password",   required_argument,      NULL,           'p' },
    { "proto",      required_argument,      NULL,           'P' },
    { "server",     required_argument,      NULL,           's' },
    { "timeout",    required_argument,      NULL,           't' },
    { "compress",   required_argument,      NULL,           'c' },
    { NULL,         0,                      NULL,           0 }
  };

  try {
    if (argc >= 2)
      {
	std::string username;
	std::string password;
	std::string proto;
	std::string server;
	int timeout = 0;
	std::string compress;
	int ch;

	while ((ch = getopt_long(argc, argv, "u:p:P:s:t:c:", longopts, NULL)) != -1)
	  {
	    switch (ch)
	      {
	      case 'u':
		username = optarg;
		break;
	      case 'p':
		password = optarg;
		break;
	      case 'P':
		proto = optarg;
		break;
	      case 's':
		server = optarg;
		break;
	      case 't':
		timeout = atoi(optarg);
		break;
	      case 'c':
		compress = optarg;
		break;
	      default:
		goto usage;
	      }
	  }
	argc -= optind;
	argv += optind;

	Client::init_process();
	Client client;
	ClientAPI::Config config;
	if (argc != 1)
	  goto usage;
	config.content = read_text(argv[0]);
	config.serverOverride = server;
	config.protoOverride = proto;
	config.connTimeout = timeout;
	config.compressionMode = compress;
	ClientAPI::EvalConfig eval = client.eval_config(config);
	if (eval.error)
	  OPENVPN_THROW_EXCEPTION("eval config error: " << eval.message);
	if (eval.autologin)
	  {
	    if (!username.empty() || !password.empty())
	      std::cout << "NOTE: creds were not needed" << std::endl;
	  }
	else
	  {
	    if (username.empty())
	      OPENVPN_THROW_EXCEPTION("need creds");
	    ClientAPI::ProvideCreds creds;
	    creds.username = username;
	    creds.password = password;
	    creds.replacePasswordWithSessionID = true;
	    ClientAPI::Status creds_status = client.provide_creds(creds);
	    if (creds_status.error)
	      OPENVPN_THROW_EXCEPTION("creds error: " << creds_status.message);
	  }

	std::cout << "CONNECTING..." << std::endl;

	// catch signals
	struct sigaction sa;
	sa.sa_handler = handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART; // restart functions if interrupted by handler
	if (sigaction(SIGINT, &sa, NULL) == -1
	    || sigaction(SIGTERM, &sa, NULL) == -1
	    || sigaction(SIGHUP, &sa, NULL) == -1)
	  OPENVPN_THROW_EXCEPTION("error setting signal handler");

	// start connect thread
	the_client = &client;
	boost::thread* thread = new boost::thread(boost::bind(&worker_thread));

	// wait for connect thread to exit
	thread->join();
	the_client = NULL;

	// print closing stats
	{
	  const int n = client.stats_n();
	  std::vector<long long> stats = client.stats_bundle();

	  std::cout << "STATS:" << std::endl;
	  for (int i = 0; i < n; ++i)
	    {
	      const long long value = stats[i];
	      if (value)
		std::cout << "  " << client.stats_name(i) << " : " << value << std::endl;
	    }
	}
	return 0;
      }
    else
      {
	goto usage;
	return 2;
      }
  }
  catch (const std::exception& e)
    {
      the_client = NULL;
      std::cout << "Main thread exception: " << e.what() << std::endl;
      return 1;
    }

  return 0;

 usage:
  std::cout << "OpenVPN Client (ovpncli)" << std::endl;
  std::cout << "usage: cli <config-file> [options]" << std::endl;
  std::cout << "--username, -u : username" << std::endl;
  std::cout << "--password, -p : password" << std::endl;
  std::cout << "--proto, -P    : protocol override (udp|tcp)" << std::endl;
  std::cout << "--server, -S   : server override" << std::endl;
  std::cout << "--timeout, -t  : timeout" << std::endl;
  std::cout << "--compress, -c : compression mode (yes|no|asym)" << std::endl;
  return 2;
}
