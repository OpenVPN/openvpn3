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

  virtual bool pause_on_connection_timeout()
  {
    return false;
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
    { "username",       required_argument,  NULL,      'u' },
    { "password",       required_argument,  NULL,      'p' },
    { "proto",          required_argument,  NULL,      'P' },
    { "server",         required_argument,  NULL,      's' },
    { "timeout",        required_argument,  NULL,      't' },
    { "compress",       required_argument,  NULL,      'c' },
    { "pk-password",    required_argument,  NULL,      'z' },
    { "proxy-host",     required_argument,  NULL,      'h' },
    { "proxy-port",     required_argument,  NULL,      'q' },
    { "proxy-username", required_argument,  NULL,      'U' },
    { "proxy-password", required_argument,  NULL,      'W' },
    { "eval",           no_argument,        NULL,      'e' },
    { NULL,             0,                  NULL,       0  }
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
	std::string privateKeyPassword;
	std::string proxyHost;
	std::string proxyPort;
	std::string proxyUsername;
	std::string proxyPassword;
	bool eval = false;

	int ch;

	while ((ch = getopt_long(argc, argv, "eu:p:P:s:t:c:z:h:q:U:W:", longopts, NULL)) != -1)
	  {
	    switch (ch)
	      {
	      case 'e':
		eval = true;
		break;
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
	      case 'z':
		privateKeyPassword = optarg;
		break;
	      case 'h':
		proxyHost = optarg;
		break;
	      case 'q':
		proxyPort = optarg;
		break;
	      case 'U':
		proxyUsername = optarg;
		break;
	      case 'W':
		proxyPassword = optarg;
		break;
	      default:
		goto usage;
	      }
	  }
	argc -= optind;
	argv += optind;

	Client::init_process();

	if (argc != 1)
	  goto usage;
	ProfileMerge pm(argv[0], "", true,
			ProfileParseLimits::MAX_LINE_SIZE, ProfileParseLimits::MAX_PROFILE_SIZE);
	if (pm.status() != ProfileMerge::MERGE_SUCCESS)
	  OPENVPN_THROW_EXCEPTION("merge config error: " << pm.status_string() << " : " << pm.error());

	ClientAPI::Config config;
	config.content = pm.profile_content();
	config.serverOverride = server;
	config.protoOverride = proto;
	config.connTimeout = timeout;
	config.compressionMode = compress;
	config.privateKeyPassword = privateKeyPassword;
	config.proxyHost = proxyHost;
	config.proxyPort = proxyPort;
	config.proxyUsername = proxyUsername;
	config.proxyPassword = proxyPassword;

	if (eval)
	  {
	    ClientAPI::EvalConfig eval = ClientAPI::OpenVPNClient::eval_config_static(config);
	    std::cout << "EVAL PROFILE" << std::endl;
	    std::cout << "error=" << eval.error << std::endl;
	    std::cout << "message=" << eval.message << std::endl;
	    std::cout << "userlockedUsername=" << eval.userlockedUsername << std::endl;
	    std::cout << "profileName=" << eval.profileName << std::endl;
	    std::cout << "friendlyName=" << eval.friendlyName << std::endl;
	    std::cout << "autologin=" << eval.autologin << std::endl;
	    std::cout << "externalPki=" << eval.externalPki << std::endl;
	    std::cout << "staticChallenge=" << eval.staticChallenge << std::endl;
	    std::cout << "staticChallengeEcho=" << eval.staticChallengeEcho << std::endl;
	    std::cout << "privateKeyPasswordRequired=" << eval.privateKeyPasswordRequired << std::endl;

	    for (size_t i = 0; i < eval.serverList.size(); ++i)
	      {
		const ClientAPI::ServerEntry& se = eval.serverList[i];
		std::cout << '[' << i << "] " << se.server << '/' << se.friendlyName << std::endl;
	      }
	  }
	else
	  {
	    Client client;
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
	  }
	return 0;
      }
    else
	goto usage;
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
  std::cout << "usage: cli [options] <config-file>" << std::endl;
  std::cout << "--eval, -e           : evaluate profile only" << std::endl;
  std::cout << "--username, -u       : username" << std::endl;
  std::cout << "--password, -p       : password" << std::endl;
  std::cout << "--proto, -P          : protocol override (udp|tcp)" << std::endl;
  std::cout << "--server, -s         : server override" << std::endl;
  std::cout << "--timeout, -t        : timeout" << std::endl;
  std::cout << "--compress, -c       : compression mode (yes|no|asym)" << std::endl;
  std::cout << "--pk-password, -z    : private key password" << std::endl;
  std::cout << "--proxy-host, -h     : HTTP proxy hostname/IP" << std::endl;
  std::cout << "--proxy-port, -q     : HTTP proxy port" << std::endl;
  std::cout << "--proxy-username, -U : HTTP proxy username" << std::endl;
  std::cout << "--proxy-password, -W : HTTP proxy password" << std::endl;
  std::cout << "" << std::endl;
  return 2;
}
