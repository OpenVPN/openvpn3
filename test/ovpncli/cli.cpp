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

// OpenVPN 3 test client

#include <stdlib.h> // for atoi

#include <string>
#include <iostream>
#include <thread>
#include <memory>
#include <mutex>

// If enabled, don't direct ovpn3 core logging to
// ClientAPI::OpenVPNClient::log() virtual method.
// Instead, logging will go to LogBaseSimple::log().
// In this case, make sure to define:
//   LogBaseSimple log;
// at the top of your main() function to receive
// log messages from all threads.
// Also, note that the OPENVPN_LOG_GLOBAL setting
// MUST be consistent across all compilation units.
#ifdef OPENVPN_USE_LOG_BASE_SIMPLE
#define OPENVPN_LOG_GLOBAL // use global rather than thread-local log object pointer
#include <openvpn/log/logbasesimple.hpp>
#endif

// don't export core symbols
#define OPENVPN_CORE_API_VISIBILITY_HIDDEN

// should be included before other openvpn includes,
// with the exception of openvpn/log includes
#include <client/ovpncli.cpp>

#include <openvpn/common/platform.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/signal.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/getopt.hpp>
#include <openvpn/common/getpw.hpp>
#include <openvpn/common/cleanup.hpp>
#include <openvpn/time/timestr.hpp>
#include <openvpn/ssl/peerinfo.hpp>

#if defined(OPENVPN_PLATFORM_WIN)
#include <openvpn/win/console.hpp>
#endif

using namespace openvpn;

namespace {
  OPENVPN_SIMPLE_EXCEPTION(usage);
}

class Client : public ClientAPI::OpenVPNClient
{
public:
  bool is_dynamic_challenge() const
  {
    return !dc_cookie.empty();
  }

  std::string dynamic_challenge_cookie()
  {
    return dc_cookie;
  }

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
    if (ev.fatal)
      std::cout << " [FATAL-ERR]";
    else if (ev.error)
      std::cout << " [ERR]";
    std::cout << std::endl;
    if (ev.name == "DYNAMIC_CHALLENGE")
      {
	dc_cookie = ev.info;

	ClientAPI::DynamicChallenge dc;
	if (ClientAPI::OpenVPNClient::parse_dynamic_challenge(ev.info, dc)) {
	  std::cout << "DYNAMIC CHALLENGE" << std::endl;
	  std::cout << "challenge: " << dc.challenge << std::endl;
	  std::cout << "echo: " << dc.echo << std::endl;
	  std::cout << "responseRequired: " << dc.responseRequired << std::endl;
	  std::cout << "stateID: " << dc.stateID << std::endl;
	}
      }
  }

  virtual void log(const ClientAPI::LogInfo& log)
  {
    std::lock_guard<std::mutex> lock(log_mutex);
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

  std::mutex log_mutex;
  std::string dc_cookie;
};

static Client *the_client = nullptr; // GLOBAL

static void worker_thread()
{
  asio::detail::signal_blocker signal_blocker; // signals should be handled by parent thread
  try {
    std::cout << "Thread starting..." << std::endl;
    ClientAPI::Status connect_status = the_client->connect();
    if (connect_status.error)
      {
	std::cout << "connect error: ";
	if (!connect_status.status.empty())
	  std::cout << connect_status.status << ": ";
	std::cout << connect_status.message << std::endl;
      }
  }
  catch (const std::exception& e)
    {
      std::cout << "Connect thread exception: " << e.what() << std::endl;
    }
  std::cout << "Thread finished" << std::endl;
}

static void print_stats(const Client& client)
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

#if !defined(OPENVPN_PLATFORM_WIN)
static void handler(int signum)
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
	the_client->reconnect(0);
      break;
    case SIGUSR1:
      if (the_client)
	print_stats(*the_client);
      break;
    case SIGUSR2:
      {
	// toggle pause/resume
	static bool hup = false;
	std::cout << "received pause/resume toggle signal " << signum << std::endl;
	if (the_client)
	  {
	    if (hup)
	      the_client->resume();
	    else
	      the_client->pause("pause-resume-signal");
	    hup = !hup;
	  }
      }
      break;
    default:
      std::cout << "received unknown signal " << signum << std::endl;
      break;
    }
}
#endif

static std::string read_profile(const char *fn, const std::string* profile_content)
{
  if (!string::strcasecmp(fn, "http") && profile_content && !profile_content->empty())
    return *profile_content;
  else
    {
      ProfileMerge pm(fn, "ovpn", "", ProfileMerge::FOLLOW_FULL,
		      ProfileParseLimits::MAX_LINE_SIZE, ProfileParseLimits::MAX_PROFILE_SIZE);
      if (pm.status() != ProfileMerge::MERGE_SUCCESS)
	OPENVPN_THROW_EXCEPTION("merge config error: " << pm.status_string() << " : " << pm.error());
      return pm.profile_content();
    }
}

int openvpn_client(int argc, char *argv[], const std::string* profile_content)
{
  static const struct option longopts[] = {
    { "username",       required_argument,  nullptr,      'u' },
    { "password",       required_argument,  nullptr,      'p' },
    { "response",       required_argument,  nullptr,      'r' },
    { "dc",             required_argument,  nullptr,      'D' },
    { "proto",          required_argument,  nullptr,      'P' },
    { "ipv6",           required_argument,  nullptr,      '6' },
    { "server",         required_argument,  nullptr,      's' },
    { "timeout",        required_argument,  nullptr,      't' },
    { "compress",       required_argument,  nullptr,      'c' },
    { "pk-password",    required_argument,  nullptr,      'z' },
    { "tvm-override",   required_argument,  nullptr,      'M' },
    { "proxy-host",     required_argument,  nullptr,      'h' },
    { "proxy-port",     required_argument,  nullptr,      'q' },
    { "proxy-username", required_argument,  nullptr,      'U' },
    { "proxy-password", required_argument,  nullptr,      'W' },
    { "peer-info",      required_argument,  nullptr,      'I' },
    { "gremlin",        required_argument,  nullptr,      'G' },
    { "proxy-basic",    no_argument,        nullptr,      'B' },
    { "alt-proxy",      no_argument,        nullptr,      'A' },
    { "dco",            no_argument,        nullptr,      'd' },
    { "eval",           no_argument,        nullptr,      'e' },
    { "self-test",      no_argument,        nullptr,      'T' },
    { "cache-password", no_argument,        nullptr,      'C' },
    { "no-cert",        no_argument,        nullptr,      'x' },
    { "force-aes-cbc",  no_argument,        nullptr,      'f' },
    { "google-dns",     no_argument,        nullptr,      'g' },
    { "persist-tun",    no_argument,        nullptr,      'j' },
    { "def-keydir",     required_argument,  nullptr,      'k' },
    { "merge",          no_argument,        nullptr,      'm' },
    { "version",        no_argument,        nullptr,      'v' },
    { "auto-sess",      no_argument,        nullptr,      'a' },
    { "ssl-debug",      required_argument,  nullptr,       1  },
    { nullptr,          0,                  nullptr,       0  }
  };

  int ret = 0;
  auto cleanup = Cleanup([]() {
      the_client = nullptr;
    });
  std::unique_ptr<std::thread> thread;

  try {
    if (argc >= 2)
      {
	std::string username;
	std::string password;
	std::string response;
	std::string dynamicChallengeCookie;
	std::string proto;
	std::string ipv6;
	std::string server;
	int timeout = 0;
	std::string compress;
	std::string privateKeyPassword;
	std::string tlsVersionMinOverride;
	std::string proxyHost;
	std::string proxyPort;
	std::string proxyUsername;
	std::string proxyPassword;
	std::string peer_info;
	std::string gremlin;
	bool eval = false;
	bool self_test = false;
	bool cachePassword = false;
	bool disableClientCert = false;
	bool proxyAllowCleartextAuth = false;
	int defaultKeyDirection = -1;
	bool forceAesCbcCiphersuites = false;
	int sslDebugLevel = 0;
	bool googleDnsFallback = false;
	bool autologinSessions = false;
	bool tunPersist = false;
	bool merge = false;
	bool version = false;
	bool altProxy = false;
	bool dco = false;

	int ch;
	optind = 1;
	while ((ch = getopt_long(argc, argv, "BAdeTCxfgjmvau:p:r:D:P:6:s:t:c:z:M:h:q:U:W:I:G:k:", longopts, nullptr)) != -1)
	  {
	    switch (ch)
	      {
	      case 1:
		sslDebugLevel = ::atoi(optarg);
		break;
	      case 'e':
		eval = true;
		break;
	      case 'T':
		self_test = true;
		break;
	      case 'C':
		cachePassword = true;
		break;
	      case 'x':
		disableClientCert = true;
		break;
	      case 'u':
		username = optarg;
		break;
	      case 'p':
		password = optarg;
		break;
	      case 'r':
		response = optarg;
		break;
	      case 'P':
		proto = optarg;
		break;
	      case '6':
		ipv6 = optarg;
		break;
	      case 's':
		server = optarg;
		break;
	      case 't':
		timeout = ::atoi(optarg);
		break;
	      case 'c':
		compress = optarg;
		break;
	      case 'z':
		privateKeyPassword = optarg;
		break;
	      case 'M':
		tlsVersionMinOverride = optarg;
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
	      case 'B':
		proxyAllowCleartextAuth = true;
		break;
	      case 'A':
		altProxy = true;
		break;
	      case 'd':
		dco = true;
		break;
	      case 'f':
		forceAesCbcCiphersuites = true;
		break;
	      case 'g':
		googleDnsFallback = true;
		break;
	      case 'a':
		autologinSessions = true;
		break;
	      case 'j':
		tunPersist = true;
		break;
	      case 'm':
		merge = true;
		break;
	      case 'v':
		version = true;
		break;
	      case 'k':
		{
		  const std::string arg = optarg;
		  if (arg == "bi" || arg == "bidirectional")
		    defaultKeyDirection = -1;
		  else if (arg == "0")
		    defaultKeyDirection = 0;
		  else if (arg == "1")
		    defaultKeyDirection = 1;
		  else
		    OPENVPN_THROW_EXCEPTION("bad default key-direction: " << arg);
		}
		break;
	      case 'D':
		dynamicChallengeCookie = optarg;
		break;
	      case 'I':
		peer_info = optarg;
		break;
	      case 'G':
		gremlin = optarg;
		break;
	      default:
		throw usage();
	      }
	  }
	argc -= optind;
	argv += optind;

	if (version)
	  {
	    std::cout << "OpenVPN cli 1.0" << std::endl;
	    std::cout << ClientAPI::OpenVPNClient::platform() << std::endl;
	    std::cout << ClientAPI::OpenVPNClient::copyright() << std::endl;
	  }
	else if (self_test)
	  {
	    std::cout << ClientAPI::OpenVPNClient::crypto_self_test();
	  }
	else if (merge)
	  {
	    if (argc != 1)
	      throw usage();
	    std::cout << read_profile(argv[0], profile_content);
	  }
	else
	  {
	    if (argc < 1)
	      throw usage();

	    bool retry;
	    do {
	      retry = false;

	      ClientAPI::Config config;
	      config.guiVersion = "cli 1.0";
	      config.content = read_profile(argv[0], profile_content);
	      for (int i = 1; i < argc; ++i)
		{
		  config.content += argv[i];
		  config.content += '\n';
		}
	      config.serverOverride = server;
	      config.protoOverride = proto;
	      config.connTimeout = timeout;
	      config.compressionMode = compress;
	      config.ipv6 = ipv6;
	      config.privateKeyPassword = privateKeyPassword;
	      config.tlsVersionMinOverride = tlsVersionMinOverride;
	      config.disableClientCert = disableClientCert;
	      config.proxyHost = proxyHost;
	      config.proxyPort = proxyPort;
	      config.proxyUsername = proxyUsername;
	      config.proxyPassword = proxyPassword;
	      config.proxyAllowCleartextAuth = proxyAllowCleartextAuth;
	      config.altProxy = altProxy;
	      config.dco = dco;
	      config.defaultKeyDirection = defaultKeyDirection;
	      config.forceAesCbcCiphersuites = forceAesCbcCiphersuites;
	      config.sslDebugLevel = sslDebugLevel;
	      config.googleDnsFallback = googleDnsFallback;
	      config.autologinSessions = autologinSessions;
	      config.tunPersist = tunPersist;
	      config.gremlinConfig = gremlin;
	      config.info = true;
	      PeerInfo::Set::parse_csv(peer_info, config.peerInfo);

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
		  std::cout << "allowPasswordSave=" << eval.allowPasswordSave << std::endl;

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
		      if (password.empty() && dynamicChallengeCookie.empty())
			password = get_password("Password:");
		      creds.username = username;
		      creds.password = password;
		      creds.response = response;
		      creds.dynamicChallengeCookie = dynamicChallengeCookie;
		      creds.replacePasswordWithSessionID = true;
		      creds.cachePassword = cachePassword;
		      ClientAPI::Status creds_status = client.provide_creds(creds);
		      if (creds_status.error)
			OPENVPN_THROW_EXCEPTION("creds error: " << creds_status.message);
		    }

		  std::cout << "CONNECTING..." << std::endl;

#if !defined(OPENVPN_PLATFORM_WIN)
		  // start connect thread
		  the_client = &client;
		  thread.reset(new std::thread([]() {
			worker_thread();
		      }));

		  {
		    // catch signals that might occur while we're in join()
		    Signal signal(handler, Signal::F_SIGINT|Signal::F_SIGTERM|Signal::F_SIGHUP|Signal::F_SIGUSR1|Signal::F_SIGUSR2);

		    // wait for connect thread to exit
		    thread->join();
		  }
		  the_client = nullptr;
#else
		  // Set Windows title bar
		  const std::string title_text = "F2:Stats F3:Reconnect F4:Stop F5:Pause";
		  Win::Console::Title title(ClientAPI::OpenVPNClient::platform() + "     " + title_text);
		  Win::Console::Input console;

		  // start connect thread
		  volatile bool thread_exit = false;
		  the_client = &client;
		  thread.reset(new std::thread([&thread_exit]() {
			worker_thread();
			thread_exit = true;
		      }));

		  // wait for connect thread to exit, also check for keypresses
		  while (!thread_exit)
		    {
		      while (true)
			{
			  const unsigned int c = console.get();
			  if (!c)
			    break;
			  else if (c == 0x3C) // F2
			    print_stats(*the_client);
			  else if (c == 0x3D) // F3
			    the_client->reconnect(0);
			  else if (c == 0x3E) // F4
			    the_client->stop();
			  else if (c == 0x3F) // F5
			    the_client->pause("user-pause");
			}
		      Sleep(1000);
		    }

		  // wait for connect thread to exit
		  thread->join();

		  the_client = nullptr;
#endif

		  // Get dynamic challenge response
		  if (client.is_dynamic_challenge())
		    {
		      std::cout << "ENTER RESPONSE" << std::endl;
		      std::getline(std::cin, response);
		      if (!response.empty())
			{
			  dynamicChallengeCookie = client.dynamic_challenge_cookie();
			  retry = true;
			}
		    }
		  else
		    {
		      // print closing stats
		      print_stats(client);
		    }
		}
	    } while (retry);
	  }
      }
    else
      throw usage();
  }
  catch (const usage&)
    {
      std::cout << "OpenVPN Client (ovpncli)" << std::endl;
      std::cout << "usage: cli [options] <config-file> [extra-config-directives...]" << std::endl;
      std::cout << "--version, -v        : show version info" << std::endl;
      std::cout << "--eval, -e           : evaluate profile only (standalone)" << std::endl;
      std::cout << "--merge, -m          : merge profile into unified format (standalone)" << std::endl;
      std::cout << "--username, -u       : username" << std::endl;
      std::cout << "--password, -p       : password" << std::endl;
      std::cout << "--response, -r       : static response" << std::endl;
      std::cout << "--dc, -D             : dynamic challenge/response cookie" << std::endl;
      std::cout << "--proto, -P          : protocol override (udp|tcp)" << std::endl;
      std::cout << "--server, -s         : server override" << std::endl;
      std::cout << "--ipv6, -6           : IPv6 (yes|no|default)" << std::endl;
      std::cout << "--timeout, -t        : timeout" << std::endl;
      std::cout << "--compress, -c       : compression mode (yes|no|asym)" << std::endl;
      std::cout << "--pk-password, -z    : private key password" << std::endl;
      std::cout << "--tvm-override, -M   : tls-version-min override (disabled, default, tls_1_x)" << std::endl;
      std::cout << "--proxy-host, -h     : HTTP proxy hostname/IP" << std::endl;
      std::cout << "--proxy-port, -q     : HTTP proxy port" << std::endl;
      std::cout << "--proxy-username, -U : HTTP proxy username" << std::endl;
      std::cout << "--proxy-password, -W : HTTP proxy password" << std::endl;
      std::cout << "--proxy-basic, -B    : allow HTTP basic auth" << std::endl;
      std::cout << "--alt-proxy, -A      : enable alternative proxy module" << std::endl;
      std::cout << "--dco, -d            : enable data channel offload" << std::endl;
      std::cout << "--cache-password, -C : cache password" << std::endl;
      std::cout << "--no-cert, -x        : disable client certificate" << std::endl;
      std::cout << "--def-keydir, -k     : default key direction ('bi', '0', or '1')" << std::endl;
      std::cout << "--force-aes-cbc, -f  : force AES-CBC ciphersuites" << std::endl;
      std::cerr << "--ssl-debug          : SSL debug level" << std::endl;
      std::cout << "--google-dns, -g     : enable Google DNS fallback" << std::endl;
      std::cout << "--auto-sess, -a      : request autologin session" << std::endl;
      std::cout << "--persist-tun, -j    : keep TUN interface open across reconnects" << std::endl;
      std::cout << "--peer-info, -I      : peer info key/value list in the form K1=V1,K2=V2,..." << std::endl;
      std::cout << "--gremlin, -G        : gremlin info (send_delay_ms, recv_delay_ms, send_drop_prob, recv_drop_prob)" << std::endl;
      ret = 2;
    }
  return ret;
}

#ifndef OPENVPN_OVPNCLI_OMIT_MAIN

int main(int argc, char *argv[])
{
  int ret = 0;

#ifdef OPENVPN_LOG_LOGBASE_H
  LogBaseSimple log;
#endif

  try {
    Client::init_process();
    ret = openvpn_client(argc, argv, nullptr);
  }
  catch (const std::exception& e)
    {
      std::cout << "Main thread exception: " << e.what() << std::endl;
      ret = 1;
    }  
  Client::uninit_process();
  return ret;
}

#endif
