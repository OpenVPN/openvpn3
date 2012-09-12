#include <string>
#include <iostream>
#include <fstream>

#include <signal.h>

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/thread/thread.hpp>

#define OPENVPN_CORE_API_VISIBILITY_HIDDEN  // don't export core symbols

#include <openvpn/common/exception.hpp>

#include <client/ovpncli.cpp>

using namespace openvpn::ClientAPI;

class Client : public OpenVPNClient
{
private:
  virtual bool socket_protect(int socket)
  {
    std::cout << "*** socket_protect " << socket << std::endl;
    return true;
  }

  virtual void event(const Event& ev)
  {
    std::cout << "EVENT: " << ev.name << ' ' << ev.info << " err=" << ev.error << std::endl;
  }

  virtual void log(const LogInfo& log)
  {
    std::cout << "LOG: " << log.text;
  }

  virtual void external_pki_cert_request(ExternalPKICertRequest& certreq)
  {
    std::cout << "*** external_pki_cert_request" << std::endl;
    certreq.error = true;
    certreq.errorText = "external_pki_cert_request not implemented";
  }

  virtual void external_pki_sign_request(ExternalPKISignRequest& signreq)
  {
    std::cout << "*** external_pki_sign_request" << std::endl;
    signreq.error = true;
    signreq.errorText = "external_pki_sign_request not implemented";
  }
};

std::string read_text(const std::string& filename)
{
  std::ifstream ifs(filename.c_str());
  if (!ifs)
    OPENVPN_THROW_EXCEPTION("cannot open " << filename);
  const std::string str((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
  if (!ifs)
    OPENVPN_THROW_EXCEPTION("cannot read " << filename);
  return str;
}

Client *the_client = NULL;

void worker_thread()
{
  boost::asio::detail::signal_blocker signal_blocker; // signals should be handled by parent thread
  try {
    std::cout << "Thread starting..." << std::endl;
    Status connect_status = the_client->connect();
    if (connect_status.error)
      std::cerr << "connect error: " <<  connect_status.message << std::endl;
  }
  catch (const std::exception& e)
    {
      std::cerr << "Connect thread exception: " << e.what() << std::endl;
    }
  std::cout << "Thread finished" << std::endl;
}

void handler(int signum)
{
  switch (signum)
    {
    case SIGTERM:
    case SIGINT:
      std::cerr << "received stop signal " << signum << std::endl;
      if (the_client)
	the_client->stop();
      break;
    case SIGHUP:
      std::cerr << "received reconnect signal " << signum << std::endl;
      if (the_client)
	the_client->reconnect(2);
      break;
    default:
      std::cerr << "received unknown signal " << signum << std::endl;
      break;
    }
}

int main(int argc, char *argv[])
{
  try {
    if (argc >= 2)
      {
	Client::init_process();
	Client client;
	Config config;
	config.content = read_text(argv[1]);
	config.compressionMode = "yes";
	EvalConfig eval = client.eval_config(config);
	if (eval.error)
	  OPENVPN_THROW_EXCEPTION("eval config error: " << eval.message);
	if (eval.autologin)
	  {
	    if (argc > 2)
	      std::cout << "NOTE: creds were not needed" << std::endl;
	  }
	else
	  {
	    if (argc < 4)
	      OPENVPN_THROW_EXCEPTION("need creds");
	    ProvideCreds creds;
	    creds.username = argv[2];
	    creds.password = argv[3];
	    creds.replacePasswordWithSessionID = true;
	    Status creds_status = client.provide_creds(creds);
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
	return 0;
      }
    else
      {
	std::cerr << "OpenVPN Client (ovpncli)" << std::endl;
	std::cerr << "usage: " << argv[0] << " <config-file> [user] [password]" << std::endl;
	return 2;
      }
  }
  catch (const std::exception& e)
    {
      the_client = NULL;
      std::cerr << "Main thread exception: " << e.what() << std::endl;
      return 1;
    }
}
