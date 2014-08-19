#include <iostream>
#include <string>

#include <boost/bind.hpp>

#define OPENVPN_LOG_SSL(x) OPENVPN_LOG(x)

// debug settings (production setting in parentheses)

#define OPENVPN_INSTRUMENTATION        // include debug instrumentation for classes (define)
#define OPENVPN_DEBUG_UDPLINK 2        // debug level for UDP link object (2)
#define OPENVPN_DEBUG_PROTO 2          // increases low-level protocol verbosity (1)
#define OPENVPN_DEBUG_SERVPROTO        // shows packets in/out (comment out)

#include <openvpn/log/logsimple.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/thread.hpp>
#include <openvpn/common/thread.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/asiosignal.hpp>
#include <openvpn/common/signal.hpp>
#include <openvpn/common/asiodispatch.hpp>
#include <openvpn/init/initprocess.hpp>
#include <openvpn/frame/frame_init.hpp>
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/ssl/sslchoose.hpp>

#include <openvpn/transport/server/udpserv.hpp>
#include <openvpn/server/servproto.hpp>

using namespace openvpn;

class MySessionStats : public SessionStats
{
public:
  typedef boost::intrusive_ptr<MySessionStats> Ptr;

  virtual void error(const size_t err_type, const std::string* text=NULL)
  {
    if (text)
      OPENVPN_LOG("ERROR: " << Error::name(err_type) << ": " << *text);
    else
      OPENVPN_LOG("ERROR: " << Error::name(err_type));
  }
};

struct MyTransportParent : public TransportServerParent
{
};

class ServerThread : public RC<thread_unsafe_refcount>
{
public:
  typedef boost::intrusive_ptr<ServerThread> Ptr;

  struct Config
  {
    TransportServerFactory::Ptr transport_factory;
  };

  ServerThread(boost::asio::io_service& io_service_arg,
	       const Config& config_arg)
    : io_service(io_service_arg),
      config(config_arg),
      halt(false)
  {
    transport_server = config.transport_factory->new_server_obj(io_service, transport_parent);
  }

  void start()
  {
    if (!halt)
      {
	transport_server->start();
	OPENVPN_LOG("Local endpoint: " << transport_server->local_endpoint_info());
      }
  }

  void stop()
  {
    if (!halt)
      {
	halt = true;
	OPENVPN_LOG("ServerThread::stop called"); // fixme
	transport_server->stop();
      }
  }

  void thread_safe_stop()
  {
    if (!halt)
      {
	OPENVPN_LOG("ServerThread::thread_safe_stop called"); // fixme
	io_service.post(asio_dispatch_post(&ServerThread::stop, this));
      }
  }

private:
  boost::asio::io_service& io_service;
  Config config;
  bool halt;

  MyTransportParent transport_parent;
  TransportServer::Ptr transport_server;
};

class MyRunContext : public RC<thread_safe_refcount>
{
public:
  typedef boost::intrusive_ptr<MyRunContext> Ptr;

  MyRunContext(ServerThread::Ptr& serv_arg)
    : io_service(1),
      signals(new ASIOSignals(io_service)),
      serv(serv_arg),
      halt(false)
  {
    signals->register_signals(asio_dispatch_signal(&MyRunContext::signal, this));
  }

  void run()
  {
    if (!halt)
      {
	io_service.run();
      }
  }

  void cancel()
  {
    if (!halt)
      {
	halt = true;
	OPENVPN_LOG("MyRunContext::cancel called"); // fixme
	io_service.post(asio_dispatch_post(&ASIOSignals::cancel, signals.get()));
	if (serv)
	  serv->thread_safe_stop();
      }
  }

private:
  void signal(const boost::system::error_code& error, int signal_number)
  {
    if (!error && !halt)
      {
	OPENVPN_LOG("ASIO SIGNAL " << signal_number); // fixme
	cancel();
      }
  }

  boost::asio::io_service io_service;
  ASIOSignals::Ptr signals;
  ServerThread::Ptr& serv;

  bool halt;
};

void work(const char *config_fn, ServerThread::Ptr& serv)
{
  typedef ServerProto<SSLLib::RandomAPI, SSLLib::CryptoAPI, SSLLib::SSLAPI>::Factory ServerProtoFactory;

  // set global PolarSSL debug level
#if defined(USE_POLARSSL) && defined(OPENVPN_SSL_DEBUG)
  debug_set_threshold(OPENVPN_SSL_DEBUG);
#endif

  // current time
  Time now;

  // parse options from server config file
  OptionList opt = OptionList::parse_from_config_static(read_text(config_fn), NULL);

  // initialize the Asio io_service object (for worker thread)
  boost::asio::io_service io_service(1); // concurrency hint=1

  // initialize RNG/PRNG
  SSLLib::RandomAPI::Ptr rng(new SSLLib::RandomAPI());
  PRNG<SSLLib::RandomAPI, SSLLib::CryptoAPI>::Ptr prng(new PRNG<SSLLib::RandomAPI, SSLLib::CryptoAPI>("SHA1", rng, 16));

  // initialize frame
  Frame::Ptr frame = frame_init();

  // initialize statistics
  SessionStats::Ptr stats = new MySessionStats();

  // initialize SSL
  SSLLib::SSLAPI::Config ssl;
  ssl.frame = frame;
  ssl.flags = SSLConst::LOG_VERIFY_STATUS;
#ifdef OPENVPN_SSL_DEBUG
  ssl.ssl_debug_level = OPENVPN_SSL_DEBUG;
#endif
#if defined(USE_POLARSSL) || defined(USE_POLARSSL_APPLE_HYBRID)
  ssl.rng = rng;
#endif
  ssl.load(opt);
  if (!ssl.mode.is_server())
    throw option_error("only server configuration supported");

  // initialize OpenVPN protocol config extras
  ProtoContextOptions pco;

  // initialize main OpenVPN protocol config
  ServerProtoFactory::ProtoConfig::Ptr pcfg(new ServerProtoFactory::ProtoConfig());
  pcfg->load(opt, pco, -1);
  pcfg->ssl_ctx.reset(new SSLLib::SSLAPI(ssl));
  pcfg->set_protocol(Protocol(Protocol::UDP));
  pcfg->frame = frame;
  pcfg->now = &now;
  pcfg->rng = rng;
  pcfg->prng = prng;

  // initialize factory to create client instance objects
  ServerProtoFactory::Ptr spf(new ServerProtoFactory(io_service, *pcfg));
  spf->proto_context_config = pcfg;
  spf->stats = stats;

  // initialize transport layer factory
  UDPTransport::ServerConfig::Ptr usc(UDPTransport::ServerConfig::new_obj());
  usc->local_ip = opt.get("local", 1, 64);
  usc->local_port = opt.get("port", 1, 16);
  usc->frame = frame;
  usc->stats = stats;
  usc->client_instance_factory = spf;

  // set up server config
  ServerThread::Config server_config;
  server_config.transport_factory = usc;

  // instantiate top-level server session
  serv.reset(new ServerThread(io_service, server_config));

  // listen for VPN clients
  serv->start(); // queue parallel async reads

  // run i/o reactor
  try {
    io_service.run();
    OPENVPN_LOG("Worker thread event loop terminated normally"); // fixme
  }
  catch (...)
    {
      OPENVPN_LOG("Worker thread event loop hit exception"); // fixme
      serv->stop();      // on exception, stop server,
      io_service.poll(); //   execute completion handlers,
      throw;
    }
}

void worker_thread(const char *config_fn, ServerThread::Ptr& serv, MyRunContext::Ptr run_context)
{
  SignalBlocker signal_blocker( // these signals should be handled by parent thread
			       Signal::F_SIGINT|
			       Signal::F_SIGTERM|
			       Signal::F_SIGHUP|
			       Signal::F_SIGUSR1|
			       Signal::F_SIGUSR2);
  try {
    OPENVPN_LOG("WORKER THREAD STARTING");
    work(config_fn, serv);
    OPENVPN_LOG("WORKER THREAD finishing normally"); // fixme
  }
  catch (const std::exception& e)
    {
      OPENVPN_LOG("Worker thread exception: " << e.what());
    }
  run_context->cancel();
  OPENVPN_LOG("WORKER THREAD exiting"); // fixme
}

int main(int argc, char* argv[])
{
  int ret = 0;
  boost::thread* thread = NULL;

  // process-wide initialization
  InitProcess::init();

  try {
    if (argc >= 2)
      {
	// start worker thread
	ServerThread::Ptr serv;
	MyRunContext::Ptr run_context = new MyRunContext(serv);
	const char *config_fn = argv[1];
	thread = new boost::thread(boost::bind(&worker_thread, config_fn, boost::ref(serv), run_context));

	// wait for worker to exit
	run_context->run();
	thread->join();
	OPENVPN_LOG("worker thread exited, join returned"); // fixme
      }
    else
      {
	OPENVPN_LOG("OpenVPN Server (C++ core)");
        OPENVPN_LOG("usage: " << argv[0] << " <config-file>");
	ret = 2;
      }
  }
  catch (const std::exception& e)
    {
      OPENVPN_LOG("Main thread exception: " << e.what());
      ret = 1;
    }

  delete thread;
  InitProcess::uninit();
  return ret;
}
