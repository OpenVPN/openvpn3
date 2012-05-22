#include <iostream>
#include <string>

#include <boost/bind.hpp>
#include <boost/unordered_map.hpp>
#include <boost/assert.hpp>

#include <openvpn/log/logsimple.hpp>

// debug settings

#define OPENVPN_DEBUG
#define OPENVPN_ENABLE_ASSERT
#define OPENVPN_DEBUG_PROTO // fixme
#define OPENVPN_DEBUG_TUN     2
#define OPENVPN_DEBUG_UDPLINK 2
#define OPENVPN_DEBUG_TCPLINK 2
//#define OPENVPN_DEBUG_COMPRESS
//#define OPENVPN_DEBUG_PACKET_ID

// log SSL handshake messages
#define OPENVPN_LOG_SSL(x) OPENVPN_LOG(x)

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/frame/frame_init.hpp>

#include <openvpn/common/thread.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/signal.hpp>
#include <openvpn/common/asiodispatch.hpp>
#include <openvpn/init/initprocess.hpp>

#include <openvpn/common/backref.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/addr/cidrmap.hpp>
#include <openvpn/transport/udplink.hpp>
#include <openvpn/transport/transmap.hpp>

using namespace openvpn;

class TransportBase;

class ClientInstanceBase : public RC<thread_unsafe_refcount>
{
public:
  typedef boost::intrusive_ptr<ClientInstanceBase> Ptr;

  virtual void start() = 0;
  virtual void stop() = 0;

  virtual void transport_recv(BufferAllocated& buf) = 0;
  virtual void tun_recv(BufferAllocated& buf) = 0;

  BackRef<TransportBase> backref;
};

class ClientInstanceFactory : public RC<thread_unsafe_refcount>
{
public:
  typedef boost::intrusive_ptr<ClientInstanceFactory> Ptr;

  virtual ClientInstanceBase::Ptr new_client_instance() = 0;
  virtual bool validate_initial_packet(const Buffer& net_buf) = 0;
};

class RouterBase;

class TransportBase : public RC<thread_unsafe_refcount>
{
public:
  typedef boost::intrusive_ptr<TransportBase> Ptr;

  void set_client_instance_factory(ClientInstanceFactory* cif)
  {
    client_factory.reset(cif);
  }

  // called by parent (RouterBase)
  virtual void start() = 0;
  virtual void stop() = 0;
  virtual void to_transport(ClientInstanceBase* cib, BufferAllocated& buf) = 0;

  // called by ClientInstanceBase
  virtual const std::string& client_info(const ClientInstanceBase* cib) const = 0;
  virtual void client_stop_notify(ClientInstanceBase* cib) = 0;
  virtual bool to_tun(ClientInstanceBase* cib, BufferAllocated& buf) = 0;
  virtual bool transport_send_const(ClientInstanceBase* cib, const Buffer& buf) = 0;
  virtual bool transport_send(ClientInstanceBase* cib, BufferAllocated& buf) = 0;

  BackRef<RouterBase> backref;

private:
  ClientInstanceFactory::Ptr client_factory;
};

class RouterBase : public RC<thread_unsafe_refcount> {
public:
  typedef boost::intrusive_ptr<RouterBase> Ptr;

  virtual void start() = 0;
  virtual void stop() = 0;

  virtual bool to_tun(ClientInstanceBase* cib, BufferAllocated& buf) = 0;
  virtual bool to_transport(BufferAllocated& buf) = 0;
};

template <typename TRANSPORT_ADDR>
class TransportUDP : public TransportBase
{
  friend class UDPTransport::Link<TransportUDP*>; // calls udp_read_handler
  typedef UDPTransport::Link<TransportUDP*> LinkImpl;

  typedef TransportMap::Endpoint<TRANSPORT_ADDR> Endpoint;

  class Value : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<Value> Ptr;

    bool defined() const
    {
      return bool(client_instance);
    }

    void stop()
    {
      if (client_instance)
	{
	  ClientInstanceBase::Ptr ci;
	  ci.swap(client_instance);
	  ci->stop();
	  ci->backref.reset();
	}
    }

    std::string client_info;

    ClientInstanceBase::Ptr client_instance;
  };

public:
  class Config : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<Config> Ptr;

    Config() : reuse_addr(false) {}

    std::string local_addr;
    std::string local_port;
    bool reuse_addr;
    Frame::Ptr frame;
    SessionStats::Ptr stats;
  };

  TransportUDP(boost::asio::io_service& io_service_arg,
	       const Config& config_arg)
    : io_service(io_service_arg),
      config(config_arg),
      client_info_undef("CLIENT_INFO_UNDEF")
  {
  }

  virtual void start()
  {
  }

  virtual void stop()
  {
  }

  virtual void to_transport(ClientInstanceBase* cib, BufferAllocated& buf)
  {
  }

  // called by ClientInstanceBase

  virtual const std::string& client_info(const ClientInstanceBase* cib) const
  {
    Value* vp = cib->backref.value<Value>();
    if (vp)
      return vp.client_info;
    else
      return client_info_undef;
  }

  virtual void client_stop_notify(ClientInstanceBase* cib)
  {
  }

  virtual bool to_tun(ClientInstanceBase* cib, BufferAllocated& buf)
  {
    return false;
  }

  virtual bool transport_send_const(ClientInstanceBase* cib, const Buffer& buf)
  {
    return false;
  }

  virtual bool transport_send(ClientInstanceBase* cib, BufferAllocated& buf)
  {
    return false;
  }

private:
  void udp_read_handler(UDPTransport::PacketFrom::SPtr& pfp) // called by LinkImpl
  {
  }

  std::string client_info_undef;

  Config config;

  boost::asio::io_service& io_service;
  boost::asio::ip::udp::socket socket;
  typename LinkImpl::Ptr impl;
  bool halt;

  // clients, segregated by auth status
  TransportMap::Map<Endpoint, Value> pre_auth;
  TransportMap::Map<Endpoint, Value> post_auth;
};

template <typename VPN_ADDR>
class Router : public RouterBase
{
  typedef CIDRMap::Route<VPN_ADDR> Route;

public:
  void add_transport(const std::string& key, TransportBase* transport)
  {
    transport_map[key] = transport;
  }

private:
  ClientInstanceFactory::Ptr client_factory;
  boost::unordered_map<std::string, TransportBase::Ptr> transport_map;
  CIDRMap::RoutingTable<Route, ClientInstanceBase::Ptr> routing_table;
};

///////

class MyClientInstance : public ClientInstanceBase
{
public:
  typedef boost::intrusive_ptr<MyClientInstance> Ptr;

  virtual void start()
  {
    if (backref.defined())
      std::cout << "MyClientInstance.start from=" << backref.ref()->client_info(this) << std::endl;
  }

  virtual void transport_recv(BufferAllocated& buf)
  {
    if (backref.defined())
      std::cout << "MyClientInstance.transport_recv from=" << backref.ref()->client_info(this)
		<< " size=" << buf.size() << std::endl;
  }

  virtual void tun_recv(BufferAllocated& buf)
  {
  }

  virtual void stop()
  {
    if (backref.defined())
      std::cout << "MyClientInstance.start from=" << backref.ref()->client_info(this) << std::endl;
  }
};

class MyClientFactory : public ClientInstanceFactory
{
public:
  virtual ClientInstanceBase::Ptr new_client_instance()
  {
    MyClientInstance::Ptr ci(new MyClientInstance());
    return ci;
  }

  virtual bool validate_initial_packet(const Buffer& net_buf)
  {
    return true;
  }
};

class ServerThread : public RC<thread_unsafe_refcount>
{
public:
  typedef boost::intrusive_ptr<ServerThread> Ptr;

  struct Config
  {
    ClientInstanceFactory::Ptr client_factory;
    RouterBase::Ptr router;
  };

  ServerThread(boost::asio::io_service& io_service_arg,
	       const Config& config_arg)
    : io_service(io_service_arg),
      config(config_arg)
  {
  }

  void start()
  {
    config.router->start();
  }

  void stop()
  {
  }

  void thread_safe_stop()
  {
  }

  virtual bool to_tun(ClientInstanceBase* cib, BufferAllocated& buf)
  {
    return false;
  }

  virtual bool to_transport(BufferAllocated& buf)
  {
    return false;
  }

private:
  boost::asio::io_service& io_service;
  Config config;
};

class MyRunContext : public RC<thread_safe_refcount>
{
public:
  typedef boost::intrusive_ptr<MyRunContext> Ptr;

  MyRunContext(ServerThread::Ptr& serv_arg)
    : io_service(1),
      signals(new ASIOSignals(io_service)),
      serv(serv_arg)
  {
    signals->register_signals(asio_dispatch_signal(&MyRunContext::stop_signal, this));
  }

  void run()
  {
    io_service.run();
  }

  void cancel()
  {
    io_service.post(asio_dispatch_post(&ASIOSignals::cancel, signals.get()));
  }

private:
  void stop_signal(const boost::system::error_code& error, int signal_number)
  {
    if (!error)
      {
	if (serv)
	  serv->thread_safe_stop();
      }
  }

  boost::asio::io_service io_service;
  ASIOSignals::Ptr signals;
  ServerThread::Ptr& serv;
};

void work(const char *config_fn, ServerThread::Ptr& serv)
{
  // parse options from server config file
  OptionList opt = OptionList::parse_from_config_static(read_text(config_fn));

  // set up server config
  ServerThread::Config server_config;

  // initialize the Asio io_service object (for worker thread)
  boost::asio::io_service io_service(1); // concurrency hint=1

  // instantiate top-level server session
  serv.reset(new ServerThread(io_service, server_config));

  // start VPN
  serv->start(); // queue parallel async reads

  // run i/o reactor
  try {
    io_service.run();
  }
  catch (const std::exception&)
    {
      serv->stop();      // on exception, stop server,
      io_service.poll(); //   execute completion handlers,
      throw;             //   and rethrow exception
    }
}

void worker_thread(const char *config_fn, ServerThread::Ptr& serv, MyRunContext::Ptr run_context)
{
  boost::asio::detail::signal_blocker signal_blocker; // signals should be handled by parent thread
  try {
    std::cout << "WORKER THREAD STARTING" << std::endl;
    work(config_fn, serv);
  }
  catch (const std::exception& e)
    {
      std::cerr << "Worker thread exception: " << e.what() << std::endl;
    }
  run_context->cancel();
}

int main(int argc, char* argv[])
{
  try
    {
      if (argc >= 2)
	{
	  // process-wide initialization
	  InitProcess::init();

	  // start worker thread
	  ServerThread::Ptr serv;
	  MyRunContext::Ptr run_context = new MyRunContext(serv);
	  const char *config_fn = argv[1];
	  boost::thread* thread = new boost::thread(boost::bind(&worker_thread, config_fn, boost::ref(serv), run_context));

	  // wait for worker to exit
	  run_context->run();
	  thread->join();
	  delete thread;
	}
      else
	{
	  std::cerr << "OpenVPN Server (C++ core)" << std::endl;
	  std::cerr << "usage: " << argv[0] << " <config-file>" << std::endl;
	  return 2;
	}
    }
  catch (const std::exception& e)
    {
      std::cerr << "Main thread exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
