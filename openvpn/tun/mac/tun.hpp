#ifndef OPENVPN_TUN_MAC_TUN_H
#define OPENVPN_TUN_MAC_TUN_H

#include <fcntl.h>
#include <errno.h>

#include <string>
#include <sstream>

#include <boost/asio.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/common/scoped_fd.hpp>
#include <openvpn/common/dispatch.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/process.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/log/protostats.hpp>
#include <openvpn/tun/tunspec.hpp>
#include <openvpn/tun/tunlog.hpp>

namespace openvpn {
  namespace TunMac {

    struct PacketFrom
    {
      typedef ScopedPtr<PacketFrom> SPtr;
      BufferAllocated buf;
    };

    // exceptions
    OPENVPN_EXCEPTION(tun_open_error);
    OPENVPN_EXCEPTION(tun_fcntl_error);

    template <typename ReadHandler>
    class Tun : public RC<thread_unsafe_refcount>
    {
    public:
      typedef boost::intrusive_ptr<Tun> Ptr;

      Tun(boost::asio::io_service& io_service,
	  ReadHandler read_handler_arg,
	  const Frame::Ptr& frame_arg,
	  const ProtoStats::Ptr& stats_arg,
	  const bool tap)

	: halt(false),
	  read_handler(read_handler_arg),
	  frame(frame_arg),
	  stats(stats_arg)
      {
	for (int i = 0; i < 256; ++i)
	  {
	    std::ostringstream node;
	    if (tap)
	      node << "tap";
	    else
	      node << "tun";
	    node << i;
	    const std::string node_str = node.str();
	    const std::string node_fn = "/dev/" + node_str;

	    ScopedFD fd(open(node_fn.c_str(), O_RDWR));
	    if (fd.defined())
	      {
		// got it
		if (fcntl (fd(), F_SETFL, O_NONBLOCK) < 0)
		  throw tun_fcntl_error(errinfo(errno));

		name_ = node_str;
		sd = new boost::asio::posix::stream_descriptor(io_service, fd.release());
		OPENVPN_LOG_TUN(node_fn << " opened");
		return;
	      }
	  }

	OPENVPN_THROW(tun_open_error, "error opening Mac " << (tap ? "tap" : "tun") << " device");
      }

      bool write(const Buffer& buf)
      {
	if (!halt)
	  {
	    try {
	      const size_t wrote = sd->write_some(buf.const_buffers_1());
	      stats->inc_stat(ProtoStats::TUN_BYTES_OUT, wrote);
	      if (wrote == buf.size())
		return true;
	      else
		{
		  OPENVPN_LOG_TUN_ERROR("TUN partial write error");
		  stats->error(ProtoStats::TUN_ERROR);
		  return false;
		}
	    }
	    catch (boost::system::system_error& e)
	      {
		OPENVPN_LOG_TUN_ERROR("TUN write error: " << e.what());
		stats->error(ProtoStats::TUN_ERROR);
		return false;
	      }
	  }
	else
	  return false;
      }

      void start(const int n_parallel)
      {
	if (!halt)
	  {
	    for (int i = 0; i < n_parallel; i++)
	      queue_read(NULL);
	  }
      }

      void stop()
      {
	if (!halt)
	  {
	    halt = true;
	    sd->close();
	    delete sd;
	  }
      }

      int ifconfig(const OptionList& opt, const unsigned int mtu) // fixme -- support IPv6
      {
	// first verify topology
	{
	  const Option& o = opt.get("topology");
	  o.min_args(2);
	  if (o[1] != "subnet")
	    throw option_error("only topology subnet supported");
	}

	// configure tun interface
	{
	  const Option& o = opt.get("ifconfig");
	  o.exact_args(3);
	  std::string ip = validate_ip_address("ifconfig-ip", o[1]);
	  std::string mask = validate_ip_address("ifconfig-net", o[2]);
	  {
	    std::ostringstream cmd;
	    cmd << "/sbin/ifconfig " << name() << ' ' << ip << ' ' << ip << " netmask " << mask << " mtu " << mtu << " up";
	    const std::string cmd_str = cmd.str();
	    OPENVPN_LOG_TUN(cmd_str);
	    const int status = ::system(cmd_str.c_str());
	  }
	  {
	    std::ostringstream cmd;
	    cmd << "/sbin/route add -net 5.5.8.0 " << ip << ' ' << mask; // fixme
	    const std::string cmd_str = cmd.str();
	    OPENVPN_LOG_TUN(cmd_str);
	    const int status = ::system(cmd_str.c_str());
	  }
	}
	return 0; // fixme -- maybe return system() status
      }

      ~Tun() { stop(); }

      std::string name() const
      {
	return name_;
      }

    private:
      void queue_read(PacketFrom *tunfrom)
      {
	OPENVPN_LOG_TUN_VERBOSE("TunMac::queue_read");
	if (!tunfrom)
	  tunfrom = new PacketFrom();
	frame->prepare(Frame::READ_TUN, tunfrom->buf);

	sd->async_read_some(tunfrom->buf.mutable_buffers_1(),
			    asio_dispatch_read(&Tun::handle_read, this, tunfrom));
      }

      void handle_read(PacketFrom *tunfrom, const boost::system::error_code& error, const size_t bytes_recvd)
      {
	OPENVPN_LOG_TUN_VERBOSE("TunMac::handle_read: " << error.message());
	typename PacketFrom::SPtr pfp(tunfrom);
	if (!halt)
	  {
	    if (!error)
	      {
		pfp->buf.set_size(bytes_recvd);
		stats->inc_stat(ProtoStats::TUN_BYTES_IN, bytes_recvd);
		read_handler->tun_read_handler(pfp);
	      }
	    else
	      {
		::sleep(1);
		OPENVPN_LOG_TUN_ERROR("TUN Read Error: " << error);
		stats->error(ProtoStats::TUN_ERROR);
	      }
	    queue_read(pfp.release()); // reuse buffer if still available
	  }
      }

      std::string name_;
      boost::asio::posix::stream_descriptor *sd;
      bool halt;
      ReadHandler read_handler;
      const Frame::Ptr frame;
      ProtoStats::Ptr stats;
    };

  }
} // namespace openvpn

#endif // OPENVPN_TUN_MAC_TUN_H
