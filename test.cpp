#include <boost/asio.hpp>
#include <openvpn/tun/tunlinux.hpp>

#include <iostream>

void stop(openvpn::tun::TunLinux *tun, const boost::system::error_code& /*e*/)
{
  std::cout << "packets: " << tun->n_read_pkts() << std::endl;
  std::cout << "bytes: " << tun->n_read_bytes() << std::endl;
  tun->stop();
}

int
main(int argc, char* argv[])
{
  try
    {
      boost::asio::io_service io_service;

      openvpn::tun::TunLinux tun(io_service, "foo");
      std::cout << "tun/tap device opened: " << tun.name() << std::endl;

      boost::asio::deadline_timer timer(io_service, boost::posix_time::seconds(30));
      timer.async_wait(boost::bind(stop,
				   &tun,
				   boost::asio::placeholders::error));

      io_service.run();
      return 0;
    }
  catch (boost::exception &e)
    {
      std::cerr << diagnostic_information(e);
      return 1;
    }
  catch (std::exception& e)
    {
      std::cerr << "STD Exception: " << e.what() << std::endl;
      return 1;
    }
}
